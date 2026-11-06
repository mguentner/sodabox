//! The filtering resolver: the [`QueryHandler`] that turns the DNS front-end
//! into an enforcement point.
//!
//! Per query:
//! 1. **Filter:** if the name is not on the domain allowlist, answer
//!    `REFUSED` — blocks DNS/QNAME exfiltration.
//! 2. **Resolve:** forward an allowed A/AAAA query to the host's
//!    upstream resolvers (from `resolv.conf`); the recursive upstream returns
//!    the CNAME chain already resolved to A/AAAA.
//! 3. **Admit:** insert each answer IP into the VM's ephemeral egress
//!    set (the slot the filter proxy reads), TTL-clamped to the policy
//!    floor/cap plus a small grace, scoped to the domain rule's proto/ports.
//!
//! The resolved answer is then returned to the guest. Non-A/AAAA queries for an
//! allowed name are forwarded but admit nothing.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use sodabox_common::allowlist::{is_public_ip, EphemeralEntry, Proto, SharedAllowlist};
use sodabox_common::event::{now_ts, DnsVerdict, Event};
use sodabox_common::policy::{Limits, VmPolicy};
use sodabox_common::request::{refusal_reason, PendingRequests, RequestVerdict, REQUEST_TTL};
use tokio::net::UdpSocket;

use crate::domain::{self, DomainAllowlist, DomainRule, SharedDomainAllowlist};
use crate::events::{null_sink, DnsEvents};
use crate::frontend::{HandleFuture, QueryHandler, Response};
use crate::wire::{
    self, RData, RecordData, RCODE_NOERROR, RCODE_REFUSED, RCODE_SERVFAIL, TYPE_A, TYPE_AAAA,
};

/// Grace added to every ephemeral TTL to absorb the race between a DNS answer
/// and the guest's connection using it.
const TTL_GRACE: Duration = Duration::from_secs(5);
/// How long a permit restored from a remembered lookup lasts. Short: it only
/// spares repeat connections the check, and the next one simply restores it.
const READMIT_TTL: Duration = Duration::from_secs(60);
/// How long to wait for an upstream reply before trying the next one.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

/// TTL of answers for [`LocalNames`]: short, so revoking access takes effect
/// soon in the guest's cache too.
const LOCAL_TTL: u32 = 30;

/// Names of services sodabox itself offers the guest (ADR-0020), e.g.
/// `inference.sodabox.internal`, mapped to their reserved addresses. The
/// resolver answers these itself, and only while they are in the map: the
/// supervisor adds a name when the policy grants access and removes it when
/// access is revoked, after which it is refused like any unlisted name.
pub type LocalNames = Arc<RwLock<HashMap<String, Ipv4Addr>>>;

/// The per-VM filtering resolver.
pub struct FilteringResolver {
    domains: SharedDomainAllowlist,
    allowlist: SharedAllowlist,
    upstreams: Vec<SocketAddr>,
    limits: Limits,
    events: Arc<dyn DnsEvents>,
    local: LocalNames,
    /// Where an undecided qname is parked for interactive approval
    /// (ADR-0021); `None` keeps the plain refuse-on-deny behavior (tests).
    pending: Option<PendingRequests>,
}

impl FilteringResolver {
    /// Build from a policy, a shared allowlist to admit ephemeral entries into,
    /// and the upstream resolver addresses.
    pub fn new(
        policy: &VmPolicy,
        allowlist: SharedAllowlist,
        upstreams: Vec<SocketAddr>,
    ) -> Result<FilteringResolver, String> {
        Ok(FilteringResolver {
            domains: domain::shared(DomainAllowlist::from_policy(policy)?),
            allowlist,
            upstreams,
            limits: policy.limits.clone(),
            events: null_sink(),
            local: LocalNames::default(),
            pending: None,
        })
    }

    /// Park undecided qnames in this table instead of refusing them
    /// (ADR-0021).
    pub fn with_pending(mut self, pending: PendingRequests) -> Self {
        self.pending = Some(pending);
        self
    }

    /// A clone of the live local-names handle (see [`LocalNames`]). Like
    /// [`FilteringResolver::domains`], take it before the resolver moves into
    /// its serve task.
    pub fn local_names(&self) -> LocalNames {
        self.local.clone()
    }

    /// A clone of the shared domain allowlist handle, so the control plane can
    /// swap it live on a `PolicySet`. Take this *before* the
    /// resolver is moved into its serve task; both ends then point at the same
    /// `RwLock`, so an allowed domain becomes resolvable without a VM restart.
    pub fn domains(&self) -> SharedDomainAllowlist {
        self.domains.clone()
    }

    /// Attach an event sink; each query then emits an [`Event::Dns`] verdict
    /// (allowed/refused) onto the monitoring stream. Without this the
    /// resolver stays silent (the default null sink).
    pub fn with_events(mut self, events: Arc<dyn DnsEvents>) -> Self {
        self.events = events;
        self
    }

    /// Read upstream nameservers from `/etc/resolv.conf` (port 53).
    pub fn upstreams_from_resolv_conf() -> io::Result<Vec<SocketAddr>> {
        let text = std::fs::read_to_string("/etc/resolv.conf")?;
        Ok(parse_resolv_conf(&text))
    }
}

/// Clamp a raw TTL to the policy floor/cap.
fn clamp_ttl(ttl: u32, limits: &Limits) -> u32 {
    ttl.clamp(limits.ttl_floor_s, limits.ttl_cap_s)
}

fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            if let Ok(ip) = rest.trim().parse::<std::net::IpAddr>() {
                out.push(SocketAddr::new(ip, 53));
            }
        }
    }
    out
}

/// Forward `query` to the upstreams in order; return the first valid response
/// whose id matches.
async fn resolve_upstream(
    upstreams: &[SocketAddr],
    id: u16,
    name: &str,
    qtype: u16,
) -> io::Result<wire::ParsedResponse> {
    let packet = wire::build_query(id, name, qtype)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    for up in upstreams {
        let bind: SocketAddr = if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }
            .parse()
            .unwrap();
        let sock = match UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        if sock.connect(up).await.is_err() || sock.send(&packet).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(UPSTREAM_TIMEOUT, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Ok(parsed) = wire::parse_response(&buf[..n]) {
                    if parsed.id == id {
                        return Ok(parsed);
                    }
                }
            }
            _ => continue,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "no upstream answered",
    ))
}

/// The dotted/colon string of an admitted answer's IP, for the event stream —
/// `None` for a passed-through CNAME (not an egress target, so not reported as an
/// admitted IP).
fn answer_ip(a: &wire::Answer) -> Option<String> {
    match &a.data {
        RecordData::A(ip) => Some(ip.to_string()),
        RecordData::Aaaa(ip) => Some(ip.to_string()),
        RecordData::Cname(_) => None,
    }
}

/// The rules granting `name`, owned so they can outlive the lock. A poisoned lock
/// means a writer panicked mid-swap: no rules, so the name is treated as unlisted
/// (fail closed).
fn rules_for(domains: &SharedDomainAllowlist, name: &str) -> Vec<DomainRule> {
    domains
        .read()
        .map(|d| d.matches(name).into_iter().cloned().collect())
        .unwrap_or_default()
}

/// Admit `answers`' A/AAAA IPs into the ephemeral set, once per rule that admits
/// (each with its own ports and proto), and collect the records to return to the
/// guest. Returns the admitted answers.
fn admit(
    allowlist: &SharedAllowlist,
    rules: &[DomainRule],
    answers: &[wire::Rr],
    limits: &Limits,
) -> Vec<wire::Answer> {
    let now = Instant::now();
    let mut out = Vec::new();
    // Fail-closed on a poisoned lock: skip admission (guest just won't reach it).
    let Ok(mut al) = allowlist.write() else {
        return out;
    };
    al.prune_expired(now);
    for rr in answers {
        let ip = match &rr.data {
            RData::A(ip) => std::net::IpAddr::V4(*ip),
            RData::Aaaa(ip) => std::net::IpAddr::V6(*ip),
            RData::Cname(target) => {
                // Not an egress target (the resolved A/AAAA IPs are), but the
                // guest's stub resolver needs the CNAME chain from the queried
                // name intact — without it, glibc/curl discard the A records as
                // mismatched-owner and report "could not resolve".
                // Pass it through in order; don't touch the ephemeral set.
                out.push(wire::Answer {
                    name: rr.name.clone(),
                    ttl: clamp_ttl(rr.ttl, limits),
                    data: RecordData::Cname(target.clone()),
                });
                continue;
            }
            RData::Other(_) => continue, // types we don't interpret
        };
        let ttl = clamp_ttl(rr.ttl, limits);
        // Anti-abuse caps: admit only within the per-VM count and total-
        // size limits. Once a cap is hit, stop admitting the rest of the spray —
        // the un-admitted IPs stay deny-by-default and are not returned to the
        // guest (no point handing it addresses the proxy will refuse). A
        // `resolve` rule admits nothing: the guest gets the address, and the
        // proxy holds whatever it dials there as its own request (ADR-0021).
        // Nor does a non-public address, whatever the rule: the name's owner
        // picks its records, so the user decides on those one by one.
        let admitted = !is_public_ip(ip)
            || rules.iter().filter(|r| r.admits).all(|rule| {
                al.try_insert_ephemeral(
                    EphemeralEntry {
                        ip,
                        ports: rule.ports.clone(),
                        proto: rule.proto,
                        expiry: now + Duration::from_secs(ttl as u64) + TTL_GRACE,
                        domain: rule.name.clone(),
                    },
                    limits,
                )
            });
        if !admitted {
            break;
        }
        out.push(wire::Answer {
            name: rr.name.clone(),
            ttl,
            data: match ip {
                std::net::IpAddr::V4(v4) => RecordData::A(v4),
                std::net::IpAddr::V6(v6) => RecordData::Aaaa(v6),
            },
        });
    }
    out
}

/// Restore the permit for an address `name` returned earlier, if a `domain` rule
/// on that name covers the connection (ADR-0021). The address's permit can be
/// missing though the rule stands: applications cache answers past their TTL, and
/// a lookup made before the rule existed admitted nothing. Returns whether a
/// permit was added; the same limits apply as for a fresh answer.
pub fn readmit_remembered(
    allowlist: &SharedAllowlist,
    domains: &SharedDomainAllowlist,
    limits: &Limits,
    name: &str,
    dst: SocketAddr,
    proto: Proto,
) -> bool {
    if !is_public_ip(dst.ip()) {
        return false;
    }
    let covering: Vec<DomainRule> = rules_for(domains, name)
        .into_iter()
        .filter(|r| r.admits && r.proto.map_or(true, |p| p == proto))
        .filter(|r| r.ports.contains(dst.port()))
        .collect();
    let Ok(mut al) = allowlist.write() else {
        return false;
    };
    let now = Instant::now();
    al.prune_expired(now);
    let mut added = false;
    for rule in covering {
        added |= al.try_insert_ephemeral(
            EphemeralEntry {
                ip: dst.ip(),
                ports: rule.ports,
                proto: rule.proto,
                expiry: now + READMIT_TTL,
                domain: rule.name,
            },
            limits,
        );
    }
    added
}

impl QueryHandler for FilteringResolver {
    fn handle(&self, query: wire::Query, _client: SocketAddr) -> HandleFuture {
        let name = query.question.name.to_ascii_lowercase();
        let qtype = query.question.qtype;

        // sodabox's own services: answered here, never forwarded upstream.
        let local = self
            .local
            .read()
            .ok()
            .and_then(|l| l.get(name.trim_end_matches('.')).copied());
        if let Some(ip) = local {
            // An A record for A queries; NOERROR with no data for the rest
            // (there is no IPv6 address).
            let answers = if qtype == TYPE_A {
                vec![wire::Answer {
                    name: name.clone(),
                    ttl: LOCAL_TTL,
                    data: RecordData::A(ip),
                }]
            } else {
                Vec::new()
            };
            self.events.emit(Event::Dns {
                ts: now_ts(),
                verdict: DnsVerdict::Allowed,
                qname: name,
                answers: answers.iter().filter_map(answer_ip).collect(),
                ttl: LOCAL_TTL,
                reason: None,
            });
            let packet = wire::build_response(&query, RCODE_NOERROR, &answers);
            return Box::pin(async move { Response::Packet(packet) });
        }

        // Filter: match synchronously, before any upstream work. A
        // poisoned lock means a writer panicked mid-swap; fail closed (refuse)
        // rather than trust a possibly-inconsistent set.
        let matched = rules_for(&self.domains, &name);
        let allowlist = self.allowlist.clone();
        let domains = self.domains.clone();
        let pending = self.pending.clone();
        let upstreams = self.upstreams.clone();
        let limits = self.limits.clone();
        let events = self.events.clone();

        Box::pin(async move {
            // Undecided, not refused (ADR-0021): an unlisted name is parked for
            // up to REQUEST_TTL and answered only once resolved. The upstream
            // query stays unsent until approval, so an unapproved name never
            // leaks to the host resolver (the ADR-0005 anti-exfil property
            // holds); retransmissions coalesce in the request table.
            let mut matched = matched;
            let mut reason = None;
            if matched.is_empty() {
                if let Some(pending) = &pending {
                    let (_, rx) = pending.hold("dns", &name, None);
                    let verdict = tokio::time::timeout(REQUEST_TTL, rx)
                        .await
                        .ok()
                        .and_then(Result::ok);
                    if verdict == Some(RequestVerdict::Approved) {
                        // Approve *is* a persistent rule: re-read the (just
                        // updated) domain allowlist, exactly like the live swap.
                        matched = rules_for(&domains, &name);
                    }
                    reason = Some(refusal_reason(verdict));
                }
            }
            if matched.is_empty() {
                // Not allowlisted -> REFUSED (anti-exfil). Report the blocked
                // query so the TUI/log can surface exfil attempts.
                events.emit(Event::Dns {
                    ts: now_ts(),
                    verdict: DnsVerdict::Refused,
                    qname: name,
                    answers: Vec::new(),
                    ttl: 0,
                    reason,
                });
                return Response::Packet(wire::build_response(&query, RCODE_REFUSED, &[]));
            }

            // Resolve. An upstream failure is an infrastructure error,
            // not a filter verdict, so it emits no allowed/refused event.
            let parsed = match resolve_upstream(&upstreams, query.id, &name, qtype).await {
                Ok(p) => p,
                Err(_) => {
                    return Response::Packet(wire::build_response(&query, RCODE_SERVFAIL, &[]))
                }
            };

            // Admit only for address queries; other types are forwarded
            // as-is without touching the egress set.
            let answers = if qtype == TYPE_A || qtype == TYPE_AAAA {
                admit(&allowlist, &matched, &parsed.answers, &limits)
            } else {
                Vec::new()
            };

            // Remember which name these addresses came from, for the requests
            // connecting to them will raise (ADR-0021). Before the reply goes out,
            // so the guest can't get there first.
            if let Some(pending) = &pending {
                for answer in &answers {
                    match answer.data {
                        RecordData::A(ip) => pending.note_resolved(ip.into(), &name),
                        RecordData::Aaaa(ip) => pending.note_resolved(ip.into(), &name),
                        RecordData::Cname(_) => {}
                    }
                }
            }

            // Allowed: report the name, the IPs it authorized into the ephemeral
            // egress set, and the soonest TTL those entries expire at.
            events.emit(Event::Dns {
                ts: now_ts(),
                verdict: DnsVerdict::Allowed,
                qname: name,
                answers: answers.iter().filter_map(answer_ip).collect(),
                ttl: answers.iter().map(|a| a.ttl).min().unwrap_or(0),
                reason: None,
            });

            Response::Packet(wire::build_response(&query, parsed.rcode, &answers))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::ChannelEvents;
    use sodabox_common::allowlist::{shared, Allowlist};
    use sodabox_common::policy::{DomainScope, Rule, VmPolicy};

    #[test]
    fn resolv_conf_parsing() {
        let text =
            "# comment\nnameserver 1.1.1.1\nsearch lan\nnameserver 8.8.4.4\nnameserver bogus\n";
        let ups = parse_resolv_conf(text);
        assert_eq!(
            ups,
            vec!["1.1.1.1:53".parse().unwrap(), "8.8.4.4:53".parse().unwrap()]
        );
    }

    #[test]
    fn ttl_clamped_to_policy() {
        let limits = Limits {
            max_ephemeral_entries: 10,
            ttl_floor_s: 30,
            ttl_cap_s: 300,
            ..Default::default()
        };
        assert_eq!(clamp_ttl(5, &limits), 30);
        assert_eq!(clamp_ttl(100, &limits), 100);
        assert_eq!(clamp_ttl(10_000, &limits), 300);
    }

    fn resolver_with_domain(name: &str) -> (FilteringResolver, SharedAllowlist) {
        let pol = VmPolicy {
            rules: vec![Rule::Domain {
                name: name.into(),
                scope: DomainScope::Subdomains,
                ports: Some("443".into()),
                proto: Some("tcp".into()),
            }],
            ..VmPolicy::default()
        };
        let al = shared(Allowlist::from_policy(&pol).unwrap());
        let r = FilteringResolver::new(&pol, al.clone(), vec![]).unwrap();
        (r, al)
    }

    #[test]
    fn resolve_rule_answers_without_admitting_egress() {
        let pol = VmPolicy {
            rules: vec![Rule::Resolve {
                name: "allowed.test".into(),
                scope: DomainScope::Subdomains,
            }],
            ..VmPolicy::default()
        };
        let al = shared(Allowlist::from_policy(&pol).unwrap());
        let domains = domain::shared(DomainAllowlist::from_policy(&pol).unwrap());
        let rules = rules_for(&domains, "www.allowed.test");
        let answers = vec![wire::Rr {
            name: "www.allowed.test".into(),
            ttl: 60,
            data: RData::A("203.0.113.10".parse().unwrap()),
        }];

        assert_eq!(admit(&al, &rules, &answers, &Limits::default()).len(), 1);
        let decision = al.read().unwrap().evaluate(
            "203.0.113.10:443".parse().unwrap(),
            Proto::Tcp,
            Instant::now(),
        );
        assert_eq!(decision, sodabox_common::allowlist::Decision::Deny);
    }

    /// A non-public answer still reaches the guest, but opens nothing: connecting
    /// to it is a request of its own, while the public one in the same answer is
    /// admitted as usual.
    #[test]
    fn a_domain_rule_does_not_admit_non_public_answers() {
        let pol = VmPolicy {
            rules: vec![Rule::Domain {
                name: "allowed.test".into(),
                scope: DomainScope::Subdomains,
                ports: None,
                proto: None,
            }],
            ..VmPolicy::default()
        };
        let al = shared(Allowlist::from_policy(&pol).unwrap());
        let domains = domain::shared(DomainAllowlist::from_policy(&pol).unwrap());
        let rules = rules_for(&domains, "allowed.test");
        let record = |ip: &str| wire::Rr {
            name: "allowed.test".into(),
            ttl: 60,
            data: RData::A(ip.parse().unwrap()),
        };
        let answers = vec![record("169.254.169.254"), record("203.0.113.10")];

        assert_eq!(admit(&al, &rules, &answers, &Limits::default()).len(), 2);
        let allowed = |dst: &str| {
            al.read()
                .unwrap()
                .evaluate(dst.parse().unwrap(), Proto::Tcp, Instant::now())
                .is_allow()
        };
        assert!(!allowed("169.254.169.254:80"));
        assert!(allowed("203.0.113.10:80"));
    }

    /// A remembered address gets its permit back only where a `domain` rule on
    /// its name covers the connection, and never for a non-public address.
    #[test]
    fn readmitting_needs_a_covering_rule_and_a_public_address() {
        let pol = VmPolicy {
            rules: vec![
                Rule::Domain {
                    name: "allowed.test".into(),
                    scope: DomainScope::Subdomains,
                    ports: Some("443".into()),
                    proto: Some("tcp".into()),
                },
                Rule::Resolve {
                    name: "named.test".into(),
                    scope: DomainScope::Subdomains,
                },
            ],
            ..VmPolicy::default()
        };
        let al = shared(Allowlist::from_policy(&pol).unwrap());
        let domains = domain::shared(DomainAllowlist::from_policy(&pol).unwrap());
        let readmit = |name: &str, dst: &str, proto| {
            readmit_remembered(
                &al,
                &domains,
                &Limits::default(),
                name,
                dst.parse().unwrap(),
                proto,
            )
        };

        assert!(!readmit("allowed.test", "203.0.113.10:80", Proto::Tcp));
        assert!(!readmit("allowed.test", "203.0.113.10:443", Proto::Udp));
        assert!(!readmit("named.test", "203.0.113.10:443", Proto::Tcp));
        assert!(!readmit("other.test", "203.0.113.10:443", Proto::Tcp));
        assert!(!readmit("allowed.test", "192.168.1.1:443", Proto::Tcp));
        assert_eq!(al.read().unwrap().ephemeral_len(), 0);

        assert!(readmit("www.allowed.test", "203.0.113.10:443", Proto::Tcp));
        let decision = al.read().unwrap().evaluate(
            "203.0.113.10:443".parse().unwrap(),
            Proto::Tcp,
            Instant::now(),
        );
        assert!(decision.is_allow());
    }

    /// Two rules for one name both reach the proxy, each with its own ports and
    /// proto, and one answer is still returned to the guest once.
    #[test]
    fn every_matching_rule_admits_its_own_ports() {
        let rule = |ports: &str, proto: &str| Rule::Domain {
            name: "allowed.test".into(),
            scope: DomainScope::Subdomains,
            ports: Some(ports.into()),
            proto: Some(proto.into()),
        };
        let pol = VmPolicy {
            rules: vec![rule("443", "tcp"), rule("53", "udp")],
            ..VmPolicy::default()
        };
        let al = shared(Allowlist::from_policy(&pol).unwrap());
        let domains = domain::shared(DomainAllowlist::from_policy(&pol).unwrap());
        let rules = rules_for(&domains, "allowed.test");
        let answers = vec![wire::Rr {
            name: "allowed.test".into(),
            ttl: 60,
            data: RData::A("203.0.113.10".parse().unwrap()),
        }];

        assert_eq!(admit(&al, &rules, &answers, &Limits::default()).len(), 1);
        let allowed = |dst: &str, proto| {
            al.read()
                .unwrap()
                .evaluate(dst.parse().unwrap(), proto, Instant::now())
                .is_allow()
        };
        assert!(allowed("203.0.113.10:443", Proto::Tcp));
        assert!(allowed("203.0.113.10:53", Proto::Udp));
        assert!(!allowed("203.0.113.10:53", Proto::Tcp));
        assert!(!allowed("203.0.113.10:443", Proto::Udp));
    }

    #[tokio::test]
    async fn local_names_are_answered_only_while_present() {
        let (r, _al) = resolver_with_domain("allowed.test");
        let name = "inference.sodabox.internal";
        let ask =
            |qtype| wire::parse_query(&wire::build_query(0x22, name, qtype).unwrap()).unwrap();
        r.local_names()
            .write()
            .unwrap()
            .insert(name.into(), Ipv4Addr::new(10, 0, 2, 4));
        // No upstreams: the answer must come from the resolver itself.
        match r.handle(ask(TYPE_A), "127.0.0.1:1".parse().unwrap()).await {
            Response::Packet(p) => {
                let parsed = wire::parse_response(&p).unwrap();
                assert_eq!(parsed.rcode, RCODE_NOERROR);
                assert!(matches!(
                    parsed.answers[0].data,
                    RData::A(ip) if ip == Ipv4Addr::new(10, 0, 2, 4)
                ));
            }
            Response::Drop => panic!("should have replied"),
        }
        // AAAA: the name exists but has no IPv6 address.
        match r
            .handle(ask(TYPE_AAAA), "127.0.0.1:1".parse().unwrap())
            .await
        {
            Response::Packet(p) => {
                let parsed = wire::parse_response(&p).unwrap();
                assert_eq!(parsed.rcode, RCODE_NOERROR);
                assert!(parsed.answers.is_empty());
            }
            Response::Drop => panic!("should have replied"),
        }
        // Access revoked: refused like any unlisted name.
        r.local_names().write().unwrap().clear();
        match r.handle(ask(TYPE_A), "127.0.0.1:1".parse().unwrap()).await {
            Response::Packet(p) => assert_eq!(p[3] & 0x0f, RCODE_REFUSED),
            Response::Drop => panic!("should have replied"),
        }
    }

    #[tokio::test]
    async fn unlisted_name_is_refused_without_upstream() {
        let (r, _al) = resolver_with_domain("allowed.test");
        // No upstreams configured; a REFUSED must come back without needing one.
        let q = wire::parse_query(&wire::build_query(0x11, "evil.test", TYPE_A).unwrap()).unwrap();
        match r.handle(q, "127.0.0.1:1".parse().unwrap()).await {
            Response::Packet(p) => assert_eq!(p[3] & 0x0f, RCODE_REFUSED),
            Response::Drop => panic!("should have replied"),
        }
    }

    #[tokio::test]
    async fn unlisted_name_is_held_then_refused_on_deny() {
        // ADR-0021: an unlisted name parks in the request table; a deny refuses
        // it exactly as if it had been refused immediately.
        let (r, _al) = resolver_with_domain("allowed.test");
        let pending = sodabox_common::request::shared();
        let r = r.with_pending(pending.clone());
        // The hold happens inside the query's future (ADR-0021), so the query
        // must run concurrently with the wait below.
        let task = {
            let q =
                wire::parse_query(&wire::build_query(0x21, "maybe.test", TYPE_A).unwrap()).unwrap();
            let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
            tokio::spawn(async move { r.handle(q, peer).await })
        };

        // The query is parked, not answered.
        let id = loop {
            if let Some(req) = pending.list().first() {
                break req.id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(pending.list()[0].destination, "maybe.test");
        assert!(pending.resolve(id, false));

        match task.await.unwrap() {
            Response::Packet(p) => assert_eq!(p[3] & 0x0f, RCODE_REFUSED),
            Response::Drop => panic!("should have replied"),
        }
    }

    /// Nobody is asked, nothing goes upstream, and the refusal says why. An allowed
    /// name on the blocklist still resolves: an allow rule wins.
    #[tokio::test]
    async fn a_blocklisted_name_is_refused_at_once_with_its_reason() {
        use sodabox_common::blocklist::Blocklist;
        use sodabox_common::event::RefusalReason;
        use sodabox_common::policy::BlocklistEntry;

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (r, _al) = resolver_with_domain("allowed.test");
        let pending = sodabox_common::request::shared();
        let entry = |name: &str| BlocklistEntry::Domain {
            name: name.into(),
            scope: DomainScope::Exact,
            ports: None,
            proto: None,
        };
        pending.set_blocklist(
            Blocklist::from_policy(&VmPolicy {
                blocklist: vec![entry("nope.test"), entry("allowed.test")],
                ..VmPolicy::default()
            })
            .unwrap(),
        );
        let r = r
            .with_pending(pending.clone())
            .with_events(Arc::new(ChannelEvents::new(tx)));
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let query = |name| wire::parse_query(&wire::build_query(0x22, name, TYPE_A).unwrap());

        match r.handle(query("nope.test").unwrap(), peer).await {
            Response::Packet(p) => assert_eq!(p[3] & 0x0f, RCODE_REFUSED),
            Response::Drop => panic!("should have replied"),
        }
        assert!(pending.list().is_empty());
        assert!(matches!(
            rx.try_recv(),
            Ok(Event::Dns {
                verdict: DnsVerdict::Refused,
                reason: Some(RefusalReason::Blocklist),
                ..
            })
        ));

        // No upstreams are configured: SERVFAIL is proof it got past the filter.
        match r.handle(query("allowed.test").unwrap(), peer).await {
            Response::Packet(p) => assert_eq!(p[3] & 0x0f, RCODE_SERVFAIL),
            Response::Drop => panic!("should have replied"),
        }
    }

    #[tokio::test]
    async fn unlisted_name_proceeds_past_the_filter_on_approval() {
        // Approve *is* a persistent rule: the domain lands in the (live) domain
        // allowlist and the held query then proceeds. No upstreams are
        // configured here, so the proof it got past the filter is SERVFAIL
        // (an upstream failure), not REFUSED (a filter verdict).
        let (r, _al) = resolver_with_domain("allowed.test");
        let domains = r.domains();
        let pending = sodabox_common::request::shared();
        let r = r.with_pending(pending.clone());
        let task = {
            let q = wire::parse_query(&wire::build_query(0x22, "granted.test", TYPE_A).unwrap())
                .unwrap();
            let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
            tokio::spawn(async move { r.handle(q, peer).await })
        };

        let id = loop {
            if let Some(req) = pending.list().first() {
                break req.id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        // The TUI's approve path: rule first, then the resolve.
        let allow = VmPolicy {
            rules: vec![Rule::Domain {
                name: "granted.test".into(),
                scope: DomainScope::Subdomains,
                ports: None,
                proto: None,
            }],
            ..VmPolicy::default()
        };
        domains.write().unwrap().swap_policy(&allow).unwrap();
        assert!(pending.resolve(id, true));

        match task.await.unwrap() {
            Response::Packet(p) => assert_eq!(p[3] & 0x0f, RCODE_SERVFAIL),
            Response::Drop => panic!("should have replied"),
        }
    }

    /// A fake upstream that answers every A query with `ip` and the given ttl.
    async fn spawn_fake_upstream(ip: std::net::Ipv4Addr, ttl: u32) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(q) = wire::parse_query(&buf[..n]) else {
                    continue;
                };
                let ans = vec![wire::Answer {
                    name: q.question.name.clone(),
                    ttl,
                    data: RecordData::A(ip),
                }];
                let resp = wire::build_response(&q, 0, &ans);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn resolved_addresses_are_remembered_under_the_queried_name() {
        // A `resolve` rule: the address gains no egress, so connecting to it is a
        // request, and that request can say where the address came from.
        let upstream = spawn_fake_upstream(Ipv4Addr::new(198, 51, 100, 5), 60).await;
        let pol = VmPolicy {
            rules: vec![Rule::Resolve {
                name: "allowed.test".into(),
                scope: DomainScope::Subdomains,
            }],
            ..VmPolicy::default()
        };
        let al = shared(Allowlist::from_policy(&pol).unwrap());
        let pending = sodabox_common::request::shared();
        let r = FilteringResolver::new(&pol, al, vec![upstream])
            .unwrap()
            .with_pending(pending.clone());

        let (unseen, _rx) = pending.hold("tcp", "198.51.100.5", Some(443));
        assert_eq!(unseen.via, None);

        let q = wire::parse_query(&wire::build_query(0x56, "www.allowed.test", TYPE_A).unwrap())
            .unwrap();
        let Response::Packet(_) = r.handle(q, "127.0.0.1:1".parse().unwrap()).await else {
            panic!("expected a reply");
        };

        let (seen, _rx) = pending.hold("tcp", "198.51.100.5", Some(22));
        assert_eq!(seen.via.as_deref(), Some("www.allowed.test"));
    }

    #[tokio::test]
    async fn end_to_end_allowed_resolves_and_admits() {
        let ip = std::net::Ipv4Addr::new(198, 51, 100, 5);
        let upstream = spawn_fake_upstream(ip, 5 /* below floor */).await;

        let pol = VmPolicy {
            rules: vec![Rule::Domain {
                name: "allowed.test".into(),
                scope: DomainScope::Subdomains,
                ports: Some("443".into()),
                proto: Some("tcp".into()),
            }],
            limits: Limits {
                max_ephemeral_entries: 10,
                ttl_floor_s: 30,
                ttl_cap_s: 300,
                ..Default::default()
            },
            ..VmPolicy::default()
        };
        let al = shared(Allowlist::from_policy(&pol).unwrap());
        let r = FilteringResolver::new(&pol, al.clone(), vec![upstream]).unwrap();

        let q = wire::parse_query(&wire::build_query(0x55, "www.allowed.test", TYPE_A).unwrap())
            .unwrap();
        let Response::Packet(p) = r.handle(q, "127.0.0.1:1".parse().unwrap()).await else {
            panic!("expected a reply");
        };
        // NOERROR with the A record returned to the guest.
        assert_eq!(p[3] & 0x0f, 0);
        assert!(p.windows(4).any(|w| w == [198, 51, 100, 5]));

        // Ephemeral admitted, TTL clamped to floor, scoped to tcp/443.
        use sodabox_common::allowlist::Decision;
        let al = al.read().unwrap();
        assert_eq!(al.ephemeral_len(), 1);
        assert!(matches!(
            al.evaluate(
                "198.51.100.5:443".parse().unwrap(),
                Proto::Tcp,
                Instant::now()
            ),
            Decision::AllowEphemeral { .. }
        ));
        assert_eq!(
            al.evaluate(
                "198.51.100.5:53".parse().unwrap(),
                Proto::Tcp,
                Instant::now()
            ),
            Decision::Deny
        );
    }

    /// A fake upstream that answers every A query with a CNAME to `target`
    /// followed by an A record *owned by that target* — the shape of a real
    /// CDN-fronted name like cache.nixos.org.
    async fn spawn_cname_upstream(target: &'static str, ip: std::net::Ipv4Addr) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(q) = wire::parse_query(&buf[..n]) else {
                    continue;
                };
                let ans = vec![
                    wire::Answer {
                        name: q.question.name.clone(),
                        ttl: 60,
                        data: RecordData::Cname(target.into()),
                    },
                    wire::Answer {
                        name: target.into(),
                        ttl: 60,
                        data: RecordData::A(ip),
                    },
                ];
                let resp = wire::build_response(&q, 0, &ans);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn cname_chain_survives_to_the_guest_and_admits_the_target_ip() {
        // cache.nixos.org is a CNAME to a Fastly host. The guest's
        // stub resolver needs the CNAME in the reply or it discards the A record
        // as a name mismatch ("could not resolve"), even though we allowed it.
        let target = "dualstack.n.sni.global.fastly.net";
        let ip = std::net::Ipv4Addr::new(146, 75, 121, 91);
        let upstream = spawn_cname_upstream(target, ip).await;

        let pol = VmPolicy {
            rules: vec![Rule::Domain {
                name: "cache.nixos.org".into(),
                scope: DomainScope::Subdomains,
                ports: None,
                proto: None,
            }],
            limits: Limits {
                max_ephemeral_entries: 10,
                ttl_floor_s: 30,
                ttl_cap_s: 300,
                ..Default::default()
            },
            ..VmPolicy::default()
        };
        let al = shared(Allowlist::from_policy(&pol).unwrap());
        let r = FilteringResolver::new(&pol, al.clone(), vec![upstream]).unwrap();

        let q = wire::parse_query(&wire::build_query(0x99, "cache.nixos.org", TYPE_A).unwrap())
            .unwrap();
        let Response::Packet(p) = r.handle(q, "127.0.0.1:1".parse().unwrap()).await else {
            panic!("expected a reply");
        };

        // The guest-facing reply must carry the CNAME chain: CNAME owned by the
        // queried name, then the A owned by the CNAME target.
        let parsed = wire::parse_response(&p).unwrap();
        assert_eq!(parsed.answers.len(), 2, "CNAME + A both present");
        assert_eq!(parsed.answers[0].name, "cache.nixos.org");
        assert_eq!(parsed.answers[0].data, wire::RData::Cname(target.into()));
        assert_eq!(parsed.answers[1].name, target);
        assert_eq!(parsed.answers[1].data, wire::RData::A(ip));

        // Only the resolved A IP is admitted for egress — the CNAME is not an
        // egress target and must not create an ephemeral entry.
        use sodabox_common::allowlist::Decision;
        let al = al.read().unwrap();
        assert_eq!(al.ephemeral_len(), 1);
        assert!(matches!(
            al.evaluate(
                "146.75.121.91:443".parse().unwrap(),
                Proto::Tcp,
                Instant::now()
            ),
            Decision::AllowEphemeral { .. }
        ));
    }

    #[tokio::test]
    async fn refused_query_emits_a_refused_event() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (r, _al) = resolver_with_domain("allowed.test");
        let r = r.with_events(Arc::new(ChannelEvents::new(tx)));

        let q = wire::parse_query(&wire::build_query(0x11, "evil.test", TYPE_A).unwrap()).unwrap();
        let _ = r.handle(q, "127.0.0.1:1".parse().unwrap()).await;

        match rx.try_recv().expect("a dns event") {
            Event::Dns {
                verdict,
                qname,
                answers,
                ttl,
                ..
            } => {
                assert_eq!(verdict, DnsVerdict::Refused);
                assert_eq!(qname, "evil.test");
                assert!(answers.is_empty());
                assert_eq!(ttl, 0);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn allowed_query_emits_an_allowed_event_with_ips_and_ttl() {
        let ip = std::net::Ipv4Addr::new(198, 51, 100, 5);
        let upstream = spawn_fake_upstream(ip, 5 /* below floor -> clamps to 30 */).await;

        let pol = VmPolicy {
            rules: vec![Rule::Domain {
                name: "allowed.test".into(),
                scope: DomainScope::Subdomains,
                ports: Some("443".into()),
                proto: Some("tcp".into()),
            }],
            limits: Limits {
                max_ephemeral_entries: 10,
                ttl_floor_s: 30,
                ttl_cap_s: 300,
                ..Default::default()
            },
            ..VmPolicy::default()
        };
        let al = shared(Allowlist::from_policy(&pol).unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let r = FilteringResolver::new(&pol, al, vec![upstream])
            .unwrap()
            .with_events(Arc::new(ChannelEvents::new(tx)));

        let q = wire::parse_query(&wire::build_query(0x55, "www.allowed.test", TYPE_A).unwrap())
            .unwrap();
        let _ = r.handle(q, "127.0.0.1:1".parse().unwrap()).await;

        match rx.try_recv().expect("a dns event") {
            Event::Dns {
                verdict,
                qname,
                answers,
                ttl,
                ..
            } => {
                assert_eq!(verdict, DnsVerdict::Allowed);
                assert_eq!(qname, "www.allowed.test");
                assert_eq!(answers, vec!["198.51.100.5".to_string()]);
                assert_eq!(ttl, 30); // clamped to the policy floor
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn allowed_name_with_no_upstream_is_servfail() {
        let (r, al) = resolver_with_domain("allowed.test");
        let q = wire::parse_query(&wire::build_query(0x22, "www.allowed.test", TYPE_A).unwrap())
            .unwrap();
        match r.handle(q, "127.0.0.1:1".parse().unwrap()).await {
            Response::Packet(p) => assert_eq!(p[3] & 0x0f, RCODE_SERVFAIL),
            Response::Drop => panic!("should have replied"),
        }
        // Nothing admitted (resolution failed).
        assert_eq!(al.read().unwrap().ephemeral_len(), 0);
    }

    #[test]
    fn admit_inserts_clamped_ephemeral_scoped_to_rule() {
        let (_r, al) = resolver_with_domain("allowed.test");
        let rule = DomainAllowlist::from_policy(&VmPolicy {
            rules: vec![Rule::Domain {
                name: "allowed.test".into(),
                scope: DomainScope::Subdomains,
                ports: Some("443".into()),
                proto: Some("tcp".into()),
            }],
            ..VmPolicy::default()
        })
        .unwrap();
        let rule: Vec<DomainRule> = rule.matches("allowed.test").into_iter().cloned().collect();
        let limits = Limits {
            max_ephemeral_entries: 10,
            ttl_floor_s: 30,
            ttl_cap_s: 300,
            ..Default::default()
        };

        let answers = vec![wire::Rr {
            name: "allowed.test".into(),
            ttl: 5, // below floor
            data: RData::A("203.0.113.10".parse().unwrap()),
        }];
        let admitted = admit(&al, &rule, &answers, &limits);
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].ttl, 30); // clamped to floor

        // The proxy would now allow tcp/443 to that IP.
        use sodabox_common::allowlist::Decision;
        let d = al.read().unwrap().evaluate(
            "203.0.113.10:443".parse().unwrap(),
            Proto::Tcp,
            Instant::now(),
        );
        assert!(matches!(d, Decision::AllowEphemeral { .. }));
        // ...but not udp, and not a different port.
        assert_eq!(
            al.read().unwrap().evaluate(
                "203.0.113.10:80".parse().unwrap(),
                Proto::Tcp,
                Instant::now()
            ),
            Decision::Deny
        );
    }

    #[test]
    fn admit_stops_at_the_anti_abuse_count_cap() {
        // A single allowed name that resolves to a spray of IPs must not admit
        // more than the per-VM count cap; the overflow is dropped and not
        // returned to the guest.
        let (_r, al) = resolver_with_domain("allowed.test");
        let rule = DomainAllowlist::from_policy(&VmPolicy {
            rules: vec![Rule::Domain {
                name: "allowed.test".into(),
                scope: DomainScope::Subdomains,
                ports: Some("443".into()),
                proto: Some("tcp".into()),
            }],
            ..VmPolicy::default()
        })
        .unwrap();
        let rule: Vec<DomainRule> = rule.matches("allowed.test").into_iter().cloned().collect();
        let limits = Limits {
            max_ephemeral_entries: 3,
            ttl_floor_s: 30,
            ttl_cap_s: 300,
            ..Default::default()
        };

        let answers: Vec<wire::Rr> = (1..=10u8)
            .map(|i| wire::Rr {
                name: "allowed.test".into(),
                ttl: 60,
                data: RData::A(std::net::Ipv4Addr::new(203, 0, 113, i)),
            })
            .collect();
        let admitted = admit(&al, &rule, &answers, &limits);
        assert_eq!(admitted.len(), 3); // capped at max_ephemeral_entries
        assert_eq!(al.read().unwrap().ephemeral_len(), 3);
    }
}
