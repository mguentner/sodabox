//! Effective egress allowlist evaluation (ADR-0004/0006), consumed
//! by the filter proxy.
//!
//! Deny-by-default: a recovered destination `(ip, port, proto)` is allowed iff it
//! matches a **static** IP rule (compiled from [`VmPolicy`]) or a live
//! **ephemeral** entry (an A/AAAA answer the DNS filter admitted for an allowed
//! domain, ADR-0005). Anything else is denied. Domain rules never match an IP
//! directly — they authorize resolution, and their answers arrive here as
//! ephemeral entries.
//!
//! No external crates: CIDR and port-range parsing are done in-house so the
//! policy path has no third-party attack surface.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::policy::{Limits, Rule, VmPolicy};

/// The live allowlist shared between the filter proxy (reader) and the DNS
/// filter / CLI (writers of ephemeral entries and policy swaps).
pub type SharedAllowlist = Arc<RwLock<Allowlist>>;

/// Wrap an [`Allowlist`] for sharing.
pub fn shared(allowlist: Allowlist) -> SharedAllowlist {
    Arc::new(RwLock::new(allowlist))
}

/// Transport protocol of the intercepted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn parse(s: &str) -> Result<Proto, String> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            other => Err(format!("unknown proto '{other}'")),
        }
    }
}

/// Why a destination was allowed (or not) — carried into egress events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Matched a static IP rule from the policy.
    AllowStatic,
    /// Matched a DNS-derived ephemeral entry for `domain`.
    AllowEphemeral { domain: String },
    /// No rule matched — deny.
    Deny,
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        !matches!(self, Decision::Deny)
    }
}

/// Whether `ip` may enter the ephemeral set: the address is one on the public
/// internet, not the host, its LAN or a link-local service such as a cloud
/// metadata endpoint. Whoever controls a name picks what it resolves to, so a
/// DNS answer alone must not open these (ADR-0021). An `ip` rule still can.
/// IPv6 forms that embed an IPv4 address are judged by that address.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || a == 0
                || a >= 240
                // Shared address space (CGNAT), RFC 6598.
                || (a == 100 && (64..128).contains(&b))
                // Benchmarking, RFC 2544.
                || (a == 198 && (b == 18 || b == 19)))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let embedded = |hi: u16, lo: u16| {
                is_public_ip(IpAddr::V4(std::net::Ipv4Addr::from(
                    (u32::from(hi) << 16) | u32::from(lo),
                )))
            };
            match s {
                // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96).
                [0, 0, 0, 0, 0, 0xffff, hi, lo] | [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] => {
                    embedded(hi, lo)
                }
                // 6to4 (2002::/16).
                [0x2002, hi, lo, ..] => embedded(hi, lo),
                _ => {
                    !(v6.is_unspecified()
                        || v6.is_loopback()
                        || v6.is_multicast()
                        // Unique local (fc00::/7).
                        || (s[0] & 0xfe00) == 0xfc00
                        // Link-local (fe80::/10) and the old site-local (fec0::/10).
                        || (s[0] & 0xff80) == 0xfe80
                        || (s[0] & 0xffc0) == 0xfec0)
                }
            }
        }
    }
}

/// A set of TCP/UDP ports: `None` means "any port".
#[derive(Debug, Clone, Default)]
pub struct PortSpec {
    /// Inclusive ranges; empty vec with `any=false` matches nothing.
    ranges: Vec<(u16, u16)>,
    any: bool,
}

impl PortSpec {
    /// Any port.
    pub fn any() -> Self {
        Self {
            ranges: Vec::new(),
            any: true,
        }
    }

    /// Parse `"443"`, `"80,443"`, `"1024-65535"`. `None` ⇒ any port.
    pub fn parse(s: Option<&str>) -> Result<PortSpec, String> {
        let Some(s) = s else {
            return Ok(PortSpec::any());
        };
        let s = s.trim();
        if s.is_empty() {
            return Ok(PortSpec::any());
        }
        let mut ranges = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            let range = match part.split_once('-') {
                Some((lo, hi)) => {
                    let lo: u16 = lo.trim().parse().map_err(|_| format!("bad port '{lo}'"))?;
                    let hi: u16 = hi.trim().parse().map_err(|_| format!("bad port '{hi}'"))?;
                    if lo > hi {
                        return Err(format!("inverted port range '{part}'"));
                    }
                    (lo, hi)
                }
                None => {
                    let p: u16 = part.parse().map_err(|_| format!("bad port '{part}'"))?;
                    (p, p)
                }
            };
            ranges.push(range);
        }
        Ok(PortSpec { ranges, any: false })
    }

    pub fn contains(&self, port: u16) -> bool {
        self.any || self.ranges.iter().any(|&(lo, hi)| lo <= port && port <= hi)
    }

    /// Whether any port is in both sets.
    pub fn overlaps(&self, other: &PortSpec) -> bool {
        self.any
            || other.any
            || self.ranges.iter().any(|&(lo, hi)| {
                other
                    .ranges
                    .iter()
                    .any(|&(other_lo, other_hi)| lo <= other_hi && other_lo <= hi)
            })
    }
}

/// An IPv4/IPv6 address or CIDR network.
#[derive(Debug, Clone, Copy)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl IpCidr {
    /// Parse `"10.0.0.0/8"`, `"192.168.1.5"` (host ⇒ /32), `"2001:db8::/32"`.
    pub fn parse(s: &str) -> Result<IpCidr, String> {
        let s = s.trim();
        let (addr_s, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let a: IpAddr = a.trim().parse().map_err(|_| format!("bad IP '{a}'"))?;
                let max = if a.is_ipv4() { 32 } else { 128 };
                let p: u8 = p.trim().parse().map_err(|_| format!("bad prefix '{p}'"))?;
                if p > max {
                    return Err(format!("prefix /{p} too large for {a}"));
                }
                (a, p)
            }
            None => {
                let a: IpAddr = s.parse().map_err(|_| format!("bad IP '{s}'"))?;
                (a, if a.is_ipv4() { 32 } else { 128 })
            }
        };
        Ok(IpCidr {
            addr: addr_s,
            prefix,
        })
    }

    /// The prefix length — larger is more specific (longest-prefix ordering).
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Does this network contain `ip`? (Address families must match.)
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let net = u32::from(net);
                let ip = u32::from(ip);
                let mask = mask_u32(self.prefix);
                (net & mask) == (ip & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let net = u128::from(net);
                let ip = u128::from(ip);
                let mask = mask_u128(self.prefix);
                (net & mask) == (ip & mask)
            }
            _ => false, // v4 rule never matches a v6 dst and vice versa
        }
    }

    /// Does this network contain all of `other`?
    pub fn covers(&self, other: &IpCidr) -> bool {
        self.prefix <= other.prefix && self.contains(other.addr)
    }
}

fn mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// A compiled static rule.
#[derive(Debug, Clone)]
struct StaticRule {
    cidr: IpCidr,
    ports: PortSpec,
    /// `None` ⇒ any protocol.
    proto: Option<Proto>,
}

impl StaticRule {
    fn matches(&self, ip: IpAddr, port: u16, proto: Proto) -> bool {
        self.proto.map_or(true, |p| p == proto)
            && self.cidr.contains(ip)
            && self.ports.contains(port)
    }
}

/// A DNS-derived ephemeral permit (ADR-0005): an answer IP for an allowed
/// domain, valid until `expiry`.
#[derive(Debug, Clone)]
pub struct EphemeralEntry {
    pub ip: IpAddr,
    pub ports: PortSpec,
    pub proto: Option<Proto>,
    pub expiry: Instant,
    /// The domain whose resolution admitted this IP (for events).
    pub domain: String,
}

impl EphemeralEntry {
    /// Estimated in-memory footprint of this entry, for the total-size
    /// anti-abuse cap: the fixed struct plus its heap-allocated
    /// parts (the `domain` string and the port ranges).
    fn heap_size(&self) -> usize {
        std::mem::size_of::<EphemeralEntry>()
            + self.domain.len()
            + self.ports.ranges.len() * std::mem::size_of::<(u16, u16)>()
    }
}

/// The effective allowlist for one VM: compiled static rules plus the live
/// ephemeral set. `evaluate` is the single decision point the proxy calls per
/// connection.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    version: u32,
    static_rules: Vec<StaticRule>,
    ephemeral: Vec<EphemeralEntry>,
}

impl Allowlist {
    /// Compile the static portion from a policy. Domain rules are skipped here —
    /// they enter as ephemeral entries via the DNS filter. Returns an error on
    /// any malformed rule (fail-closed: a broken policy must not silently widen
    /// access).
    pub fn from_policy(policy: &VmPolicy) -> Result<Allowlist, String> {
        let mut static_rules = Vec::new();
        for rule in &policy.rules {
            if let Rule::Ip { cidr, ports, proto } = rule {
                static_rules.push(StaticRule {
                    cidr: IpCidr::parse(cidr)?,
                    ports: PortSpec::parse(ports.as_deref())?,
                    proto: proto.as_deref().map(Proto::parse).transpose()?,
                });
            }
        }
        Ok(Allowlist {
            version: policy.version,
            static_rules,
            ephemeral: Vec::new(),
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// Live policy swap (ADR-0006): replace the static rules and
    /// version from `policy`, **retaining only the ephemeral entries whose
    /// admitting domain rule still exists** (matched by name). Removing a domain
    /// rule therefore purges its DNS-derived IPs immediately, while unchanged
    /// domains keep their cached answers so working flows are not disrupted.
    ///
    /// Atomic and fail-safe: the new policy is validated (via [`from_policy`])
    /// *before* any field is mutated, so an invalid policy leaves `self`
    /// untouched. Callers hold the [`SharedAllowlist`] write lock, so a reader
    /// never observes a half-applied swap.
    ///
    /// Note: an ephemeral records its admitting rule's *name* (not the resolved
    /// FQDN), so narrowing a **kept** domain's scope/ports does not retroactively
    /// purge already-cached IPs — those age out at their TTL, and no new
    /// out-of-scope IPs are admitted meanwhile (the DNS filter re-checks scope on
    /// every query). Rule *removal* — this ticket's contract — is exact.
    ///
    /// [`from_policy`]: Allowlist::from_policy
    /// [`SharedAllowlist`]: crate::allowlist::SharedAllowlist
    pub fn swap_policy(&mut self, policy: &VmPolicy) -> Result<(), String> {
        let rebuilt = Allowlist::from_policy(policy)?; // validates; no mutation yet
        let live_domains: std::collections::HashSet<&str> = policy
            .rules
            .iter()
            .filter_map(|r| match r {
                Rule::Domain { name, .. } => Some(name.as_str()),
                Rule::Ip { .. } | Rule::Resolve { .. } | Rule::Service { .. } => None,
            })
            .collect();
        self.static_rules = rebuilt.static_rules;
        self.version = rebuilt.version;
        self.ephemeral
            .retain(|e| live_domains.contains(e.domain.as_str()));
        Ok(())
    }

    /// Add (or refresh) an ephemeral permit from the DNS filter, unconditionally.
    /// Prefer [`try_insert_ephemeral`] on the admission path so the per-VM
    /// anti-abuse caps are enforced.
    ///
    /// [`try_insert_ephemeral`]: Allowlist::try_insert_ephemeral
    pub fn insert_ephemeral(&mut self, entry: EphemeralEntry) {
        self.ephemeral.push(entry);
    }

    /// Admit an ephemeral permit, enforcing the per-VM anti-abuse caps:
    /// reject if it would push the live set past
    /// `max_ephemeral_entries` (count) or `max_ephemeral_bytes` (estimated total
    /// size). Returns `true` if admitted, `false` if a cap would be exceeded — in
    /// which case the entry is dropped and that IP simply stays deny-by-default.
    ///
    /// The caller should [`prune_expired`] first so expired entries don't count
    /// against a live spray.
    ///
    /// [`prune_expired`]: Allowlist::prune_expired
    pub fn try_insert_ephemeral(&mut self, entry: EphemeralEntry, limits: &Limits) -> bool {
        if self.ephemeral.len() >= limits.max_ephemeral_entries as usize {
            return false;
        }
        if self.ephemeral_bytes() + entry.heap_size() > limits.max_ephemeral_bytes as usize {
            return false;
        }
        self.ephemeral.push(entry);
        true
    }

    /// Drop expired ephemeral entries as of `now`.
    pub fn prune_expired(&mut self, now: Instant) {
        self.ephemeral.retain(|e| e.expiry > now);
    }

    pub fn ephemeral_len(&self) -> usize {
        self.ephemeral.len()
    }

    /// Estimated total in-memory size of the live ephemeral set, in bytes — the
    /// quantity bounded by `max_ephemeral_bytes`.
    pub fn ephemeral_bytes(&self) -> usize {
        self.ephemeral.iter().map(EphemeralEntry::heap_size).sum()
    }

    /// Decide egress for a recovered destination. Static rules are checked first
    /// (most specific / longest-prefix first), then unexpired ephemeral entries,
    /// then deny.
    pub fn evaluate(&self, dst: SocketAddr, proto: Proto, now: Instant) -> Decision {
        let ip = dst.ip();
        let port = dst.port();

        // Static: prefer the most specific match, for deterministic ordering. The
        // blocklist doesn't come in here: it only answers what this denies.
        let mut best: Option<&StaticRule> = None;
        for r in &self.static_rules {
            if r.matches(ip, port, proto)
                && best.map_or(true, |b| r.cidr.prefix() > b.cidr.prefix())
            {
                best = Some(r);
            }
        }
        if best.is_some() {
            return Decision::AllowStatic;
        }

        // Ephemeral: any unexpired matching entry.
        for e in &self.ephemeral {
            if e.expiry > now
                && e.proto.map_or(true, |p| p == proto)
                && e.ip == ip
                && e.ports.contains(port)
            {
                return Decision::AllowEphemeral {
                    domain: e.domain.clone(),
                };
            }
        }

        Decision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::VmPolicy;
    use std::time::Duration;

    fn ip_rule(cidr: &str, ports: Option<&str>, proto: Option<&str>) -> Rule {
        Rule::Ip {
            cidr: cidr.into(),
            ports: ports.map(Into::into),
            proto: proto.map(Into::into),
        }
    }

    #[test]
    fn only_public_addresses_count_as_public() {
        for ip in [
            "93.184.216.34",
            "203.0.113.5",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700::1111",
            "::ffff:93.184.216.34",
            "64:ff9b::5db8:d822",
            "2002:5db8:d822::1",
        ] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd00:ec2::254",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "::ffff:192.168.1.1",
            "64:ff9b::a9fe:a9fe",
            "2002:c0a8:101::1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn policy_with(rules: Vec<Rule>) -> VmPolicy {
        VmPolicy {
            rules,
            ..VmPolicy::default()
        }
    }

    #[test]
    fn portspec_parsing() {
        assert!(PortSpec::parse(None).unwrap().contains(1234));
        assert!(PortSpec::parse(Some("443")).unwrap().contains(443));
        assert!(!PortSpec::parse(Some("443")).unwrap().contains(444));
        let p = PortSpec::parse(Some("80,443,8000-8100")).unwrap();
        assert!(p.contains(80) && p.contains(443) && p.contains(8050));
        assert!(!p.contains(8101));
        assert!(PortSpec::parse(Some("5-1")).is_err());
        assert!(PortSpec::parse(Some("x")).is_err());
    }

    #[test]
    fn cidr_containment_and_family() {
        let n = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(n.contains("10.1.2.3".parse().unwrap()));
        assert!(!n.contains("11.0.0.1".parse().unwrap()));
        // host address ⇒ /32
        let h = IpCidr::parse("1.2.3.4").unwrap();
        assert!(h.contains("1.2.3.4".parse().unwrap()));
        assert!(!h.contains("1.2.3.5".parse().unwrap()));
        // v6, and cross-family never matches
        let v6 = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::dead".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(!n.contains("2001:db8::1".parse().unwrap()));
        // /0 matches everything of its family
        assert!(IpCidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        assert!(IpCidr::parse("33.0.0.0/33").is_err());
    }

    #[test]
    fn static_allow_and_default_deny() {
        let pol = policy_with(vec![ip_rule("93.184.216.0/24", Some("443"), Some("tcp"))]);
        let al = Allowlist::from_policy(&pol).unwrap();
        let now = Instant::now();

        assert_eq!(
            al.evaluate(sa("93.184.216.34:443"), Proto::Tcp, now),
            Decision::AllowStatic
        );
        // wrong port, wrong proto, wrong net all deny
        assert_eq!(
            al.evaluate(sa("93.184.216.34:80"), Proto::Tcp, now),
            Decision::Deny
        );
        assert_eq!(
            al.evaluate(sa("93.184.216.34:443"), Proto::Udp, now),
            Decision::Deny
        );
        assert_eq!(
            al.evaluate(sa("8.8.8.8:443"), Proto::Tcp, now),
            Decision::Deny
        );
    }

    #[test]
    fn ephemeral_allow_and_expiry() {
        let al_base = Allowlist::from_policy(&VmPolicy::default()).unwrap();
        let mut al = al_base;
        let now = Instant::now();
        al.insert_ephemeral(EphemeralEntry {
            ip: "203.0.113.9".parse().unwrap(),
            ports: PortSpec::any(),
            proto: Some(Proto::Tcp),
            expiry: now + Duration::from_secs(30),
            domain: "example.com".into(),
        });
        assert_eq!(
            al.evaluate(sa("203.0.113.9:443"), Proto::Tcp, now),
            Decision::AllowEphemeral {
                domain: "example.com".into()
            }
        );
        // proto mismatch denies
        assert_eq!(
            al.evaluate(sa("203.0.113.9:443"), Proto::Udp, now),
            Decision::Deny
        );
        // expired denies + pruned
        let later = now + Duration::from_secs(31);
        assert_eq!(
            al.evaluate(sa("203.0.113.9:443"), Proto::Tcp, later),
            Decision::Deny
        );
        al.prune_expired(later);
        assert_eq!(al.ephemeral_len(), 0);
    }

    fn limits(max_entries: u32, max_bytes: u64) -> Limits {
        Limits {
            max_ephemeral_entries: max_entries,
            max_ephemeral_bytes: max_bytes,
            ttl_floor_s: 5,
            ttl_cap_s: 3600,
        }
    }

    #[test]
    fn try_insert_enforces_count_cap() {
        let mut al = Allowlist::from_policy(&VmPolicy::default()).unwrap();
        let lim = limits(2, u64::MAX); // count binds, size doesn't
        assert!(al.try_insert_ephemeral(ephemeral_for("203.0.113.1", "example.com"), &lim));
        assert!(al.try_insert_ephemeral(ephemeral_for("203.0.113.2", "example.com"), &lim));
        // The third would exceed the count cap and is refused; nothing is added.
        assert!(!al.try_insert_ephemeral(ephemeral_for("203.0.113.3", "example.com"), &lim));
        assert_eq!(al.ephemeral_len(), 2);
    }

    #[test]
    fn try_insert_enforces_size_cap() {
        let mut al = Allowlist::from_policy(&VmPolicy::default()).unwrap();
        // A byte cap that fits exactly one entry of this size but not a second.
        let one = ephemeral_for("203.0.113.1", "example.com").heap_size() as u64;
        let lim = limits(u32::MAX, one); // size binds, count doesn't
        assert!(al.try_insert_ephemeral(ephemeral_for("203.0.113.1", "example.com"), &lim));
        assert_eq!(al.ephemeral_bytes(), one as usize);
        // A second would push total size over the cap -> refused.
        assert!(!al.try_insert_ephemeral(ephemeral_for("203.0.113.2", "example.com"), &lim));
        assert_eq!(al.ephemeral_len(), 1);
        assert_eq!(al.ephemeral_bytes(), one as usize);

        // Pruning the (only) entry frees the budget so admission resumes.
        al.prune_expired(Instant::now() + Duration::from_secs(600));
        assert_eq!(al.ephemeral_bytes(), 0);
        assert!(al.try_insert_ephemeral(ephemeral_for("203.0.113.3", "example.com"), &lim));
    }

    #[test]
    fn malformed_policy_is_rejected() {
        let pol = policy_with(vec![ip_rule("not-an-ip", None, None)]);
        assert!(Allowlist::from_policy(&pol).is_err());
    }

    #[test]
    fn longest_prefix_preferred() {
        let pol = policy_with(vec![
            ip_rule("10.0.0.0/8", Some("443"), None),
            ip_rule("10.1.2.0/24", Some("443"), None),
        ]);
        let al = Allowlist::from_policy(&pol).unwrap();
        // Both match; the /24 is the more specific winner. (Both allow here, but
        // the selection is what a future deny-rule model relies on.)
        assert_eq!(
            al.evaluate(sa("10.1.2.3:443"), Proto::Tcp, Instant::now()),
            Decision::AllowStatic
        );
    }

    fn domain_rule(name: &str) -> Rule {
        Rule::Domain {
            name: name.into(),
            scope: crate::policy::DomainScope::Subdomains,
            ports: None,
            proto: None,
        }
    }

    fn ephemeral_for(ip: &str, domain: &str) -> EphemeralEntry {
        EphemeralEntry {
            ip: ip.parse().unwrap(),
            ports: PortSpec::any(),
            proto: Some(Proto::Tcp),
            expiry: Instant::now() + Duration::from_secs(300),
            domain: domain.into(),
        }
    }

    #[test]
    fn swap_policy_purges_removed_domain_ephemerals_only() {
        // Start allowing two domains + a static IP, each with a cached answer.
        let mut al = Allowlist::from_policy(&policy_with(vec![
            ip_rule("10.0.0.0/8", None, None),
            domain_rule("keep.test"),
            domain_rule("gone.test"),
        ]))
        .unwrap();
        al.insert_ephemeral(ephemeral_for("203.0.113.1", "keep.test"));
        al.insert_ephemeral(ephemeral_for("203.0.113.2", "gone.test"));
        assert_eq!(al.ephemeral_len(), 2);

        // New policy drops gone.test (and the /8, adds a /16) and bumps version.
        let new = VmPolicy {
            version: 5,
            rules: vec![
                ip_rule("192.168.0.0/16", None, None),
                domain_rule("keep.test"),
            ],
            ..VmPolicy::default()
        };
        al.swap_policy(&new).unwrap();

        // Version stamped; static rules rebuilt; only the surviving domain's
        // ephemeral is retained.
        assert_eq!(al.version(), 5);
        assert_eq!(al.ephemeral_len(), 1);
        let now = Instant::now();
        assert_eq!(
            al.evaluate(sa("203.0.113.1:443"), Proto::Tcp, now),
            Decision::AllowEphemeral {
                domain: "keep.test".into()
            }
        );
        assert_eq!(
            al.evaluate(sa("203.0.113.2:443"), Proto::Tcp, now),
            Decision::Deny
        );
        // New static took effect; old one is gone.
        assert_eq!(
            al.evaluate(sa("192.168.1.1:80"), Proto::Tcp, now),
            Decision::AllowStatic
        );
        assert_eq!(
            al.evaluate(sa("10.1.1.1:80"), Proto::Tcp, now),
            Decision::Deny
        );
    }

    #[test]
    fn swap_policy_rejects_bad_and_leaves_unchanged() {
        let mut al = Allowlist::from_policy(&policy_with(vec![domain_rule("keep.test")])).unwrap();
        al.insert_ephemeral(ephemeral_for("203.0.113.1", "keep.test"));
        let before_ver = al.version();

        // An invalid new policy must be rejected without mutating anything.
        let bad = VmPolicy {
            version: 99,
            rules: vec![ip_rule("not-an-ip", None, None), domain_rule("keep.test")],
            ..VmPolicy::default()
        };
        assert!(al.swap_policy(&bad).is_err());
        assert_eq!(al.version(), before_ver);
        assert_eq!(al.ephemeral_len(), 1); // ephemeral untouched
    }
}
