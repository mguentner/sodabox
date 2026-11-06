//! The compiled blocklist (ADR-0021), consulted when a request no rule covers
//! would otherwise be held and asked about.
//!
//! An entry can't grant anything: everything it doesn't match is still
//! deny-by-default, and it is only reached once the allow rules have said no. So
//! a broken or unreadable list costs a prompt, not a hole.

use std::net::SocketAddr;

use crate::allowlist::{IpCidr, PortSpec, Proto};
use crate::policy::{normalize_name, BlocklistEntry, DomainScope, Rule, VmPolicy};

enum Target {
    Ip(IpCidr),
    Name { name: String, scope: DomainScope },
}

struct Compiled {
    target: Target,
    ports: PortSpec,
    proto: Option<Proto>,
    /// Neither `ports` nor `proto`: a name entry like this refuses lookups too.
    whole: bool,
}

impl Compiled {
    fn covers(&self, port: u16, proto: Proto) -> bool {
        self.ports.contains(port) && self.proto.map_or(true, |p| p == proto)
    }
}

/// The blocklist of one VM.
#[derive(Default)]
pub struct Blocklist {
    entries: Vec<Compiled>,
}

impl Blocklist {
    /// Compile `policy`'s entries. A malformed one is an error, like a malformed
    /// rule, so a policy with one is rejected as a whole.
    pub fn from_policy(policy: &VmPolicy) -> Result<Blocklist, String> {
        let mut entries = Vec::new();
        for entry in &policy.blocklist {
            entry.validate()?;
            let (target, ports, proto) = match entry {
                BlocklistEntry::Ip { cidr, ports, proto } => {
                    (Target::Ip(IpCidr::parse(cidr)?), ports, proto)
                }
                BlocklistEntry::Domain {
                    name,
                    scope,
                    ports,
                    proto,
                } => (
                    Target::Name {
                        name: normalize_name(name),
                        scope: *scope,
                    },
                    ports,
                    proto,
                ),
            };
            entries.push(Compiled {
                target,
                ports: PortSpec::parse(ports.as_deref())?,
                proto: proto.as_deref().map(Proto::parse).transpose()?,
                whole: ports.is_none() && proto.is_none(),
            });
        }
        Ok(Blocklist { entries })
    }

    /// Whether a lookup of `qname` is refused without asking.
    pub fn blocks_name(&self, qname: &str) -> bool {
        let qname = normalize_name(qname);
        self.entries.iter().any(|e| {
            e.whole
                && matches!(&e.target, Target::Name { name, scope } if scope.matches(name, &qname))
        })
    }

    /// Whether a connection to `dst` is refused without asking. `via` is the name
    /// the address came from, if one is remembered.
    pub fn blocks_address(&self, dst: SocketAddr, proto: Proto, via: Option<&str>) -> bool {
        let via = via.map(normalize_name);
        self.entries.iter().any(|e| {
            e.covers(dst.port(), proto)
                && match &e.target {
                    Target::Ip(cidr) => cidr.contains(dst.ip()),
                    Target::Name { name, scope } => {
                        via.as_deref().is_some_and(|v| scope.matches(name, v))
                    }
                }
        })
    }
}

/// The entries of `blocklist` that `rules` make pointless: since an allow rule
/// wins, they no longer decide anything, but they would come back into force if
/// the rule were revoked.
pub fn overridden_by<'a>(
    rules: &[Rule],
    blocklist: &'a [BlocklistEntry],
) -> Vec<&'a BlocklistEntry> {
    blocklist
        .iter()
        .filter(|entry| rules.iter().any(|rule| rule_overrides(rule, entry)))
        .collect()
}

fn rule_overrides(rule: &Rule, entry: &BlocklistEntry) -> bool {
    match (rule, entry) {
        (
            Rule::Ip { cidr, ports, proto },
            BlocklistEntry::Ip {
                cidr: blocked,
                ports: blocked_ports,
                proto: blocked_proto,
            },
        ) => {
            let (Ok(cidr), Ok(blocked)) = (IpCidr::parse(cidr), IpCidr::parse(blocked)) else {
                return false;
            };
            cidr.covers(&blocked) && traffic_overlaps(ports, proto, blocked_ports, blocked_proto)
        }
        (
            Rule::Domain {
                name,
                scope,
                ports,
                proto,
            },
            BlocklistEntry::Domain {
                name: blocked,
                scope: blocked_scope,
                ports: blocked_ports,
                proto: blocked_proto,
            },
        ) => {
            name_covers(name, *scope, blocked, *blocked_scope)
                && traffic_overlaps(ports, proto, blocked_ports, blocked_proto)
        }
        // Resolving overrides what an entry says about lookups, and only a whole
        // name entry says anything about those.
        (
            Rule::Resolve { name, scope },
            BlocklistEntry::Domain {
                name: blocked,
                scope: blocked_scope,
                ports: None,
                proto: None,
            },
        ) => name_covers(name, *scope, blocked, *blocked_scope),
        _ => false,
    }
}

/// Whether the rule's name and scope take in everything the entry's do.
fn name_covers(name: &str, scope: DomainScope, blocked: &str, blocked_scope: DomainScope) -> bool {
    let (name, blocked) = (normalize_name(name), normalize_name(blocked));
    match blocked_scope {
        DomainScope::Exact => scope.matches(&name, &blocked),
        _ => name == blocked && (scope == DomainScope::Subdomains || scope == blocked_scope),
    }
}

fn traffic_overlaps(
    ports: &Option<String>,
    proto: &Option<String>,
    blocked_ports: &Option<String>,
    blocked_proto: &Option<String>,
) -> bool {
    let protos_meet = match (proto, blocked_proto) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => true,
    };
    let (Ok(ports), Ok(blocked)) = (
        PortSpec::parse(ports.as_deref()),
        PortSpec::parse(blocked_ports.as_deref()),
    ) else {
        return false;
    };
    protos_meet && ports.overlaps(&blocked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(n: &str, ports: Option<&str>, proto: Option<&str>) -> BlocklistEntry {
        BlocklistEntry::Domain {
            name: n.into(),
            scope: DomainScope::Exact,
            ports: ports.map(Into::into),
            proto: proto.map(Into::into),
        }
    }

    fn ip(cidr: &str, ports: Option<&str>, proto: Option<&str>) -> BlocklistEntry {
        BlocklistEntry::Ip {
            cidr: cidr.into(),
            ports: ports.map(Into::into),
            proto: proto.map(Into::into),
        }
    }

    fn compile(entries: Vec<BlocklistEntry>) -> Blocklist {
        Blocklist::from_policy(&VmPolicy {
            blocklist: entries,
            ..VmPolicy::default()
        })
        .unwrap()
    }

    fn dst(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_exact_name_entry_refuses_that_name_only() {
        let list = compile(vec![name("telemetry.example.com", None, None)]);
        assert!(list.blocks_name("telemetry.example.com"));
        assert!(list.blocks_name("TELEMETRY.example.com."));
        assert!(!list.blocks_name("x.telemetry.example.com"));
        assert!(!list.blocks_name("example.com"));
    }

    #[test]
    fn a_scope_can_widen_a_name_entry() {
        let list = compile(vec![BlocklistEntry::Domain {
            name: "telemetry.example.com".into(),
            scope: DomainScope::Subdomains,
            ports: None,
            proto: None,
        }]);
        assert!(list.blocks_name("telemetry.example.com"));
        assert!(list.blocks_name("x.telemetry.example.com"));
    }

    #[test]
    fn a_name_entry_with_ports_leaves_lookups_alone() {
        // TCP is allowed and HTTP/3 keeps asking: the name has to keep resolving.
        let list = compile(vec![name("example.com", Some("443"), Some("udp"))]);
        assert!(!list.blocks_name("example.com"));
        let a = dst("203.0.113.5:443");
        assert!(list.blocks_address(a, Proto::Udp, Some("example.com")));
        assert!(!list.blocks_address(a, Proto::Tcp, Some("example.com")));
        assert!(!list.blocks_address(dst("203.0.113.5:80"), Proto::Udp, Some("example.com")));
        // Nothing connects the address to the name without a remembered lookup.
        assert!(!list.blocks_address(a, Proto::Udp, None));
        assert!(!list.blocks_address(a, Proto::Udp, Some("other.test")));
    }

    #[test]
    fn a_whole_name_entry_covers_its_addresses_on_any_port() {
        let list = compile(vec![name("example.com", None, None)]);
        assert!(list.blocks_address(dst("203.0.113.5:22"), Proto::Tcp, Some("example.com.")));
    }

    #[test]
    fn an_ip_entry_matches_its_address_port_and_proto() {
        let list = compile(vec![ip("203.0.113.0/24", Some("22"), Some("tcp"))]);
        assert!(list.blocks_address(dst("203.0.113.5:22"), Proto::Tcp, None));
        assert!(!list.blocks_address(dst("203.0.113.5:22"), Proto::Udp, None));
        assert!(!list.blocks_address(dst("203.0.113.5:23"), Proto::Tcp, None));
        assert!(!list.blocks_address(dst("198.51.100.1:22"), Proto::Tcp, None));
        assert!(!list.blocks_name("203.0.113.5"));
    }

    #[test]
    fn a_malformed_entry_rejects_the_policy() {
        for bad in [ip("nope", None, None), ip("1.2.3.4", Some("x"), None)] {
            let policy = VmPolicy {
                blocklist: vec![bad],
                ..VmPolicy::default()
            };
            assert!(Blocklist::from_policy(&policy).is_err());
        }
    }

    #[test]
    fn a_rule_overrides_only_the_entries_it_overlaps() {
        let domain = |n: &str, scope, ports: Option<&str>, proto: Option<&str>| Rule::Domain {
            name: n.into(),
            scope,
            ports: ports.map(Into::into),
            proto: proto.map(Into::into),
        };
        let subs = DomainScope::Subdomains;
        let udp443 = name("example.com", Some("443"), Some("udp"));
        let whole = name("example.com", None, None);
        let list = [udp443.clone(), whole.clone()];

        // A TCP rule doesn't touch the UDP entry, but does touch the whole name.
        let tcp = domain("example.com", subs, Some("443"), Some("tcp"));
        assert_eq!(overridden_by(&[tcp], &list), vec![&whole]);
        // Any protocol on 443 overlaps both, and so does a rule on a parent.
        let https = domain("example.com", subs, Some("443"), None);
        assert_eq!(overridden_by(&[https], &list).len(), 2);
        let parent = domain("com", subs, None, None);
        assert_eq!(overridden_by(&[parent], &list).len(), 2);
        // An exact rule on a subdomain doesn't cover its parent.
        let child = domain("api.example.com", DomainScope::Exact, None, None);
        assert!(overridden_by(&[child], &list).is_empty());
        // Resolving only speaks to the entry that refuses lookups.
        let resolve = Rule::Resolve {
            name: "example.com".into(),
            scope: subs,
        };
        assert_eq!(overridden_by(&[resolve], &list), vec![&whole]);
    }

    #[test]
    fn a_narrow_rule_does_not_override_a_wider_entry() {
        let wide = BlocklistEntry::Domain {
            name: "example.com".into(),
            scope: DomainScope::Subdomains,
            ports: None,
            proto: None,
        };
        let exact = Rule::Domain {
            name: "example.com".into(),
            scope: DomainScope::Exact,
            ports: None,
            proto: None,
        };
        assert!(overridden_by(&[exact], std::slice::from_ref(&wide)).is_empty());
    }

    #[test]
    fn an_ip_rule_overrides_ip_entries_it_contains() {
        let rule = |cidr: &str, ports: Option<&str>| Rule::Ip {
            cidr: cidr.into(),
            ports: ports.map(Into::into),
            proto: None,
        };
        let list = [ip("203.0.113.5", Some("443"), Some("tcp"))];
        assert_eq!(
            overridden_by(&[rule("203.0.113.5", Some("443"))], &list).len(),
            1
        );
        assert_eq!(
            overridden_by(&[rule("203.0.113.0/24", None)], &list).len(),
            1
        );
        assert!(overridden_by(&[rule("203.0.113.5", Some("80"))], &list).is_empty());
        assert!(overridden_by(&[rule("198.51.100.1", None)], &list).is_empty());
        // One address in a blocked network leaves the rest of it blocked.
        let net = [ip("203.0.113.0/24", None, None)];
        assert!(overridden_by(&[rule("203.0.113.5", None)], &net).is_empty());
    }
}
