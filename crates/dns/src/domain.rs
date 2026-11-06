//! Domain allowlist matching for the DNS filter (ADR-0005/0006).
//!
//! Default-deny: a guest query resolves only if its name matches a `Domain` rule
//! in the VM policy; otherwise it is REFUSED (blocking DNS/QNAME exfiltration).
//! Scope (from [`DomainScope`]):
//! - `Exact` — only the name itself.
//! - `Subdomains` (default) — the name and any subdomain.
//! - `Wildcard` — strict subdomains only (not the apex), i.e. `*.name`.

use std::sync::{Arc, RwLock};

use sodabox_common::allowlist::{PortSpec, Proto};
use sodabox_common::policy::{normalize_name as normalize, DomainScope, Rule, VmPolicy};

/// The live domain allowlist shared between the DNS filter (reader, on every
/// query) and the control plane (writer, on a live policy swap). Mirrors
/// [`SharedAllowlist`] for the proxy's IP/ephemeral set so a `PolicySet` updates
/// both consumers atomically.
///
/// [`SharedAllowlist`]: sodabox_common::allowlist::SharedAllowlist
pub type SharedDomainAllowlist = Arc<RwLock<DomainAllowlist>>;

/// Wrap a [`DomainAllowlist`] for sharing.
pub fn shared(domains: DomainAllowlist) -> SharedDomainAllowlist {
    Arc::new(RwLock::new(domains))
}

/// A compiled domain rule.
#[derive(Debug, Clone)]
pub struct DomainRule {
    /// Normalised (lowercased, no trailing dot) allowlisted name.
    pub name: String,
    pub scope: DomainScope,
    /// Ports admitted for the resolved IPs (into the ephemeral set).
    pub ports: PortSpec,
    pub proto: Option<Proto>,
    /// Whether resolved IPs enter the ephemeral set: true for a `domain` rule,
    /// false for a `resolve` rule (ADR-0021).
    pub admits: bool,
}

impl DomainRule {
    fn matches(&self, qname: &str) -> bool {
        self.scope.matches(&self.name, qname)
    }
}

/// The set of domain rules for one VM.
#[derive(Debug, Clone, Default)]
pub struct DomainAllowlist {
    rules: Vec<DomainRule>,
}

impl DomainAllowlist {
    /// Compile the `Domain` and `Resolve` rules from a policy. Malformed
    /// port/proto specs are an error (fail-closed). IP rules are ignored here
    /// (they are the proxy's).
    pub fn from_policy(policy: &VmPolicy) -> Result<DomainAllowlist, String> {
        let mut rules = Vec::new();
        for rule in &policy.rules {
            match rule {
                Rule::Domain {
                    name,
                    scope,
                    ports,
                    proto,
                } => rules.push(DomainRule {
                    name: normalize(name),
                    scope: *scope,
                    ports: PortSpec::parse(ports.as_deref())?,
                    proto: proto.as_deref().map(Proto::parse).transpose()?,
                    admits: true,
                }),
                Rule::Resolve { name, scope } => rules.push(DomainRule {
                    name: normalize(name),
                    scope: *scope,
                    ports: PortSpec::any(),
                    proto: None,
                    admits: false,
                }),
                Rule::Ip { .. } | Rule::Service { .. } => {}
            }
        }
        Ok(DomainAllowlist { rules })
    }

    /// The rules granting `qname` (case-insensitive), empty if the name is not
    /// allowlisted. Every matching `domain` rule applies, since the policy only
    /// holds allows: a rule added for another port or a subdomain adds to what
    /// is granted rather than replacing it. `resolve` rules count only when no
    /// `domain` rule matches: an approved DNS request must not narrow what a
    /// written rule grants.
    pub fn matches(&self, qname: &str) -> Vec<&DomainRule> {
        let q = normalize(qname);
        let matching = || self.rules.iter().filter(|r| r.matches(&q));
        if matching().any(|r| r.admits) {
            matching().filter(|r| r.admits).collect()
        } else {
            matching().collect()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Live policy swap: recompile the domain rules from `policy`,
    /// replacing the current set. Validated before any mutation (via
    /// [`from_policy`]), so a malformed policy leaves `self` untouched
    /// (fail-closed). Callers hold the [`SharedDomainAllowlist`] write lock, so a
    /// reader never observes a half-applied swap.
    ///
    /// [`from_policy`]: DomainAllowlist::from_policy
    pub fn swap_policy(&mut self, policy: &VmPolicy) -> Result<(), String> {
        let rebuilt = DomainAllowlist::from_policy(policy)?; // validates; no mutation yet
        self.rules = rebuilt.rules;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain_rule(name: &str, scope: DomainScope) -> Rule {
        Rule::Domain {
            name: name.into(),
            scope,
            ports: None,
            proto: None,
        }
    }

    fn al(rules: Vec<Rule>) -> DomainAllowlist {
        DomainAllowlist::from_policy(&VmPolicy {
            rules,
            ..VmPolicy::default()
        })
        .unwrap()
    }

    #[test]
    fn domain_rule_wins_over_a_more_specific_resolve_rule() {
        let resolve = |name: &str| Rule::Resolve {
            name: name.into(),
            scope: DomainScope::Subdomains,
        };
        let a = al(vec![
            domain_rule("example.com", DomainScope::Subdomains),
            resolve("api.example.com"),
            resolve("other.test"),
        ]);
        assert!(a.matches("api.example.com").iter().all(|r| r.admits));
        assert_eq!(a.matches("api.example.com").len(), 1);
        assert!(a.matches("www.example.com")[0].admits);
        assert!(!a.matches("www.other.test")[0].admits);
    }

    #[test]
    fn exact_scope() {
        let a = al(vec![domain_rule("example.com", DomainScope::Exact)]);
        assert!(!a.matches("example.com").is_empty());
        assert!(!a.matches("EXAMPLE.COM.").is_empty()); // case + trailing dot
        assert!(a.matches("www.example.com").is_empty());
    }

    #[test]
    fn subdomains_scope_includes_apex() {
        let a = al(vec![domain_rule("example.com", DomainScope::Subdomains)]);
        assert!(!a.matches("example.com").is_empty());
        assert!(!a.matches("www.example.com").is_empty());
        assert!(!a.matches("a.b.example.com").is_empty());
        assert!(a.matches("notexample.com").is_empty());
        assert!(a.matches("example.com.evil.test").is_empty());
    }

    #[test]
    fn wildcard_scope_excludes_apex() {
        let a = al(vec![domain_rule("example.com", DomainScope::Wildcard)]);
        assert!(a.matches("example.com").is_empty()); // apex not matched
        assert!(!a.matches("www.example.com").is_empty());
    }

    #[test]
    fn default_deny_for_unlisted() {
        let a = al(vec![domain_rule("allowed.test", DomainScope::Subdomains)]);
        assert!(a.matches("evil.test").is_empty());
        assert!(al(vec![]).matches("anything.test").is_empty());
    }

    /// Rules add up: a second rule for a name or a subdomain must not take away
    /// what an earlier one granted.
    #[test]
    fn every_matching_domain_rule_applies() {
        let a = al(vec![
            domain_rule("example.com", DomainScope::Subdomains),
            domain_rule("example.com", DomainScope::Exact),
            domain_rule("api.example.com", DomainScope::Subdomains),
        ]);
        let names = |q| -> Vec<String> { a.matches(q).iter().map(|r| r.name.clone()).collect() };
        assert_eq!(names("api.example.com"), ["example.com", "api.example.com"]);
        assert_eq!(names("example.com"), ["example.com", "example.com"]);
    }
}
