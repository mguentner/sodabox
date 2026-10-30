//! Per-VM egress allowlist model (ADR-0006).

use serde::{Deserialize, Serialize};

use crate::paths;

/// A VM's declarative, deny-by-default egress policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmPolicy {
    /// Monotonically increasing version so clients can see which policy is live.
    pub version: u32,
    /// Absent in a freshly-created `policy.toml` (`version = 0` only) — an empty
    /// allowlist is the deny-by-default posture, so treat a missing table as `[]`.
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub limits: Limits,
}

/// A single allowlist rule. `ip` is a static permit; `domain` also permits DNS
/// resolution of the name and authorizes its resolved IPs (ADR-0005).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Rule {
    Ip {
        /// IPv4/IPv6 address or CIDR.
        cidr: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ports: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proto: Option<String>,
    },
    Domain {
        name: String,
        #[serde(default)]
        scope: DomainScope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ports: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proto: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainScope {
    /// The name and its subdomains (default).
    #[default]
    Subdomains,
    Exact,
    Wildcard,
}

/// Anti-abuse bounds on the DNS-derived ephemeral egress set (ADR-0005).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// Cap on the number of live ephemeral entries.
    pub max_ephemeral_entries: u32,
    /// Cap on the estimated total in-memory size of the ephemeral set, in bytes.
    /// A second dimension alongside the count cap so a spray of
    /// long allowed names can't balloon host memory even under the count limit.
    /// Defaulted for backward compatibility with older `policy.toml` files
    /// that predate the byte cap.
    #[serde(default = "default_max_ephemeral_bytes")]
    pub max_ephemeral_bytes: u64,
    pub ttl_floor_s: u32,
    pub ttl_cap_s: u32,
}

/// 1 MiB: comfortably above legitimate use (a few dozen entries) but well below
/// what a spray under the 4096-entry count cap could otherwise reach.
fn default_max_ephemeral_bytes() -> u64 {
    1 << 20
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_ephemeral_entries: 4096,
            max_ephemeral_bytes: default_max_ephemeral_bytes(),
            ttl_floor_s: 5,
            ttl_cap_s: 3600,
        }
    }
}

impl VmPolicy {
    /// Load `<data-dir>/<vm>/policy.toml`. A missing file is deny-by-default (an
    /// empty policy), so a freshly-created VM with no rules still starts.
    pub fn load(vm: &str) -> std::io::Result<VmPolicy> {
        let path = paths::data_dir(vm).join("policy.toml");
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VmPolicy::default()),
            Err(e) => Err(e),
        }
    }

    /// Add a static IP/CIDR allow rule. `cidr` and `ports` are
    /// validated with the same parsers the allowlist uses, so a rule that would
    /// fail to compile is rejected here rather than at load. Returns `Ok(false)`
    /// if an identical rule already exists (idempotent add).
    pub fn add_ip(&mut self, cidr: &str, ports: Option<&str>) -> Result<bool, String> {
        // Validate up front (fail-closed: never persist a rule we can't compile).
        crate::allowlist::IpCidr::parse(cidr)?;
        crate::allowlist::PortSpec::parse(ports)?;
        let cidr = cidr.to_string();
        let ports = ports.map(str::to_string);
        let dup = self.rules.iter().any(|r| {
            matches!(r, Rule::Ip { cidr: c, ports: p, proto: None } if *c == cidr && *p == ports)
        });
        if dup {
            return Ok(false);
        }
        self.rules.push(Rule::Ip {
            cidr,
            ports,
            proto: None,
        });
        Ok(true)
    }

    /// Add a domain allow rule (name + resolution + its resolved IPs, ADR-0005).
    /// The name is validated as a hostname and `ports` with the allowlist parser.
    /// Returns `Ok(false)` if an identical (name, scope, ports) rule exists.
    pub fn add_domain(
        &mut self,
        name: &str,
        scope: DomainScope,
        ports: Option<&str>,
    ) -> Result<bool, String> {
        validate_domain(name)?;
        crate::allowlist::PortSpec::parse(ports)?;
        let name = name.to_string();
        let ports = ports.map(str::to_string);
        let dup = self.rules.iter().any(|r| {
            matches!(r, Rule::Domain { name: n, scope: s, ports: p, proto: None }
                if *n == name && *s == scope && *p == ports)
        });
        if dup {
            return Ok(false);
        }
        self.rules.push(Rule::Domain {
            name,
            scope,
            ports,
            proto: None,
        });
        Ok(true)
    }

    /// Remove every rule whose target matches `spec`: an [`Rule::Ip`] whose `cidr`
    /// equals `spec`, or a [`Rule::Domain`] whose `name` equals `spec`
    /// (the `deny` verb). Returns how many rules were removed.
    pub fn remove_matching(&mut self, spec: &str) -> usize {
        let before = self.rules.len();
        self.rules.retain(|r| match r {
            Rule::Ip { cidr, .. } => cidr != spec,
            Rule::Domain { name, .. } => name != spec,
        });
        before - self.rules.len()
    }
}

impl Rule {
    /// Check the rule with the same parsers the allowlist compiles it with,
    /// plus hostname validation for domain rules, so a rule read from a file
    /// (a profile) is rejected up front rather than at policy load.
    pub fn validate(&self) -> Result<(), String> {
        use crate::allowlist::{IpCidr, PortSpec, Proto};
        let (ports, proto) = match self {
            Rule::Ip { cidr, ports, proto } => {
                IpCidr::parse(cidr)?;
                (ports, proto)
            }
            Rule::Domain {
                name, ports, proto, ..
            } => {
                validate_domain(name)?;
                (ports, proto)
            }
        };
        PortSpec::parse(ports.as_deref())?;
        proto.as_deref().map(Proto::parse).transpose()?;
        Ok(())
    }
}

/// Header written into a freshly-created `policy.toml`.
pub const POLICY_HEADER: &str =
    "# sodabox egress policy (deny-by-default). Edit via `soda allow/deny/policy edit`.\n\
     # `version` is managed automatically — it bumps on every change.\n";

/// `policy.toml` as a format-preserving document (ADR-0006, ADR-0015).
///
/// Every edit — `allow`, `deny`, `policy edit`, `profile add`, the version
/// bump — goes through this type and touches only the parts of the file it
/// changes, so comments the user wrote and the `# from profile …` provenance
/// comments on merged rules survive. The document is the source of truth; the
/// enforced [`VmPolicy`] is always parsed back out of it ([`PolicyFile::policy`]).
#[derive(Debug, Clone)]
pub struct PolicyFile {
    doc: toml_edit::DocumentMut,
}

impl PolicyFile {
    /// Parse `policy.toml` text. Fails if it isn't valid TOML or doesn't
    /// deserialize as a [`VmPolicy`], so a held `PolicyFile` always has a
    /// policy view.
    pub fn parse(text: &str) -> Result<PolicyFile, String> {
        let doc: toml_edit::DocumentMut = text.parse().map_err(|e| format!("{e}"))?;
        let file = PolicyFile { doc };
        file.policy()?;
        Ok(file)
    }

    /// A new, empty (deny-by-default) policy at `version = 0`.
    pub fn new() -> PolicyFile {
        PolicyFile::parse(&format!("{POLICY_HEADER}version = 0\n")).expect("static policy parses")
    }

    /// `<data-dir>/<vm>/policy.toml`.
    pub fn path(vm: &str) -> std::path::PathBuf {
        paths::data_dir(vm).join("policy.toml")
    }

    /// Load `vm`'s `policy.toml`; a missing file is a new empty policy, as in
    /// [`VmPolicy::load`].
    pub fn load(vm: &str) -> std::io::Result<PolicyFile> {
        match std::fs::read_to_string(Self::path(vm)) {
            Ok(text) => PolicyFile::parse(&text)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PolicyFile::new()),
            Err(e) => Err(e),
        }
    }

    /// Persist to `<data-dir>/<vm>/policy.toml` (ADR-0006/0008).
    /// Writes to a sibling temp file and renames so a reader never observes a
    /// half-written policy (an empty/truncated file would read as deny-all, but a
    /// syntactically broken one fails the load — atomicity avoids both).
    pub fn save(&self, vm: &str) -> std::io::Result<()> {
        let dir = paths::data_dir(vm);
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join(".policy.toml.tmp");
        std::fs::write(&tmp, self.to_string())?;
        std::fs::rename(&tmp, Self::path(vm))
    }

    /// The policy this document describes.
    pub fn policy(&self) -> Result<VmPolicy, String> {
        toml::from_str(&self.doc.to_string()).map_err(|e| format!("{e}"))
    }

    pub fn version(&self) -> u32 {
        self.policy().map(|p| p.version).unwrap_or(0)
    }

    /// Set `version`, keeping any comment around the existing value.
    pub fn set_version(&mut self, version: u32) {
        let mut v = toml_edit::Value::from(i64::from(version));
        if let Some(old) = self.doc.get("version").and_then(toml_edit::Item::as_value) {
            *v.decor_mut() = old.decor().clone();
        }
        self.doc["version"] = toml_edit::Item::Value(v);
    }

    /// [`VmPolicy::add_ip`], applied to the document.
    pub fn add_ip(&mut self, cidr: &str, ports: Option<&str>) -> Result<bool, String> {
        let mut p = self.policy()?;
        if !p.add_ip(cidr, ports)? {
            return Ok(false);
        }
        self.push_rule(p.rules.last().expect("just pushed"))?;
        Ok(true)
    }

    /// [`VmPolicy::add_domain`], applied to the document.
    pub fn add_domain(
        &mut self,
        name: &str,
        scope: DomainScope,
        ports: Option<&str>,
    ) -> Result<bool, String> {
        let mut p = self.policy()?;
        if !p.add_domain(name, scope, ports)? {
            return Ok(false);
        }
        self.push_rule(p.rules.last().expect("just pushed"))?;
        Ok(true)
    }

    /// [`VmPolicy::remove_matching`], applied to the document: the removed
    /// rules' tables go together with the comments attached to them.
    pub fn remove_matching(&mut self, spec: &str) -> Result<usize, String> {
        let Some(rules) = self.rules_mut() else {
            return Ok(0);
        };
        let mut removed = 0;
        let mut err = None;
        rules.retain(|t| match table_rule(t) {
            Ok(rule) => {
                let target = match &rule {
                    Rule::Ip { cidr, .. } => cidr,
                    Rule::Domain { name, .. } => name,
                };
                let keep = target != spec;
                removed += usize::from(!keep);
                keep
            }
            Err(e) => {
                err.get_or_insert(e);
                true
            }
        });
        match err {
            Some(e) => Err(e),
            None => Ok(removed),
        }
    }

    /// Merge one profile's rules (ADR-0015). A rule the policy already has is
    /// skipped; every other one is copied over as the profile file wrote it,
    /// comments included, with a `# from profile '<name>'` line above it.
    /// Returns how many rules were added.
    pub fn merge_profile(&mut self, profile: &crate::profile::Profile) -> Result<usize, String> {
        let mut existing = self.policy()?.rules;
        let mut added = 0;
        for (rule, table) in profile.entries() {
            if existing.contains(rule) {
                continue;
            }
            let mut table = fresh_table(table);
            let comments = table
                .decor()
                .prefix()
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .trim_start_matches('\n');
            let prefix = format!("\n# from profile '{}'\n{comments}", profile.name());
            table.decor_mut().set_prefix(prefix);
            self.rules_or_insert()?.push(table);
            existing.push(rule.clone());
            added += 1;
        }
        Ok(added)
    }

    /// Append `rule` as a new `[[rules]]` table.
    fn push_rule(&mut self, rule: &Rule) -> Result<(), String> {
        let text = toml::to_string(rule).map_err(|e| format!("{e}"))?;
        let doc: toml_edit::DocumentMut = text.parse().map_err(|e| format!("{e}"))?;
        let mut table = fresh_table(doc.as_table());
        table.decor_mut().set_prefix("\n");
        self.rules_or_insert()?.push(table);
        Ok(())
    }

    /// The `rules` array of tables, if present. An inline `rules = [{…}]` is
    /// converted to `[[rules]]` tables first.
    fn rules_mut(&mut self) -> Option<&mut toml_edit::ArrayOfTables> {
        let item = self.doc.get_mut("rules")?;
        if !item.is_array_of_tables() {
            if let Ok(aot) = std::mem::take(item).into_array_of_tables() {
                *item = toml_edit::Item::ArrayOfTables(aot);
            }
        }
        item.as_array_of_tables_mut()
    }

    fn rules_or_insert(&mut self) -> Result<&mut toml_edit::ArrayOfTables, String> {
        let empty = match self.doc.get("rules") {
            None => true,
            Some(item) => item.as_array().is_some_and(|a| a.is_empty()),
        };
        if empty {
            self.doc["rules"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
        }
        self.rules_mut()
            .ok_or_else(|| "policy.toml: `rules` is not an array of tables".to_string())
    }
}

impl Default for PolicyFile {
    fn default() -> Self {
        PolicyFile::new()
    }
}

impl std::fmt::Display for PolicyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.doc.fmt(f)
    }
}

/// Deserialize one `[[rules]]` table.
pub(crate) fn table_rule(table: &toml_edit::Table) -> Result<Rule, String> {
    toml::from_str(&toml_edit::DocumentMut::from(table.clone()).to_string())
        .map_err(|e| format!("{e}"))
}

/// A copy of `src` (keys, values, their formatting and the table's own
/// comments) with no document position, so toml_edit renders it right after
/// the tables already in the target document — a parsed table's position is
/// relative to the document it came from.
fn fresh_table(src: &toml_edit::Table) -> toml_edit::Table {
    let mut t = toml_edit::Table::new();
    for (key, item) in src.iter() {
        let key = src
            .key(key)
            .cloned()
            .unwrap_or_else(|| toml_edit::Key::new(key));
        t.insert_formatted(&key, item.clone());
    }
    *t.decor_mut() = src.decor().clone();
    t
}

/// Minimal hostname validation for a domain rule: non-empty, at most 253 chars,
/// no scheme/path/whitespace. Deliberately lenient (the DNS filter is the real
/// authority) but rejects obvious mistakes like pasting a URL.
fn validate_domain(name: &str) -> Result<(), String> {
    let n = name.strip_prefix("*.").unwrap_or(name);
    if n.is_empty() || n.len() > 253 {
        return Err(format!("invalid domain '{name}': empty or too long"));
    }
    if n.contains("://") || n.contains('/') {
        return Err(format!(
            "invalid domain '{name}': looks like a URL, not a hostname"
        ));
    }
    if n.chars().any(|c| c.is_whitespace()) {
        return Err(format!("invalid domain '{name}': contains whitespace"));
    }
    if n.starts_with('.') || n.ends_with('.') || n.contains("..") {
        return Err(format!("invalid domain '{name}': malformed label"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_ip_validates_and_dedups() {
        let mut p = VmPolicy::default();
        assert_eq!(p.add_ip("10.0.0.0/8", Some("443")), Ok(true));
        // Identical rule is a no-op.
        assert_eq!(p.add_ip("10.0.0.0/8", Some("443")), Ok(false));
        // Different ports is a distinct rule.
        assert_eq!(p.add_ip("10.0.0.0/8", Some("80")), Ok(true));
        assert_eq!(p.rules.len(), 2);
        // Bad CIDR / bad port are rejected before mutating.
        assert!(p.add_ip("not-a-cidr", None).is_err());
        assert!(p.add_ip("10.0.0.0/8", Some("notaport")).is_err());
        assert_eq!(p.rules.len(), 2);
    }

    #[test]
    fn add_domain_validates_scope_and_url_rejected() {
        let mut p = VmPolicy::default();
        assert_eq!(
            p.add_domain("example.com", DomainScope::Subdomains, None),
            Ok(true)
        );
        // Same name, different scope is distinct.
        assert_eq!(
            p.add_domain("example.com", DomainScope::Exact, None),
            Ok(true)
        );
        assert_eq!(
            p.add_domain("example.com", DomainScope::Exact, None),
            Ok(false)
        );
        assert_eq!(p.rules.len(), 2);
        // A pasted URL is rejected.
        assert!(p
            .add_domain("https://example.com/x", DomainScope::Exact, None)
            .is_err());
        // Wildcard label is allowed.
        assert_eq!(
            p.add_domain("*.example.com", DomainScope::Wildcard, None),
            Ok(true)
        );
    }

    #[test]
    fn remove_matching_counts_ip_and_domain() {
        let mut p = VmPolicy::default();
        p.add_ip("1.2.3.4/32", None).unwrap();
        p.add_domain("example.com", DomainScope::Subdomains, None)
            .unwrap();
        p.add_domain("other.test", DomainScope::Exact, None)
            .unwrap();
        assert_eq!(p.remove_matching("example.com"), 1);
        assert_eq!(p.remove_matching("1.2.3.4/32"), 1);
        // Nothing matches -> zero removed.
        assert_eq!(p.remove_matching("nope.example"), 0);
        assert_eq!(p.rules.len(), 1);
    }

    #[test]
    fn toml_roundtrip_is_stable() {
        // The exact bytes `save()` would write (minus the header comment) must
        // reload to an equal policy — the persisted format is the wire format.
        let mut p = VmPolicy {
            version: 7,
            ..VmPolicy::default()
        };
        p.add_ip("192.0.2.0/24", Some("443")).unwrap();
        p.add_domain("example.com", DomainScope::Wildcard, Some("80,443"))
            .unwrap();
        let body = toml::to_string_pretty(&p).unwrap();
        let back: VmPolicy = toml::from_str(&body).unwrap();
        assert_eq!(back.version, 7);
        assert_eq!(back.rules.len(), 2);
        // Spot-check the domain rule survived with its scope + ports.
        match &back.rules[1] {
            Rule::Domain {
                name, scope, ports, ..
            } => {
                assert_eq!(name, "example.com");
                assert_eq!(*scope, DomainScope::Wildcard);
                assert_eq!(ports.as_deref(), Some("80,443"));
            }
            other => panic!("expected domain rule, got {other:?}"),
        }
    }
}
