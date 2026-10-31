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
    /// The inference gateway's settings (ADR-0020). Configuring it does not
    /// grant access: that takes a `service` rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayConfig>,
    /// Model aliases the gateway resolves (ADR-0020). The aliases are also the
    /// allowlist of models: a name without one is rejected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<ModelAlias>,
}

/// The services sodabox itself offers the guest (ADR-0020). A `service` rule
/// may only name one of these.
pub const SERVICES: &[&str] = &["inference"];

/// `[gateway]` in `policy.toml` (ADR-0020).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    #[serde(default)]
    pub enabled: bool,
    /// `unlimited` turns the quota off for every alias of the VM.
    #[serde(default, skip_serializing_if = "QuotaMode::is_limited")]
    pub quota: QuotaMode,
}

/// Whether token quotas apply (ADR-0020).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaMode {
    #[default]
    Limited,
    Unlimited,
}

impl QuotaMode {
    pub fn is_limited(&self) -> bool {
        *self == QuotaMode::Limited
    }
}

/// One `[[models]]` table: the name the guest uses for a model, and which
/// provider and upstream model it stands for on this VM (ADR-0020).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelAlias {
    /// The name the guest sends as `model`.
    pub alias: String,
    /// A provider file in `$XDG_CONFIG_HOME/sodabox/providers/`.
    pub provider: String,
    /// The model name sent upstream.
    pub model: String,
    /// The balance written to the ledger when the alias is first used
    /// (default 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_quota: Option<u64>,
    /// `unlimited` turns the quota off for this alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<QuotaMode>,
}

impl ModelAlias {
    /// Check the alias the way the gateway will use it.
    pub fn validate(&self) -> Result<(), String> {
        validate_alias(&self.alias)?;
        crate::profile::validate_name(&self.provider)
            .map_err(|e| format!("model '{}': provider: {e}", self.alias))?;
        if self.model.is_empty() || self.model.chars().any(char::is_control) {
            return Err(format!(
                "model '{}': invalid upstream model name",
                self.alias
            ));
        }
        Ok(())
    }
}

/// An alias is what a client puts in `model`, e.g. `foo:13b` or
/// `mistral/large`. It is matched exactly and shown to the guest, so it must
/// be printable, have no whitespace, and be at most 128 bytes.
pub fn validate_alias(alias: &str) -> Result<(), String> {
    if alias.is_empty() || alias.len() > 128 {
        return Err(format!(
            "invalid model alias '{alias}': must be 1–128 bytes"
        ));
    }
    if alias.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "invalid model alias '{alias}': no whitespace or control characters"
        ));
    }
    Ok(())
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
    /// Access to a service sodabox itself offers the guest, e.g. the
    /// inference gateway (ADR-0020). Not an egress permit.
    Service { name: String },
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
        self.rules.retain(|r| r.target() != spec);
        before - self.rules.len()
    }

    /// Add a `service` rule granting the guest access to one of [`SERVICES`].
    /// Returns `Ok(false)` if the VM already has it.
    pub fn add_service(&mut self, name: &str) -> Result<bool, String> {
        let rule = Rule::Service {
            name: name.to_string(),
        };
        rule.validate()?;
        if self.rules.contains(&rule) {
            return Ok(false);
        }
        self.rules.push(rule);
        Ok(true)
    }

    /// Whether a `service` rule grants access to `name`.
    pub fn allows_service(&self, name: &str) -> bool {
        self.rules
            .iter()
            .any(|r| matches!(r, Rule::Service { name: n } if n == name))
    }

    /// The alias table for `alias`, if any.
    pub fn model(&self, alias: &str) -> Option<&ModelAlias> {
        self.models.iter().find(|m| m.alias == alias)
    }

    /// Whether `alias` is metered: false if the gateway or the alias is set to
    /// `unlimited`. The VM-wide setting wins.
    pub fn is_metered(&self, alias: &str) -> bool {
        let vm = self.gateway.as_ref().map(|g| g.quota).unwrap_or_default();
        let own = self.model(alias).and_then(|m| m.quota).unwrap_or_default();
        vm.is_limited() && own.is_limited()
    }

    /// Check every model alias, and that no alias appears twice.
    pub fn validate_models(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for m in &self.models {
            m.validate()?;
            if !seen.insert(m.alias.as_str()) {
                return Err(format!("model alias '{}' is defined twice", m.alias));
            }
        }
        Ok(())
    }
}

/// What [`PolicyFile::set_model`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelChange {
    Added,
    /// The alias existed and now points elsewhere; its balance is kept.
    Repointed,
    Unchanged,
}

impl Rule {
    /// What `soda deny <spec>` matches: the CIDR, domain or service name.
    pub fn target(&self) -> &str {
        match self {
            Rule::Ip { cidr, .. } => cidr,
            Rule::Domain { name, .. } | Rule::Service { name } => name,
        }
    }

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
            Rule::Service { name } => {
                if !SERVICES.contains(&name.as_str()) {
                    return Err(format!(
                        "unknown service '{name}' (known: {})",
                        SERVICES.join(", ")
                    ));
                }
                return Ok(());
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
        file.policy()?.validate_models()?;
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
                let keep = rule.target() != spec;
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

    /// [`VmPolicy::add_service`], applied to the document.
    pub fn add_service(&mut self, name: &str) -> Result<bool, String> {
        let mut p = self.policy()?;
        if !p.add_service(name)? {
            return Ok(false);
        }
        self.push_rule(p.rules.last().expect("just pushed"))?;
        Ok(true)
    }

    /// Switch the gateway on or off in `[gateway]`, creating the table if
    /// needed. Returns `false` if it was already in that state.
    pub fn set_gateway_enabled(&mut self, enabled: bool) -> Result<bool, String> {
        let was = self.policy()?.gateway.is_some_and(|g| g.enabled);
        if was == enabled {
            return Ok(false);
        }
        self.gateway_table()?["enabled"] = toml_edit::value(enabled);
        Ok(true)
    }

    /// Set the quota mode of one alias, or of the whole VM (`alias = None`,
    /// in `[gateway]`). `limited` is the default, so it removes the key.
    /// Returns `false` if nothing changed.
    pub fn set_quota_mode(&mut self, alias: Option<&str>, mode: QuotaMode) -> Result<bool, String> {
        let p = self.policy()?;
        let current = match alias {
            None => p.gateway.as_ref().map(|g| g.quota).unwrap_or_default(),
            Some(a) => p
                .model(a)
                .ok_or_else(|| format!("no model alias '{a}'"))?
                .quota
                .unwrap_or_default(),
        };
        if current == mode {
            return Ok(false);
        }
        let table = match alias {
            None => self.gateway_table()?,
            Some(a) => self.model_table_mut(a)?,
        };
        match mode {
            QuotaMode::Unlimited => table["quota"] = toml_edit::value("unlimited"),
            QuotaMode::Limited => {
                table.remove("quota");
            }
        }
        Ok(true)
    }

    /// Add a model alias, or re-point an existing one to `provider`/`model`.
    /// Re-pointing keeps the alias's other settings, and its balance lives on
    /// in the ledger (ADR-0020). `initial_quota` applies only when adding.
    pub fn set_model(
        &mut self,
        alias: &str,
        provider: &str,
        model: &str,
        initial_quota: Option<u64>,
    ) -> Result<ModelChange, String> {
        let new = ModelAlias {
            alias: alias.to_string(),
            provider: provider.to_string(),
            model: model.to_string(),
            initial_quota,
            quota: None,
        };
        new.validate()?;
        let p = self.policy()?;
        if let Some(old) = p.model(alias) {
            if old.provider == provider && old.model == model {
                return Ok(ModelChange::Unchanged);
            }
            let table = self.model_table_mut(alias)?;
            table["provider"] = toml_edit::value(provider);
            table["model"] = toml_edit::value(model);
            return Ok(ModelChange::Repointed);
        }
        let text = toml::to_string(&new).map_err(|e| format!("{e}"))?;
        let doc: toml_edit::DocumentMut = text.parse().map_err(|e| format!("{e}"))?;
        let mut table = fresh_table(doc.as_table());
        table.decor_mut().set_prefix("\n");
        self.aot_or_insert("models")?.push(table);
        Ok(ModelChange::Added)
    }

    /// Remove a model alias together with its comments. Its ledger history is
    /// kept, so adding the alias back continues from the old balance.
    /// Returns `false` if there was no such alias.
    pub fn remove_model(&mut self, alias: &str) -> Result<bool, String> {
        let Some(models) = self.aot_mut("models") else {
            return Ok(false);
        };
        let before = models.len();
        models.retain(|t| t.get("alias").and_then(|v| v.as_str()) != Some(alias));
        Ok(models.len() != before)
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

    /// The `[gateway]` table, created if missing.
    fn gateway_table(&mut self) -> Result<&mut toml_edit::Table, String> {
        let item = self
            .doc
            .entry("gateway")
            .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
        item.as_table_mut()
            .ok_or_else(|| "policy.toml: `gateway` is not a table".to_string())
    }

    /// The `[[models]]` table for `alias`.
    fn model_table_mut(&mut self, alias: &str) -> Result<&mut toml_edit::Table, String> {
        self.aot_mut("models")
            .and_then(|m| {
                m.iter_mut()
                    .find(|t| t.get("alias").and_then(|v| v.as_str()) == Some(alias))
            })
            .ok_or_else(|| format!("no model alias '{alias}'"))
    }

    /// The `rules` array of tables, if present.
    fn rules_mut(&mut self) -> Option<&mut toml_edit::ArrayOfTables> {
        self.aot_mut("rules")
    }

    fn rules_or_insert(&mut self) -> Result<&mut toml_edit::ArrayOfTables, String> {
        self.aot_or_insert("rules")
    }

    /// The array of tables at `key`, if present. An inline `key = [{…}]` is
    /// converted to `[[key]]` tables first.
    fn aot_mut(&mut self, key: &str) -> Option<&mut toml_edit::ArrayOfTables> {
        let item = self.doc.get_mut(key)?;
        if !item.is_array_of_tables() {
            if let Ok(aot) = std::mem::take(item).into_array_of_tables() {
                *item = toml_edit::Item::ArrayOfTables(aot);
            }
        }
        item.as_array_of_tables_mut()
    }

    fn aot_or_insert(&mut self, key: &str) -> Result<&mut toml_edit::ArrayOfTables, String> {
        let empty = match self.doc.get(key) {
            None => true,
            Some(item) => item.as_array().is_some_and(|a| a.is_empty()),
        };
        if empty {
            self.doc[key] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
        }
        self.aot_mut(key)
            .ok_or_else(|| format!("policy.toml: `{key}` is not an array of tables"))
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

    const GATEWAY_POLICY: &str = r#"version = 3

# my notes on the gateway
[gateway]
enabled = true

[[rules]]
kind = "service"
name = "inference"

# a cheap local model
[[models]]
alias = "foo:13b"
provider = "local"
model = "the_actual_foo:13b"
initial_quota = 1000
"#;

    #[test]
    fn gateway_and_models_load_and_old_files_still_parse() {
        let p: VmPolicy = toml::from_str(GATEWAY_POLICY).unwrap();
        assert!(p.gateway.as_ref().unwrap().enabled);
        assert!(p.allows_service("inference"));
        assert_eq!(p.model("foo:13b").unwrap().initial_quota, Some(1000));
        assert!(p.is_metered("foo:13b"));
        // A pre-gateway policy has neither.
        let old: VmPolicy = toml::from_str("version = 1\n").unwrap();
        assert!(old.gateway.is_none() && old.models.is_empty());
        assert!(!old.allows_service("inference"));
    }

    #[test]
    fn only_known_services_and_valid_aliases_are_accepted() {
        let mut p = VmPolicy::default();
        assert_eq!(p.add_service("inference"), Ok(true));
        assert_eq!(p.add_service("inference"), Ok(false));
        assert!(p.add_service("ssh").is_err());
        assert!(validate_alias("foo:13b").is_ok());
        assert!(validate_alias("mistral/large-latest").is_ok());
        assert!(validate_alias("").is_err());
        assert!(validate_alias("a b").is_err());
        let dup = format!(
            "{GATEWAY_POLICY}\n[[models]]\nalias = \"foo:13b\"\nprovider = \"x\"\nmodel = \"y\"\n"
        );
        assert!(PolicyFile::parse(&dup).is_err());
        let bad_provider =
            "version = 1\n[[models]]\nalias = \"a\"\nprovider = \"../x\"\nmodel = \"y\"\n";
        assert!(PolicyFile::parse(bad_provider).is_err());
    }

    #[test]
    fn unlimited_vm_wins_over_the_alias() {
        let mut p: VmPolicy = toml::from_str(GATEWAY_POLICY).unwrap();
        p.models[0].quota = Some(QuotaMode::Unlimited);
        assert!(!p.is_metered("foo:13b"));
        p.models[0].quota = None;
        p.gateway.as_mut().unwrap().quota = QuotaMode::Unlimited;
        assert!(!p.is_metered("foo:13b"));
    }

    #[test]
    fn model_edits_keep_comments_and_repoint_in_place() {
        let mut f = PolicyFile::parse(GATEWAY_POLICY).unwrap();
        assert_eq!(
            f.set_model("foo:13b", "local", "the_actual_foo:13b", None),
            Ok(ModelChange::Unchanged)
        );
        assert_eq!(
            f.set_model("foo:13b", "openrouter", "foo-13b", None),
            Ok(ModelChange::Repointed)
        );
        assert_eq!(
            f.set_model("big", "mistral", "mistral-large-latest", Some(5)),
            Ok(ModelChange::Added)
        );
        let text = f.to_string();
        assert!(text.contains("# my notes on the gateway"));
        assert!(text.contains("# a cheap local model"));
        let p = f.policy().unwrap();
        let foo = p.model("foo:13b").unwrap();
        assert_eq!(
            (foo.provider.as_str(), foo.model.as_str()),
            ("openrouter", "foo-13b")
        );
        // Re-pointing keeps the alias's other settings.
        assert_eq!(foo.initial_quota, Some(1000));
        assert_eq!(p.model("big").unwrap().initial_quota, Some(5));

        assert_eq!(f.remove_model("foo:13b"), Ok(true));
        assert_eq!(f.remove_model("foo:13b"), Ok(false));
        assert!(!f.to_string().contains("# a cheap local model"));
    }

    #[test]
    fn quota_mode_and_enable_edits() {
        let mut f = PolicyFile::new();
        assert_eq!(f.set_gateway_enabled(true), Ok(true));
        assert_eq!(f.set_gateway_enabled(true), Ok(false));
        assert!(f
            .set_quota_mode(Some("nope"), QuotaMode::Unlimited)
            .is_err());
        f.set_model("foo", "local", "foo", None).unwrap();
        assert_eq!(
            f.set_quota_mode(Some("foo"), QuotaMode::Unlimited),
            Ok(true)
        );
        assert!(!f.policy().unwrap().is_metered("foo"));
        assert_eq!(f.set_quota_mode(Some("foo"), QuotaMode::Limited), Ok(true));
        assert!(!f.to_string().contains("quota"));
        assert_eq!(f.set_quota_mode(None, QuotaMode::Unlimited), Ok(true));
        assert!(!f.policy().unwrap().is_metered("foo"));
        assert_eq!(f.add_service("inference"), Ok(true));
        // The edited document still parses as a policy.
        PolicyFile::parse(&f.to_string()).unwrap();
    }

    #[test]
    fn deny_removes_a_service_rule() {
        let mut f = PolicyFile::parse(GATEWAY_POLICY).unwrap();
        assert_eq!(f.remove_matching("inference"), Ok(1));
        assert!(!f.policy().unwrap().allows_service("inference"));
    }
}
