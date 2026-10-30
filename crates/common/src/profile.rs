//! Policy profiles (ADR-0015): named, reusable sets of allow rules — e.g. the
//! endpoints one coding agent needs — merged into a VM's `policy.toml`.
//!
//! A profile is a TOML file in [`paths::profiles_dir`] with an optional
//! `description` and the same `[[rules]]` tables as `policy.toml`. It has no
//! `version` or `limits`; those belong to the VM. Merging copies the rules into
//! the VM's policy, so a VM's policy is a snapshot: changing a profile later
//! does not change VMs it was already applied to.

use serde::Deserialize;

use crate::paths;
use crate::policy::{table_rule, Rule};

/// What a profile file may contain. `deny_unknown_fields` so a `version` or
/// `limits` table (or a typo) is an error instead of being silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileSpec {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    rules: Vec<Rule>,
}

/// A loaded, validated profile: each rule together with the table it was
/// written as, so merging can carry the profile's comments into the policy.
#[derive(Debug, Clone)]
pub struct Profile {
    name: String,
    description: Option<String>,
    entries: Vec<(Rule, toml_edit::Table)>,
}

impl Profile {
    /// Parse and validate a profile named `name` from `text`. Every rule must
    /// pass [`Rule::validate`]; one bad rule rejects the whole profile.
    pub fn parse(name: &str, text: &str) -> Result<Profile, String> {
        validate_name(name)?;
        let spec: ProfileSpec =
            toml::from_str(text).map_err(|e| format!("profile '{name}': {e}"))?;
        let doc: toml_edit::DocumentMut =
            text.parse().map_err(|e| format!("profile '{name}': {e}"))?;
        let tables: Vec<toml_edit::Table> = match doc.get("rules").cloned() {
            None => Vec::new(),
            Some(item) => match item.into_array_of_tables() {
                Ok(aot) => aot.iter().cloned().collect(),
                // An empty inline `rules = []`.
                Err(_) => Vec::new(),
            },
        };
        if tables.len() != spec.rules.len() {
            return Err(format!(
                "profile '{name}': could not read `rules` as tables"
            ));
        }
        let mut entries = Vec::with_capacity(tables.len());
        for (i, (rule, table)) in spec.rules.into_iter().zip(tables).enumerate() {
            rule.validate()
                .map_err(|e| format!("profile '{name}', rule {}: {e}", i + 1))?;
            debug_assert_eq!(table_rule(&table).as_ref(), Ok(&rule));
            entries.push((rule, table));
        }
        Ok(Profile {
            name: name.to_string(),
            description: spec.description,
            entries,
        })
    }

    /// Load `<profiles-dir>/<name>.toml`.
    pub fn load(name: &str) -> Result<Profile, String> {
        validate_name(name)?;
        let path = paths::profile_path(name);
        let text = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                format!("no such profile '{name}' (see `sodabox profile ls`)")
            }
            _ => format!("reading {}: {e}", path.display()),
        })?;
        Profile::parse(name, &text)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.entries.iter().map(|(r, _)| r)
    }

    /// Each rule with the table it was written as.
    pub fn entries(&self) -> impl Iterator<Item = (&Rule, &toml_edit::Table)> {
        self.entries.iter().map(|(r, t)| (r, t))
    }
}

/// A profile name: `[a-z0-9][a-z0-9_-]*`, at most 64 chars. It becomes a file
/// name, so this is also what keeps `--profiles ../x` out of other dirs.
pub fn validate_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid profile name '{name}': use lowercase letters, digits, '-' and '_'"
        ))
    }
}

/// Names of the profiles in [`paths::profiles_dir`], sorted. Files whose stem
/// isn't a valid profile name are skipped; a missing dir is an empty list.
pub fn list() -> std::io::Result<Vec<String>> {
    let entries = match std::fs::read_dir(paths::profiles_dir()) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut names = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") || !path.is_file() {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            if validate_name(stem).is_ok() {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DomainScope, PolicyFile};

    const CLAUDE: &str = r#"# vendor header
description = "test"

# the API
[[rules]]
kind = "domain"
name = "api.anthropic.com"
scope = "exact"
ports = "443" # https only

[[rules]]
kind = "domain"
name = "claude.ai"
scope = "exact"
ports = "443"
"#;

    const OTHER: &str = r#"
[[rules]]
kind = "domain"
name = "claude.ai"
scope = "exact"
ports = "443"

[[rules]]
kind = "ip"
cidr = "10.1.0.0/16"
"#;

    #[test]
    fn names_are_restricted() {
        for ok in ["claudecode", "my-lab_2", "0x"] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "../x",
            "a/b",
            "Claude",
            "-x",
            "_x",
            "a.b",
            "a b",
            &"x".repeat(65),
        ] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parse_keeps_rules_and_description() {
        let p = Profile::parse("claudecode", CLAUDE).unwrap();
        assert_eq!(p.description(), Some("test"));
        assert_eq!(p.rules().count(), 2);
        assert!(Profile::parse("empty", "description = \"x\"\n")
            .unwrap()
            .rules()
            .next()
            .is_none());
        assert!(Profile::parse("empty", "rules = []\n")
            .unwrap()
            .rules()
            .next()
            .is_none());
    }

    #[test]
    fn version_limits_and_unknown_keys_are_rejected() {
        assert!(Profile::parse("x", "version = 1\n").is_err());
        assert!(Profile::parse(
            "x",
            "[limits]\nmax_ephemeral_entries = 1\nttl_floor_s = 1\nttl_cap_s = 1\n"
        )
        .is_err());
        assert!(Profile::parse("x", "descripton = \"typo\"\n").is_err());
    }

    #[test]
    fn one_bad_rule_rejects_the_profile() {
        let bad = "[[rules]]\nkind = \"domain\"\nname = \"https://x.test/\"\n";
        let e = Profile::parse("x", bad).unwrap_err();
        assert!(e.contains("rule 1"), "{e}");
        assert!(Profile::parse("x", "[[rules]]\nkind = \"ip\"\ncidr = \"nope\"\n").is_err());
        assert!(Profile::parse(
            "x",
            "[[rules]]\nkind = \"ip\"\ncidr = \"1.2.3.4\"\nproto = \"icmp\"\n"
        )
        .is_err());
    }

    #[test]
    fn merge_dedups_and_writes_provenance_comments() {
        let mut f = PolicyFile::new();
        let a = Profile::parse("claudecode", CLAUDE).unwrap();
        let b = Profile::parse("other", OTHER).unwrap();
        assert_eq!(f.merge_profile(&a).unwrap(), 2);
        // claude.ai is already there from claudecode, so only the IP is new.
        assert_eq!(f.merge_profile(&b).unwrap(), 1);
        // Merging again changes nothing.
        assert_eq!(f.merge_profile(&a).unwrap(), 0);

        let rules = f.policy().unwrap().rules;
        assert_eq!(rules.len(), 3);
        assert!(matches!(&rules[2], Rule::Ip { cidr, .. } if cidr == "10.1.0.0/16"));

        let text = f.to_string();
        assert_eq!(
            text.matches("# from profile 'claudecode'").count(),
            2,
            "{text}"
        );
        assert_eq!(text.matches("# from profile 'other'").count(), 1, "{text}");
        // The profile's own comments come along.
        assert!(text.contains("# the API\n[[rules]]"), "{text}");
        assert!(text.contains("# https only"), "{text}");
        // The profile's file header stays with the profile.
        assert!(!text.contains("vendor header"), "{text}");
        // And the text reparses to the same policy.
        assert_eq!(
            PolicyFile::parse(&text).unwrap().policy().unwrap().rules,
            rules
        );
    }

    #[test]
    fn edits_keep_comments() {
        let mut f = PolicyFile::new();
        f.merge_profile(&Profile::parse("claudecode", CLAUDE).unwrap())
            .unwrap();
        let mut text = f.to_string();
        text.push_str(
            "\n# hand-written note\n[[rules]]\nkind = \"ip\"\ncidr = \"192.0.2.1\" # lab box\n",
        );
        text = text.replace("version = 0", "version = 0 # keep me");
        let mut f = PolicyFile::parse(&text).unwrap();

        assert!(f
            .add_domain("example.com", DomainScope::Subdomains, None)
            .unwrap());
        assert!(!f
            .add_domain("example.com", DomainScope::Subdomains, None)
            .unwrap());
        assert_eq!(f.remove_matching("claude.ai").unwrap(), 1);
        f.set_version(7);

        let out = f.to_string();
        assert!(out.starts_with("# sodabox egress policy"), "{out}");
        assert!(out.contains("version = 7 # keep me"), "{out}");
        assert!(
            out.contains("# from profile 'claudecode'\n# the API"),
            "{out}"
        );
        assert!(out.contains("# hand-written note"), "{out}");
        assert!(out.contains("# lab box"), "{out}");
        // The removed rule took its provenance comment with it.
        assert_eq!(out.matches("# from profile").count(), 1, "{out}");
        let p = f.policy().unwrap();
        assert_eq!(p.version, 7);
        assert_eq!(p.rules.len(), 3);
        assert!(matches!(&p.rules[2], Rule::Domain { name, .. } if name == "example.com"));
    }

    #[test]
    fn inline_rules_array_is_editable() {
        let mut f =
            PolicyFile::parse("version = 1\nrules = [{ kind = \"ip\", cidr = \"10.0.0.0/8\" }]\n")
                .unwrap();
        assert!(f.add_ip("192.0.2.0/24", None).unwrap());
        assert_eq!(f.remove_matching("10.0.0.0/8").unwrap(), 1);
        let rules = f.policy().unwrap().rules;
        assert_eq!(rules.len(), 1);
        let mut f = PolicyFile::parse("version = 1\nrules = []\n").unwrap();
        assert!(f.add_ip("192.0.2.0/24", None).unwrap());
        assert_eq!(f.policy().unwrap().rules.len(), 1);
    }

    #[test]
    fn rules_land_before_a_later_limits_table() {
        let text = "version = 1\n\n[[rules]]\nkind = \"ip\"\ncidr = \"10.0.0.0/8\"\n\n[limits]\nmax_ephemeral_entries = 10\nttl_floor_s = 5\nttl_cap_s = 60\n";
        let mut f = PolicyFile::parse(text).unwrap();
        f.merge_profile(&Profile::parse("other", OTHER).unwrap())
            .unwrap();
        let out = f.to_string();
        assert!(
            out.find("10.1.0.0/16").unwrap() < out.find("[limits]").unwrap(),
            "{out}"
        );
        assert_eq!(f.policy().unwrap().limits.max_ephemeral_entries, 10);
    }
}
