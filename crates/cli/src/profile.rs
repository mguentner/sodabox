//! Vendor policy profiles and the `sodabox profile` verbs (ADR-0015).
//!
//! sodabox ships a few profiles embedded in the binary and keeps them current
//! in the profiles dir: unlike the guest input (ADR-0012), a vendor profile is
//! sodabox's file, rewritten whenever it differs from the shipped copy. Users
//! customise by copying one to a new name; every other file there is theirs.

use std::fs;
use std::io;

use sodabox_common::paths;
use sodabox_common::profile::{self, Profile};

/// The shipped profiles, embedded from the repo's `profiles/`.
const VENDOR: &[(&str, &str)] = &[
    (
        "claudecode",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/claudecode.toml"
        )),
    ),
    (
        "github",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/github.toml"
        )),
    ),
    (
        "mistral",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/mistral.toml"
        )),
    ),
    (
        "nixpkgs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/nixpkgs.toml"
        )),
    ),
    (
        "openai",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/openai.toml"
        )),
    ),
];

pub fn is_vendor(name: &str) -> bool {
    VENDOR.iter().any(|(n, _)| *n == name)
}

/// Write every vendor profile whose file is missing or differs from the shipped
/// copy, atomically. An overwritten file is reported, since that discards
/// whatever was changed in it.
pub fn sync_vendor() -> io::Result<()> {
    let dir = paths::profiles_dir();
    fs::create_dir_all(&dir)?;
    for (name, text) in VENDOR {
        let path = paths::profile_path(name);
        let existed = match fs::read_to_string(&path) {
            Ok(cur) if cur == *text => continue,
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(e),
        };
        let tmp = dir.join(format!(".{name}.toml.tmp"));
        fs::write(&tmp, text)?;
        fs::rename(&tmp, &path)?;
        if existed {
            eprintln!(
                "sodabox: updated vendor profile '{name}' at {} (local changes discarded; \
                 copy it to a new name to customise)",
                path.display()
            );
        }
    }
    Ok(())
}

/// Sync the vendor profiles, then load each of `names` in order. Any error —
/// unknown name, invalid rule — fails the lot, so callers can resolve profiles
/// before making changes.
pub fn load_all(names: &[String]) -> anyhow::Result<Vec<Profile>> {
    sync_vendor().map_err(|e| anyhow::anyhow!("installing vendor profiles: {e}"))?;
    names
        .iter()
        .map(|n| Profile::load(n).map_err(|e| anyhow::anyhow!(e)))
        .collect()
}

/// `sodabox profile ls`.
pub fn ls() -> anyhow::Result<()> {
    sync_vendor()?;
    let names = profile::list()?;
    println!("{:<20} {:<7} DESCRIPTION", "NAME", "SOURCE");
    for name in names {
        let source = if is_vendor(&name) { "vendor" } else { "user" };
        let desc = match Profile::load(&name) {
            Ok(p) => p.description().unwrap_or("").to_string(),
            Err(e) => format!("(invalid: {e})"),
        };
        println!("{name:<20} {source:<7} {desc}");
    }
    println!("\nprofiles dir: {}", paths::profiles_dir().display());
    Ok(())
}

/// `sodabox profile show <name>` — the file as written, comments included.
pub fn show(name: &str) -> anyhow::Result<()> {
    sync_vendor()?;
    let p = Profile::load(name).map_err(|e| anyhow::anyhow!(e))?;
    let path = paths::profile_path(p.name());
    print!("{}", fs::read_to_string(&path)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_profiles_are_valid() {
        for (name, text) in VENDOR {
            let p = Profile::parse(name, text).unwrap_or_else(|e| panic!("{e}"));
            assert!(p.description().is_some(), "{name} has no description");
            assert!(p.rules().next().is_some(), "{name} has no rules");
            assert!(
                text.contains("MANAGED BY SODABOX"),
                "{name} lacks the managed-file warning"
            );
        }
    }
}
