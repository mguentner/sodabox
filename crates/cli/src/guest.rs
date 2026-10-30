//! Materializing the user-owned guest input (ADR-0012).
//!
//! sodabox ships a default guest input (`configuration.nix` + npins-pinned
//! `nixpkgs`) embedded in the binary and writes it into the config dir on first
//! `create`, if absent. The user then owns and edits it — sodabox never
//! clobbers it, and `npins update` in that dir bumps `nixpkgs`.

use std::fs;
use std::io;
use std::path::PathBuf;

use sodabox_common::paths;

// The shipped default, embedded from the repo's `guest-default/`.
const DEFAULT_CONFIGURATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../guest-default/configuration.nix"
));
const DEFAULT_NPINS_SOURCES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../guest-default/npins/sources.json"
));
const DEFAULT_NPINS_DEFAULT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../guest-default/npins/default.nix"
));

/// Write the default guest input into the shared config dir if it is not there
/// yet. Returns `(created, dir)`; `created == false` means the user's existing
/// input was left untouched.
pub fn ensure_default_guest_input() -> io::Result<(bool, PathBuf)> {
    let dir = paths::shared_guest_dir();
    let configuration = dir.join("configuration.nix");
    if configuration.is_file() {
        return Ok((false, dir));
    }
    fs::create_dir_all(dir.join("npins"))?;
    fs::write(&configuration, DEFAULT_CONFIGURATION)?;
    fs::write(
        dir.join("npins").join("sources.json"),
        DEFAULT_NPINS_SOURCES,
    )?;
    fs::write(dir.join("npins").join("default.nix"), DEFAULT_NPINS_DEFAULT)?;
    Ok((true, dir))
}

/// The per-VM layer, embedded from the repo's `guest-default/vm/`. Its
/// `@HOSTNAME@` placeholder is filled in by [`render_vm_configuration`].
const VM_CONFIGURATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../guest-default/vm/configuration.nix"
));

/// base.nix's built-in hostname, which `--hostname static` keeps.
pub const STATIC_HOSTNAME: &str = "sodabox-guest";

/// How `create` picks the guest hostname written into the per-VM layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HostnameMode {
    /// The VM name, lowercased with anything outside `[a-z0-9-]` mapped to `-`.
    Name,
    /// Always `sodabox-guest`, the same in every VM.
    Static,
    /// `s` plus 8 random `[a-z0-9]` characters, fixed once at create.
    Random,
}

/// Resolve `mode` to a concrete hostname for VM `vm`. Each result is a single
/// RFC 1123 label, which is also what NixOS's `networking.hostName` accepts.
pub fn resolve_hostname(mode: HostnameMode, vm: &str) -> anyhow::Result<String> {
    match mode {
        HostnameMode::Name => hostname_from_name(vm).ok_or_else(|| {
            anyhow::anyhow!(
                "VM name '{vm}' doesn't make a valid hostname — pass --hostname static or --hostname random"
            )
        }),
        HostnameMode::Static => Ok(STATIC_HOSTNAME.to_string()),
        HostnameMode::Random => {
            let mut bytes = [0u8; 8];
            io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut bytes)?;
            Ok(random_hostname(&bytes))
        }
    }
}

/// `vm` as a hostname label: lowercased, every char outside `[a-z0-9-]` becomes
/// `-`, leading/trailing `-` trimmed, capped at 63 chars. `None` when nothing
/// usable is left. Pure.
fn hostname_from_name(vm: &str) -> Option<String> {
    let mapped: String = vm
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let label: String = mapped.trim_matches('-').chars().take(63).collect();
    let label = label.trim_end_matches('-');
    (!label.is_empty()).then(|| label.to_string())
}

/// `s` + one `[a-z0-9]` char per input byte. The leading letter keeps it from
/// ever being all digits. Pure; [`resolve_hostname`] feeds it /dev/urandom.
fn random_hostname(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    // 256 % 36 != 0, so this has a slight modulo bias. That's fine here: it only
    // has to tell VMs apart, not be secret.
    let tail: String = bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    format!("s{tail}")
}

/// The per-VM `configuration.nix` for `hostname`. Pure.
fn render_vm_configuration(hostname: &str) -> String {
    VM_CONFIGURATION.replace("@HOSTNAME@", hostname)
}

/// Write VM `vm`'s own guest layer (`<config-dir>/<vm>/guest/`) if absent: a
/// `configuration.nix` that imports the shared one and sets the hostname, plus
/// an `npins` symlink to the shared pins so `npins update` there still moves
/// every VM. `hostname` is resolved only when the file is actually written,
/// which keeps a re-`create` from rolling a new random name. Returns
/// `(created, dir)`; an existing layer is left untouched, like the shared one.
pub fn ensure_vm_guest_input(
    vm: &str,
    hostname: impl FnOnce() -> anyhow::Result<String>,
) -> anyhow::Result<(bool, PathBuf)> {
    let dir = paths::vm_guest_override_dir(vm);
    let configuration = dir.join("configuration.nix");
    if configuration.is_file() {
        return Ok((false, dir));
    }
    let hostname = hostname()?;
    fs::create_dir_all(&dir)?;
    let npins = dir.join("npins");
    if fs::symlink_metadata(&npins).is_err() {
        // Relative, matching the template's `../../guest/configuration.nix`, so
        // moving the whole config dir keeps working.
        std::os::unix::fs::symlink("../../guest/npins", &npins)?;
    }
    fs::write(&configuration, render_vm_configuration(&hostname))?;
    Ok((true, dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_from_name_sanitizes_to_one_label() {
        assert_eq!(hostname_from_name("thebox").as_deref(), Some("thebox"));
        assert_eq!(
            hostname_from_name("My_Box.dev").as_deref(),
            Some("my-box-dev")
        );
        assert_eq!(hostname_from_name("-edge-").as_deref(), Some("edge"));
        assert_eq!(hostname_from_name("___"), None);
        assert_eq!(hostname_from_name(""), None);
        // Capped at 63, without leaving a dangling '-' at the cut.
        let long = format!("{}-b", "a".repeat(62));
        assert_eq!(hostname_from_name(&long).unwrap(), "a".repeat(62));
    }

    #[test]
    fn random_hostname_is_s_plus_lowercase_alnum() {
        let h = random_hostname(&[0, 25, 26, 35, 36, 255, 100, 7]);
        assert_eq!(h, "saz09ad2h");
        assert!(h
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn resolve_hostname_modes() {
        assert_eq!(
            resolve_hostname(HostnameMode::Name, "thebox").unwrap(),
            "thebox"
        );
        assert_eq!(
            resolve_hostname(HostnameMode::Static, "thebox").unwrap(),
            STATIC_HOSTNAME
        );
        let r = resolve_hostname(HostnameMode::Random, "thebox").unwrap();
        assert_eq!(r.len(), 9);
        assert!(r.starts_with('s'));
        assert!(resolve_hostname(HostnameMode::Name, "___").is_err());
    }

    #[test]
    fn vm_configuration_imports_shared_and_sets_hostname() {
        let c = render_vm_configuration("thebox");
        assert!(
            c.contains("imports = [ ../../guest/configuration.nix ];"),
            "{c}"
        );
        assert!(c.contains("networking.hostName = \"thebox\";"), "{c}");
        assert!(!c.contains("@HOSTNAME@"));
    }
}
