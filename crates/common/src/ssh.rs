//! Tool-owned SSH identity (ADR-0011).
//!
//! sodabox owns a single ed25519 keypair whose *public* half is injected into
//! every guest's `authorized_keys` at launch, so `sodabox ssh` and sync work out
//! of the box. The private half lives only on the host (mode 0600) and is never
//! mounted into a VM. Key material is generated on demand with the system
//! `ssh-keygen` (shelling out, per ADR-0011's "reuse the OpenSSH tooling").

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::paths;

/// Environment override for the `ssh-keygen` binary (pinned on PATH by the
/// packaging wrapper, ADR-0010). Defaults to `ssh-keygen`.
const SSH_KEYGEN_ENV: &str = "SODABOX_SSH_KEYGEN";
/// Environment override for the `ssh` binary (pinned on PATH by the packaging
/// wrapper, ADR-0010). Defaults to `ssh`.
const SSH_ENV: &str = "SODABOX_SSH";

fn ssh_keygen_bin() -> OsString {
    std::env::var_os(SSH_KEYGEN_ENV).unwrap_or_else(|| "ssh-keygen".into())
}

/// The `ssh` binary to drive (`$SODABOX_SSH` or `ssh`).
pub fn ssh_bin() -> OsString {
    std::env::var_os(SSH_ENV).unwrap_or_else(|| "ssh".into())
}

/// Environment override for the `scp` binary (pinned on PATH by the packaging
/// wrapper, ADR-0010). Defaults to `scp`.
const SCP_ENV: &str = "SODABOX_SCP";

/// The `scp` binary to drive (`$SODABOX_SCP` or `scp`).
pub fn scp_bin() -> OsString {
    std::env::var_os(SCP_ENV).unwrap_or_else(|| "scp".into())
}

/// Environment override for the `rsync` binary (pinned on PATH by the packaging
/// wrapper, ADR-0010). Defaults to `rsync`.
const RSYNC_ENV: &str = "SODABOX_RSYNC";

/// The `rsync` binary to drive (`$SODABOX_RSYNC` or `rsync`).
pub fn rsync_bin() -> OsString {
    std::env::var_os(RSYNC_ENV).unwrap_or_else(|| "rsync".into())
}

/// The value for rsync's `-e` (remote-shell) flag: the `ssh` binary plus the
/// shared hardened options (ADR-0011), so sync authenticates exactly like
/// `sodabox ssh`. rsync word-splits `-e` on whitespace without shell quoting, so
/// this relies on the tool key path (under `$XDG_DATA_HOME/sodabox`) containing
/// no spaces — which sodabox controls.
pub fn ssh_rsh_command(vm: &str) -> String {
    let mut parts = vec![ssh_bin().to_string_lossy().into_owned()];
    parts.extend(
        hardened_ssh_opts(vm)
            .iter()
            .map(|o| o.to_string_lossy().into_owned()),
    );
    parts.join(" ")
}

/// A stable ssh host-key alias for VM `vm`, so the pinned known_hosts entry is
/// keyed by the VM rather than by the host:port of its forward (which is stable
/// per VM, but can still be reassigned if an outside process holds it).
pub fn host_key_alias(vm: &str) -> String {
    format!("sodabox-{vm}")
}

/// Per-VM pinned known_hosts file (`<data-dir>/<vm>/known_hosts`); ssh records
/// and verifies the guest host key here (TOFU).
pub fn known_hosts_path(vm: &str) -> PathBuf {
    paths::data_dir(vm).join("known_hosts")
}

/// The single, hardened, pinned-identity SSH option set for VM `vm` (ADR-0011),
/// shared verbatim by `sodabox ssh` and `sync` so both authenticate and verify
/// identically. These are only the `-F`/`-o`/`-i` flags; the caller adds the
/// `ssh` binary, `-p <port>`, the `user@host`, and any remote command (sync
/// splices them into rsync's `-e`).
///
/// `-F /dev/null` ignores the user's ssh config; `IdentitiesOnly=yes` +
/// `IdentityAgent=none` pin authentication to *only* the tool key and never
/// contact an agent — one deterministic auth attempt, and a gpg/ssh agent can't
/// stall or prompt.
///
/// **Host-key verification (TOFU):** `StrictHostKeyChecking=accept-new`
/// records the guest's host key in the per-VM [`known_hosts_path`] on the first
/// connection and *verifies* it on every later one — a **changed** key is
/// refused. `HostKeyAlias` keys the entry by the VM name so the forward's
/// host:port can't defeat the pin, and `GlobalKnownHostsFile=/dev/null`
/// ignores the system file. This relies on the guest persisting its host key on
/// its home disk (`/persistent/home/sodabox`, nix/guest/base.nix); without that
/// the key would change every boot and be refused. A `persist = "none"` VM has no
/// such disk, so its key is host-held and pre-pinned ([`pinned_guest_host_key`]).
pub fn hardened_ssh_opts(vm: &str) -> Vec<OsString> {
    vec![
        "-F".into(),
        "/dev/null".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts_path(vm).display()).into(),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        format!("HostKeyAlias={}", host_key_alias(vm)).into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "IdentityAgent=none".into(),
        "-i".into(),
        tool_key_path().into_os_string(),
    ]
}

/// First host-loopback port of the SSH-forward range (ADR-0011). Above
/// the crowded 2000–3000 band, where the old base of `2222` invited collisions
/// with other local SSH forwards.
pub const HOST_SSH_BASE_PORT: u16 = 3522;

/// How many ports the forward range spans — i.e. the ceiling on simultaneously
/// *registered* VMs (`HOST_SSH_BASE_PORT..HOST_SSH_BASE_PORT + HOST_SSH_PORTS`).
pub const HOST_SSH_PORTS: u16 = 64;

/// The lowest port in `[base, base + span)` that is not in `taken`.
///
/// This is the whole allocator. The chosen port is then **recorded in the VM's
/// `meta.toml`** ([`crate::vm::VmMeta::ssh_port`]) rather than leased or
/// re-derived per boot: an assignment is state, so a VM keeps its port across
/// restarts, and because every other VM's assignment is in `taken`, two VMs can
/// never be handed the same one. Pure.
pub fn allocate_port(taken: &[u16], base: u16, span: u16) -> Option<u16> {
    (u32::from(base)..u32::from(base) + u32::from(span))
        .filter_map(|p| u16::try_from(p).ok())
        .find(|p| !taken.contains(p))
}

/// The live host-loopback endpoint of a VM's SSH forward, read
/// from `runtime_dir/<vm>/ssh.endpoint` (written while the supervisor runs).
/// Normally this is the VM's assigned [`crate::vm::VmMeta::ssh_port`]; the file
/// stays the client-facing source of truth so a reassignment needs no client
/// change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshEndpoint {
    pub host: String,
    pub port: u16,
}

impl SshEndpoint {
    /// Load and parse the endpoint file for `vm`. A missing file means the VM is
    /// not running (with networking), so the error says how to bring it up.
    pub fn load(vm: &str) -> io::Result<SshEndpoint> {
        let path = paths::ssh_endpoint_path(vm);
        let raw = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no SSH endpoint for VM '{vm}' at {} — start it with networking first (`sodabox start {vm} --net --foreground`)",
                    path.display()
                ),
            ),
            _ => io::Error::new(e.kind(), format!("reading {}: {e}", path.display())),
        })?;
        Self::parse(raw.trim()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "malformed SSH endpoint {:?} in {}",
                    raw.trim(),
                    path.display()
                ),
            )
        })
    }

    /// Parse a `host:port` line (IPv4/hostname; sodabox only ever writes
    /// `127.0.0.1:<port>`).
    fn parse(s: &str) -> Option<SshEndpoint> {
        let (host, port) = s.rsplit_once(':')?;
        if host.is_empty() {
            return None;
        }
        Some(SshEndpoint {
            host: host.to_string(),
            port: port.parse().ok()?,
        })
    }
}

/// Path of the tool-owned private key: `$XDG_DATA_HOME/sodabox/sodabox_ed25519`.
/// Reused across every instance; the public key is the same path plus `.pub`.
pub fn tool_key_path() -> PathBuf {
    paths::data_root().join("sodabox_ed25519")
}

fn pubkey_path(priv_path: &Path) -> PathBuf {
    let mut p = priv_path.as_os_str().to_os_string();
    p.push(".pub");
    PathBuf::from(p)
}

/// Ensure the tool keypair exists, returning its public-key line (the trimmed
/// contents of the `.pub` file). Reuses an existing key; otherwise generates a
/// new passphrase-less ed25519 key with the system `ssh-keygen`.
pub fn ensure_tool_key() -> io::Result<String> {
    ensure_tool_key_at(&tool_key_path())
}

/// [`ensure_tool_key`] against an explicit private-key path (hermetic; tests).
fn ensure_tool_key_at(priv_path: &Path) -> io::Result<String> {
    ensure_ed25519_key_at(priv_path, "sodabox")
}

/// Host-held sshd host key of VM `vm` (`<data-dir>/<vm>/ssh_host_ed25519_key`),
/// used only by `persist = "none"` VMs (ADR-0014).
pub fn guest_host_key_path(vm: &str) -> PathBuf {
    paths::data_dir(vm).join("ssh_host_ed25519_key")
}

/// The sshd host key for a VM that keeps no guest state (`persist = "none"`,
/// ADR-0014), returned as the private key text to ship on the config disk.
///
/// Such a guest would otherwise generate a new host key every boot, which the
/// TOFU pin ([`hardened_ssh_opts`]) refuses — and simply re-trusting each new
/// key would quietly drop host-key verification. So the *host* owns this VM's
/// identity instead: the key is generated once into the VM's data dir and its
/// public half is pinned in [`known_hosts_path`] up front, so the very first
/// connection is already verified rather than trust-on-first-use. The pin is
/// rewritten every launch, which also clears any stale entry.
pub fn pinned_guest_host_key(vm: &str) -> io::Result<String> {
    let priv_path = guest_host_key_path(vm);
    let pubkey = ensure_ed25519_key_at(&priv_path, &host_key_alias(vm))?;
    let line = known_hosts_line(&host_key_alias(vm), &pubkey).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed host public key for '{vm}'"),
        )
    })?;
    std::fs::write(known_hosts_path(vm), line)?;
    std::fs::read_to_string(&priv_path)
}

/// The `known_hosts` line pinning `pubkey` (an OpenSSH `.pub` line) under
/// `alias` — the name [`hardened_ssh_opts`] looks it up by (`HostKeyAlias`).
fn known_hosts_line(alias: &str, pubkey: &str) -> Option<String> {
    let mut it = pubkey.split_whitespace();
    let (kind, body) = (it.next()?, it.next()?);
    Some(format!("{alias} {kind} {body}\n"))
}

/// Ensure a passphrase-less ed25519 keypair at `priv_path` (+ `.pub`), returning
/// its public-key line. An existing key is reused.
fn ensure_ed25519_key_at(priv_path: &Path, comment: &str) -> io::Result<String> {
    let pub_path = pubkey_path(priv_path);
    if pub_path.exists() {
        return read_pubkey(&pub_path);
    }
    if let Some(dir) = priv_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // ssh-keygen refuses to overwrite an existing file; clear a stray private
    // key left without its `.pub` by an interrupted earlier run.
    let _ = std::fs::remove_file(priv_path);

    let status = Command::new(ssh_keygen_bin())
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("") // no passphrase
        .arg("-C")
        .arg(comment)
        .arg("-f")
        .arg(priv_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| io::Error::new(e.kind(), format!("running ssh-keygen: {e}")))?;
    if !status.success() {
        return Err(io::Error::other(format!("ssh-keygen failed ({status})")));
    }
    // ssh-keygen already writes the private key 0600; enforce it defensively.
    harden_perms(priv_path)?;
    read_pubkey(&pub_path)
}

fn read_pubkey(pub_path: &Path) -> io::Result<String> {
    Ok(std::fs::read_to_string(pub_path)?.trim().to_string())
}

#[cfg(unix)]
fn harden_perms(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn harden_perms(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// The guest `authorized_keys` body (ADR-0011): the tool key and nothing else,
/// so `sodabox ssh` and sync work and no other identity can log in. Generates
/// the key on first use; rebuilt each launch (the config disk is).
pub fn authorized_keys() -> io::Result<String> {
    Ok(format!("{}\n", ensure_tool_key()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("sodabox-ssh-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn ensure_tool_key_generates_then_reuses() {
        // Skip cleanly where ssh-keygen is unavailable (keeps CI hermetic).
        if which_ssh_keygen().is_none() {
            eprintln!("ssh-keygen not found; skipping");
            return;
        }
        let dir = scratch("keygen");
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("sodabox_ed25519");

        let pub1 = ensure_tool_key_at(&key).unwrap();
        assert!(
            pub1.starts_with("ssh-ed25519 "),
            "unexpected pubkey: {pub1}"
        );
        assert!(key.exists() && pubkey_path(&key).exists());

        // Private key must be host-only (0600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "private key perms {mode:o}");
        }

        // Second call reuses the same key (identical pubkey, no regeneration).
        let pub2 = ensure_tool_key_at(&key).unwrap();
        assert_eq!(pub1, pub2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn known_hosts_line_pins_key_under_the_alias() {
        assert_eq!(
            known_hosts_line("sodabox-web", "ssh-ed25519 AAAAC3Nz sodabox-web\n").as_deref(),
            Some("sodabox-web ssh-ed25519 AAAAC3Nz\n")
        );
        assert_eq!(known_hosts_line("a", "ssh-ed25519"), None);
    }

    #[test]
    fn hardened_opts_pin_identity_and_verify_host_key() {
        let opts: Vec<String> = hardened_ssh_opts("web")
            .iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect();
        // No user ssh config, one deterministic key, never an agent.
        assert!(opts.windows(2).any(|w| w == ["-F", "/dev/null"]));
        assert!(opts.iter().any(|o| o == "IdentitiesOnly=yes"));
        assert!(opts.iter().any(|o| o == "IdentityAgent=none"));
        // TOFU host-key pinning: accept-new into a per-VM known_hosts, keyed by
        // the VM alias so the forward's port can't defeat it.
        assert!(opts.iter().any(|o| o == "StrictHostKeyChecking=accept-new"));
        assert!(opts.iter().any(|o| o == "HostKeyAlias=sodabox-web"));
        assert!(opts
            .iter()
            .any(|o| o == &format!("UserKnownHostsFile={}", known_hosts_path("web").display())));
        // The tool key is passed with -i.
        let i = opts.iter().position(|o| o == "-i").expect("-i present");
        assert_eq!(opts[i + 1], tool_key_path().to_string_lossy());
    }

    #[test]
    fn allocate_port_takes_the_lowest_free_slot() {
        // Nothing assigned yet -> the base port.
        assert_eq!(allocate_port(&[], 3522, 4), Some(3522));
        // Holes are reused (a removed VM frees its port for the next create).
        assert_eq!(allocate_port(&[3522, 3524], 3522, 4), Some(3523));
        // Out-of-range assignments don't consume slots.
        assert_eq!(allocate_port(&[9999], 3522, 4), Some(3522));
        // Range exhausted -> no port (the caller reports it).
        assert_eq!(allocate_port(&[3522, 3523, 3524, 3525], 3522, 4), None);
        // A span running past u16::MAX stops at the last real port.
        assert_eq!(allocate_port(&[u16::MAX], u16::MAX, 8), None);
    }

    #[test]
    fn endpoint_parses_host_and_port() {
        let ep = SshEndpoint::parse("127.0.0.1:2233").unwrap();
        assert_eq!(
            ep,
            SshEndpoint {
                host: "127.0.0.1".into(),
                port: 2233
            }
        );
        // Rejects garbage and a missing/empty host.
        assert!(SshEndpoint::parse("nonsense").is_none());
        assert!(SshEndpoint::parse("127.0.0.1:notaport").is_none());
        assert!(SshEndpoint::parse(":2233").is_none());
    }

    fn which_ssh_keygen() -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|d| d.join("ssh-keygen"))
            .find(|p| p.exists())
    }
}
