//! XDG-based runtime/persistent layout (ADR-0007/0008). All state is per-user;
//! nothing is written outside these directories.

use std::path::{Path, PathBuf};

/// `$XDG_RUNTIME_DIR/sodabox/` — the root that holds every VM's runtime dir.
/// Falls back to `/run/user/<uid>` semantics via `$XDG_RUNTIME_DIR`, then `/tmp`.
pub fn runtime_root() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("sodabox")
}

/// `$XDG_RUNTIME_DIR/sodabox/<vm>/` — control.sock, pid, console/chv/passt socks.
pub fn runtime_dir(vm: &str) -> PathBuf {
    runtime_root().join(vm)
}

/// `$XDG_RUNTIME_DIR/sodabox/<vm>/ssh.endpoint` — the live `host:port` the SSH
/// forward listens on (ADR-0011). Written by the supervisor once the
/// host-loopback listener is bound; read by `soda ssh`/`sync`.
pub fn ssh_endpoint_path(vm: &str) -> PathBuf {
    runtime_dir(vm).join("ssh.endpoint")
}

/// `$XDG_RUNTIME_DIR/sodabox/<vm>/control.sock` — the control + event socket
/// the supervisor exposes (ADR-0007).
pub fn control_sock_path(vm: &str) -> PathBuf {
    runtime_dir(vm).join("control.sock")
}

/// `$XDG_RUNTIME_DIR/sodabox/<vm>/pid` — the host-side supervisor process pid
/// (ADR-0007 layout). Written while the VM is running; removed by clean
/// teardown and stale sweeps.
pub fn pid_path(vm: &str) -> PathBuf {
    runtime_dir(vm).join("pid")
}

/// `$XDG_RUNTIME_DIR/sodabox/<vm>/passt.sock` — passt vhost-user socket (the
/// netns child binds it).
pub fn passt_sock_path(vm: &str) -> PathBuf {
    runtime_dir(vm).join("passt.sock")
}

/// `$XDG_RUNTIME_DIR/sodabox/<vm>/chv-api.sock` — cloud-hypervisor API socket
/// (short name stays under SUN_LEN; used for the clean ACPI power-off).
pub fn chv_api_sock_path(vm: &str) -> PathBuf {
    runtime_dir(vm).join("chv-api.sock")
}

/// `$XDG_RUNTIME_DIR/sodabox/<vm>/console.log` — guest serial console.
pub fn console_path(vm: &str) -> PathBuf {
    runtime_dir(vm).join("console.log")
}

/// `$XDG_RUNTIME_DIR/sodabox/<vm>/supervisor.log` — the detached supervisor's
/// stdout/stderr when started in the background (ADR-0007: "detached/background
/// start by default"). Recreated fresh each boot after the runtime dir is wiped;
/// the launcher tails it to surface a start failure.
pub fn supervisor_log_path(vm: &str) -> PathBuf {
    runtime_dir(vm).join("supervisor.log")
}

/// `$XDG_RUNTIME_DIR/sodabox/<vm>/config.img` — the read-only guest config disk
/// built at start (ADR-0011). Rebuilt every launch.
pub fn config_img_path(vm: &str) -> PathBuf {
    runtime_dir(vm).join("config.img")
}

/// Remove the VM's entire runtime dir if it exists, ignoring the case where it
/// is already gone. A VM needs none of its runtime state once stopped, so this
/// is how a boot starts clean and a clean teardown ends: stale sockets from an
/// unclean shutdown (a cloud-hypervisor `--api-socket` bind, a passt vhost-user
/// bind, or `bind()` on control.sock) are what block a restart, and wiping the
/// whole dir removes them all at once (ADR-0007: "cleanup of stale runtime
/// dirs after unclean shutdown").
pub fn wipe_runtime_dir(vm: &str) -> std::io::Result<()> {
    remove_dir_quiet(&runtime_dir(vm))
}

/// Best-effort recursive removal of `dir`; `NotFound` is a success (an already
/// clean runtime dir is the common case).
pub fn remove_dir_quiet(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// `$XDG_DATA_HOME/sodabox/` — the root that holds every VM's data dir.
/// Falls back to `$HOME/.local/share`.
pub fn data_root() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from(".local/share"))
        .join("sodabox")
}

/// `$XDG_DATA_HOME/sodabox/<vm>/` — data.img, policy.toml, meta.toml.
pub fn data_dir(vm: &str) -> PathBuf {
    data_root().join(vm)
}

/// `$XDG_DATA_HOME/sodabox/<vm>/events.log` — the persisted event stream for
/// post-hoc audit and `soda logs` (ADR-0009). Lives in the
/// persistent data dir (not the wiped runtime dir) so it survives VM restarts;
/// newline-delimited JSON [`crate::event::Event`] records.
pub fn event_log_path(vm: &str) -> PathBuf {
    data_dir(vm).join("events.log")
}

/// The single rotated-out predecessor of [`event_log_path`] (`events.log.1`),
/// kept so a long-lived VM's audit trail is bounded to two files rather than
/// growing without limit.
pub fn event_log_prev_path(vm: &str) -> PathBuf {
    data_dir(vm).join("events.log.1")
}

/// `$XDG_CONFIG_HOME/sodabox/` — user-owned config. Falls back to `$HOME/.config`.
pub fn config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("sodabox")
}

/// Names a VM may not take: the config dir holds one `<vm>/` dir per VM next
/// to these shared dirs, so a VM with one of these names would collide.
pub const RESERVED_VM_NAMES: &[&str] = &["dotfiles", "guest", "profiles", "providers"];

/// `$XDG_CONFIG_HOME/sodabox/profiles/` — vendor and user policy profiles
/// (ADR-0015), one `<name>.toml` each.
pub fn profiles_dir() -> PathBuf {
    config_dir().join("profiles")
}

/// `$XDG_CONFIG_HOME/sodabox/profiles/<name>.toml`. `name` must already have
/// passed [`crate::profile::validate_name`].
pub fn profile_path(name: &str) -> PathBuf {
    profiles_dir().join(format!("{name}.toml"))
}

/// `$XDG_CONFIG_HOME/sodabox/providers/` — inference providers (ADR-0020), one
/// `<name>.toml` each. Host-wide; never copied into a VM.
pub fn providers_dir() -> PathBuf {
    config_dir().join("providers")
}

/// `$XDG_CONFIG_HOME/sodabox/providers/<name>.toml`. `name` must already have
/// passed [`crate::provider::validate_name`].
pub fn provider_path(name: &str) -> PathBuf {
    providers_dir().join(format!("{name}.toml"))
}

/// `$XDG_DATA_HOME/sodabox/<vm>/quota.jsonl` — the VM's token quota ledger
/// (ADR-0020). In the data dir, out of the guest's reach.
pub fn quota_ledger_path(vm: &str) -> PathBuf {
    data_dir(vm).join("quota.jsonl")
}

/// `$XDG_CONFIG_HOME/sodabox/dotfiles/` — dotfile collections (ADR-0019), one
/// folder each.
pub fn dotfiles_dir() -> PathBuf {
    config_dir().join("dotfiles")
}

/// `$XDG_DATA_HOME/sodabox/<vm>/dotfiles/` — the VM's own copy of its merged
/// collections, written at `create` and shipped on the config disk (ADR-0019).
pub fn vm_dotfiles_dir(vm: &str) -> PathBuf {
    data_dir(vm).join("dotfiles")
}

/// The shared, editable guest input (ADR-0012): `configuration.nix` + `npins/`.
pub fn shared_guest_dir() -> PathBuf {
    config_dir().join("guest")
}

/// `$XDG_CONFIG_HOME/sodabox/<vm>/` — the VM's user-owned config (e.g. its
/// guest override).
pub fn vm_config_dir(vm: &str) -> PathBuf {
    config_dir().join(vm)
}

/// Optional per-VM guest input that shadows the shared default.
pub fn vm_guest_override_dir(vm: &str) -> PathBuf {
    vm_config_dir(vm).join("guest")
}

/// The guest input dir sodabox builds for `vm`: the per-VM override if it has a
/// `configuration.nix`, else the shared default (ADR-0012).
pub fn resolve_guest_dir(vm: &str) -> PathBuf {
    let over = vm_guest_override_dir(vm);
    if over.join("configuration.nix").is_file() {
        over
    } else {
        shared_guest_dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runtime-dir name unique to this test process; `sodabox <pid>` dirs are
    /// ours alone, so `wipe_runtime_dir` can be exercised against the real
    /// (pid-scoped) layout without racing other test binaries.
    fn test_vm(suffix: &str) -> String {
        format!("test{}-{suffix}", std::process::id())
    }

    #[test]
    fn runtime_dir_lives_under_runtime_root() {
        let dir = runtime_dir("vm1");
        let root = runtime_root();
        assert!(dir.starts_with(&root), "{dir:?} not under {root:?}");
        assert_eq!(dir.file_name(), Some(std::ffi::OsStr::new("vm1")));
    }

    #[test]
    fn runtime_files_are_named_per_adr0007() {
        let vm = "vm1";
        for (f, name) in [
            (control_sock_path(vm), "control.sock"),
            (pid_path(vm), "pid"),
            (passt_sock_path(vm), "passt.sock"),
            (chv_api_sock_path(vm), "chv-api.sock"),
            (console_path(vm), "console.log"),
            (supervisor_log_path(vm), "supervisor.log"),
            (config_img_path(vm), "config.img"),
            (ssh_endpoint_path(vm), "ssh.endpoint"),
        ] {
            assert_eq!(f.file_name().and_then(|n| n.to_str()), Some(name));
            assert!(f.starts_with(runtime_dir(vm)), "{f:?} not in runtime dir");
        }
    }

    #[test]
    fn wipe_removes_runtime_dir_and_is_idempotent() {
        let vm = test_vm("wipe");
        let dir = runtime_dir(&vm);
        // Simulate stale leftovers from an unclean shutdown.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(control_sock_path(&vm), b"").unwrap();
        std::fs::write(chv_api_sock_path(&vm), b"").unwrap();
        std::fs::write(passt_sock_path(&vm), b"").unwrap();
        std::fs::write(pid_path(&vm), "1234").unwrap();
        assert!(dir.exists());

        wipe_runtime_dir(&vm).unwrap();
        assert!(!dir.exists());
        // A second wipe (already clean) is a success, not an error.
        wipe_runtime_dir(&vm).unwrap();
        let _ = remove_dir_quiet(&dir);
    }

    #[test]
    fn wipe_survives_a_missing_runtime_root() {
        let vm = test_vm("missing");
        assert!(remove_dir_quiet(&runtime_dir(&vm)).is_ok());
    }
}
