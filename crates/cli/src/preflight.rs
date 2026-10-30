//! `soda preflight` (ADR-0010): check the two hard host prerequisites —
//! access to `/dev/kvm` (ADR-0002) and the ability to create unprivileged
//! user + network namespaces (ADR-0004) — plus report the bundled helper tools.
//!
//! sodabox refuses to modify the host, so preflight only *diagnoses*: it prints
//! remediation the user can apply themselves and never changes anything.

use std::path::Path;

/// Hidden argv used to re-exec ourselves as a single-threaded namespace probe.
/// `CLONE_NEWUSER` requires the process to be single-threaded, so we cannot
/// probe from under the async runtime — main() runs this before any threads.
pub const PROBE_ARG: &str = "__preflight-userns-probe";

/// Child entry point: attempt to create a user namespace, then a network
/// namespace inside it (exactly what a per-VM supervisor does). Exit codes are
/// read by the parent.
pub fn probe_namespaces() -> i32 {
    use nix::sched::{unshare, CloneFlags};
    match unshare(CloneFlags::CLONE_NEWUSER) {
        Ok(()) => match unshare(CloneFlags::CLONE_NEWNET) {
            Ok(()) => 0, // user+net namespaces both work
            Err(_) => 3, // userns ok, netns denied
        },
        Err(_) => 2, // unprivileged userns blocked
    }
}

pub fn run() -> anyhow::Result<()> {
    println!("soda preflight — host prerequisites\n");
    let mut ok = true;
    ok &= check_kvm();
    ok &= check_namespaces();
    check_tools(); // informational only

    println!();
    if ok {
        println!("[ ok ] all required checks passed.");
        Ok(())
    } else {
        println!("[FAIL] one or more required checks failed (see above).");
        std::process::exit(1);
    }
}

fn check_kvm() -> bool {
    let path = Path::new("/dev/kvm");
    if !path.exists() {
        line(false, "KVM", "/dev/kvm is missing");
        hint("enable KVM (kvm_intel/kvm_amd) and ensure hardware virtualization is on in BIOS");
        return false;
    }
    // A read/write open is the access test the VMM itself performs; harmless
    // without a subsequent ioctl.
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(_) => {
            line(true, "KVM", "/dev/kvm present and read/write");
            true
        }
        Err(e) => {
            line(
                false,
                "KVM",
                &format!("/dev/kvm present but not accessible ({e})"),
            );
            hint(
                "add your user to the 'kvm' group (e.g. `sudo usermod -aG kvm $USER`) and re-login",
            );
            false
        }
    }
}

fn check_namespaces() -> bool {
    let exe = std::env::current_exe().unwrap_or_else(|_| "/proc/self/exe".into());
    let status = std::process::Command::new(exe).arg(PROBE_ARG).status();
    let code = match status {
        Ok(s) => s.code(),
        Err(e) => {
            line(
                false,
                "userns",
                &format!("could not run namespace probe ({e})"),
            );
            return false;
        }
    };
    match code {
        Some(0) => {
            line(
                true,
                "userns",
                "unprivileged user + network namespaces work",
            );
            true
        }
        Some(2) => {
            line(
                false,
                "userns",
                "cannot create an unprivileged user namespace",
            );
            userns_diagnostics();
            false
        }
        Some(3) => {
            line(
                false,
                "netns",
                "user namespace ok, but network namespace was denied",
            );
            userns_diagnostics();
            false
        }
        other => {
            line(
                false,
                "userns",
                &format!("namespace probe failed (exit {other:?})"),
            );
            userns_diagnostics();
            false
        }
    }
}

/// Best-effort sysctl hints for why unprivileged namespaces might be blocked.
fn userns_diagnostics() {
    for (path, note) in [
        (
            "/proc/sys/kernel/unprivileged_userns_clone",
            "must be 1 (Debian/Ubuntu)",
        ),
        ("/proc/sys/user/max_user_namespaces", "must be > 0"),
        (
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            "must be 0 (Ubuntu 24.04+)",
        ),
    ] {
        if let Ok(v) = std::fs::read_to_string(path) {
            println!("         {path} = {}  ({note})", v.trim());
        }
    }
    hint("enable unprivileged user namespaces (see the sysctls above); sodabox cannot do this for you");
}

/// Report the bundled helper binaries. Informational: the flake provides pinned
/// versions on PATH (ADR-0010), so absence here is only a warning.
fn check_tools() {
    for tool in [
        "cloud-hypervisor",
        "passt",
        "mkfs.erofs",
        "ssh-keygen",
        "ssh",
        "rsync",
    ] {
        match which(tool) {
            Some(p) => line_info(tool, &format!("found at {}", p.display())),
            None => line_info(
                tool,
                "not on PATH (provided by the sodabox flake at runtime)",
            ),
        }
    }
}

fn which(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.exists())
}

fn line(ok: bool, tag: &str, msg: &str) {
    println!("[{}] {tag:<8} {msg}", if ok { " ok " } else { "FAIL" });
}
fn line_info(tag: &str, msg: &str) {
    println!("[info] {tag:<16} {msg}");
}
fn hint(msg: &str) {
    println!("         -> {msg}");
}
