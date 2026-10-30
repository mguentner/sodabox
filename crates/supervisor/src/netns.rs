//! Per-VM user + network namespace, created and owned by the supervisor
//! (spike 0002 recipe: `unshare -Un --map-root-user`).
//!
//! Each VM gets its own fresh user namespace (so we can be root *inside* it
//! without any host privilege) and, nested in it, a fresh network namespace we
//! fully control — CAP_NET_ADMIN in the new netns lets the supervisor run passt,
//! install the nftables egress rules, and bring up interfaces. The supervisor
//! process **is** the owner: cloud-hypervisor, passt and the filter proxy are
//! spawned as its children and inherit the namespaces, and when the supervisor
//! exits the kernel tears the netns down with it — that is the fail-closed
//! property (no supervisor ⇒ no egress path).
//!
//! # Threading
//! `unshare(CLONE_NEWUSER)` requires a single-threaded process, so
//! [`enter_new`] must run *before* any async runtime (tokio) spawns threads —
//! the same constraint the preflight probe handles by re-exec. The supervisor
//! entry point calls [`enter_new`] first, then builds its runtime.

use std::fs;
use std::io;
use std::net::Ipv4Addr;

use nix::sched::{unshare, CloneFlags};
use nix::unistd::{getgid, getuid};

/// Create a fresh user+network namespace for the current process and map the
/// caller to root inside the user namespace (granting full capabilities there,
/// including CAP_NET_ADMIN in the newly-created netns).
///
/// Must be called from a single-threaded context. On success the process is
/// uid/gid 0 *inside* the namespace, in an isolated network namespace that
/// currently contains only a (down) loopback device — call [`bring_up_loopback`]
/// next.
pub fn enter_new() -> io::Result<()> {
    let uid = getuid();
    let gid = getgid();

    // A single unshare creates the netns already owned by the new userns, so we
    // hold CAP_NET_ADMIN over it without a second privileged step.
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET).map_err(io::Error::from)?;

    // Establish the identity mapping outer{uid,gid} -> 0 inside. `setgroups` must
    // be denied before writing gid_map from an unprivileged userns.
    fs::write("/proc/self/setgroups", "deny")?;
    fs::write("/proc/self/uid_map", format!("0 {} 1\n", uid.as_raw()))?;
    fs::write("/proc/self/gid_map", format!("0 {} 1\n", gid.as_raw()))?;

    Ok(())
}

/// Bring the loopback interface up inside the current netns. passt's DNS-forward
/// target and the in-netns filter proxy both live on loopback (spike 0002), so
/// `lo` must be up. Uses the `ip` binary (iproute2, pinned by packaging); the
/// override env is [`IP_BIN_ENV`].
pub fn bring_up_loopback() -> io::Result<()> {
    let ip = std::env::var_os(IP_BIN_ENV).unwrap_or_else(|| "ip".into());
    let status = std::process::Command::new(&ip)
        .args(["link", "set", "lo", "up"])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "`{} link set lo up` failed: {status}",
            ip.to_string_lossy()
        )));
    }
    Ok(())
}

/// Create a dummy interface `name` carrying `addr/prefix`, bring it up, and add a
/// default route out of it. passt needs a usable non-loopback interface in the
/// netns to derive the guest network from (via the route to its `-o` outbound
/// address) — without one it ignores `-a`/`-g` and hands the guest a link-local
/// `169.254.x` address (verified against passt 2025_09; spike 0002). The
/// interface is a black hole: real guest egress is marked and TPROXY'd onto `lo`
/// to the filter proxy before it would ever leave via this route.
pub fn create_outbound_iface(name: &str, addr: Ipv4Addr, prefix: u8) -> io::Result<()> {
    let cidr = format!("{addr}/{prefix}");
    run_ip(&["link", "add", name, "type", "dummy"])?;
    run_ip(&["addr", "add", &cidr, "dev", name])?;
    run_ip(&["link", "set", name, "up"])?;
    // A default route so passt's outbound `connect()` has a route to hand to the
    // OUTPUT hook (where nft marks it and the policy route bounces it onto `lo`).
    run_ip(&[
        "route",
        "add",
        "default",
        "via",
        &addr.to_string(),
        "dev",
        name,
    ])?;
    Ok(())
}

/// Run `ip <args>` inside the current netns, mapping a non-zero exit to an error.
fn run_ip(args: &[&str]) -> io::Result<()> {
    let ip = std::env::var_os(IP_BIN_ENV).unwrap_or_else(|| "ip".into());
    let status = std::process::Command::new(&ip).args(args).status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "`{} {}` failed: {status}",
            ip.to_string_lossy(),
            args.join(" ")
        )));
    }
    Ok(())
}

/// Environment override for the `ip` (iproute2) binary.
pub const IP_BIN_ENV: &str = "SODABOX_IP";

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};

    /// The child asserts the namespace transition; these codes are read by the
    /// parent so the (multi-threaded) test harness never calls unshare itself.
    const OK: i32 = 0;
    const ASSERT_FAILED: i32 = 1;
    const UNSUPPORTED: i32 = 2;

    #[test]
    fn enter_new_creates_owned_user_net_ns() {
        // Capture the current netns identity in the parent, before forking.
        let before = fs::read_link("/proc/self/ns/net").expect("read ns/net");

        // unshare(CLONE_NEWUSER) needs a single-threaded process; fork one.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                let code = match enter_new() {
                    Err(e)
                        if matches!(
                            e.raw_os_error(),
                            Some(libc_eperm) if libc_eperm == nix::libc::EPERM
                                || libc_eperm == nix::libc::EINVAL
                        ) =>
                    {
                        // Unprivileged userns disabled on this host — not a code
                        // defect; let the parent skip rather than fail.
                        UNSUPPORTED
                    }
                    Err(_) => ASSERT_FAILED,
                    Ok(()) => {
                        let after = fs::read_link("/proc/self/ns/net").unwrap_or_default();
                        let uid_ok = getuid().as_raw() == 0 && getgid().as_raw() == 0;
                        let ns_changed = after != before && !after.as_os_str().is_empty();
                        if uid_ok && ns_changed {
                            OK
                        } else {
                            ASSERT_FAILED
                        }
                    }
                };
                // Bypass unwinding/atexit in the child.
                std::process::exit(code);
            }
            ForkResult::Parent { child } => match waitpid(child, None).expect("waitpid") {
                WaitStatus::Exited(_, OK) => {}
                WaitStatus::Exited(_, UNSUPPORTED) => {
                    eprintln!("skipping: unprivileged user namespaces are disabled on this host");
                }
                other => panic!("namespace child failed: {other:?}"),
            },
        }
    }
}
