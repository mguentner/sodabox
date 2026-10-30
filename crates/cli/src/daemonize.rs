//! Detaching a background supervisor from the launching shell.
//!
//! ADR-0007 makes background start the default: `soda start <vm>` should spawn
//! the per-VM supervisor and return, leaving it running independently of the
//! terminal. We do that in-process: [`daemonize`] forks once, `setsid`s the child
//! into its own session (so a terminal hang-up won't kill it) and points its stdin
//! at `/dev/null`, then hands control back to each side:
//!
//! - the **child** ([`Daemon::Child`]) goes on to run the supervisor
//!   ([`sodabox_supervisor::supervise::run_with_log`], which redirects its own
//!   stdout/stderr to the VM's `supervisor.log`);
//! - the **launcher** ([`Daemon::Launcher`]) holds the child's pid so it can wait
//!   for the VM to come up (its control socket) — or notice the child died first.
//!
//! Only a single fork is used. After the launcher reports readiness and exits, the
//! still-running supervisor is reparented (to init / the nearest subreaper), which
//! reaps it on eventual exit; `setsid` already detached it from the controlling
//! terminal, so no double-fork is needed.
//!
//! Must be called single-threaded, before any tokio runtime exists — same
//! constraint as the supervisor's own `fork` (it unshares a user namespace).

use std::path::Path;

/// Which side of the [`daemonize`] fork the caller is on.
pub enum Daemon {
    /// The original process. Wait on the child's readiness, then exit.
    Launcher { child: nix::unistd::Pid },
    /// The detached supervisor. Run the workload; never return to the shell.
    Child,
}

/// Fork off a detached background process. See the module docs. `ready_dir` must
/// already exist (it holds the supervisor log the child will write to); we only
/// use it to fail early with a clear error if the caller forgot.
pub fn daemonize(ready_dir: &Path) -> anyhow::Result<Daemon> {
    if !ready_dir.is_dir() {
        anyhow::bail!("runtime dir {} does not exist", ready_dir.display());
    }
    // SAFETY: caller guarantees single-threaded, pre-tokio. Between fork and the
    // child's later exec/exit we only touch async-signal-safe operations.
    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Parent { child } => Ok(Daemon::Launcher { child }),
        nix::unistd::ForkResult::Child => {
            detach_child()?;
            Ok(Daemon::Child)
        }
    }
}

/// New session + detach stdin from the terminal. stdout/stderr are left for the
/// supervisor to redirect to its log file once the runtime dir is prepared.
fn detach_child() -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    nix::unistd::setsid().map_err(|e| anyhow::anyhow!("setsid: {e}"))?;
    // Point stdin at /dev/null so the guest/console can never read the terminal.
    let devnull = std::fs::File::open("/dev/null")?;
    // SAFETY: dup2 onto stdin; devnull is a valid open fd held until end of scope.
    if unsafe { nix::libc::dup2(devnull.as_raw_fd(), nix::libc::STDIN_FILENO) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Non-blocking check of whether the daemon child has already exited (a failed
/// start). `Ok(None)` = still running; `Ok(Some(code))` = exited with that status;
/// the child is reaped when it has exited so it never lingers as a zombie.
pub fn child_exit_status(child: nix::unistd::Pid) -> anyhow::Result<Option<i32>> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
        Ok(WaitStatus::StillAlive) => Ok(None),
        Ok(WaitStatus::Exited(_, code)) => Ok(Some(code)),
        Ok(WaitStatus::Signaled(_, sig, _)) => Ok(Some(128 + sig as i32)),
        Ok(_) => Ok(None),
        // ECHILD: already reaped elsewhere — treat as gone with unknown status.
        Err(nix::errno::Errno::ECHILD) => Ok(Some(-1)),
        Err(e) => Err(anyhow::anyhow!("waitpid: {e}")),
    }
}
