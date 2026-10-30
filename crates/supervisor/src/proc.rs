//! Small shared helpers for supervising child processes (cloud-hypervisor,
//! passt, …): graceful shutdown via SIGTERM with a SIGKILL fallback.

use std::process::ExitStatus;
use std::time::Duration;

use tokio::process::Child;

/// Ask `child` to terminate (SIGTERM), then SIGKILL it if it has not exited
/// within `grace`. Reaps the child either way.
pub async fn graceful_shutdown(child: &mut Child, grace: Duration) -> std::io::Result<ExitStatus> {
    if let Some(pid) = child.id() {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        // ESRCH just means it already exited — ignore.
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
    }
    match tokio::time::timeout(grace, child.wait()).await {
        Ok(status) => status,
        Err(_) => {
            child.start_kill()?;
            child.wait().await
        }
    }
}
