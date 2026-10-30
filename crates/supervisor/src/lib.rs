//! Per-VM supervisor (ADR-0007). No central daemon: `sodabox start <vm>` spawns
//! one of these, which creates and owns the user+network namespace (spike
//! 0002), launches cloud-hypervisor (spike 0001:
//! docs/spikes/0001-rootless-chv-boot.md) + passt + the in-process filter proxy
//! and DNS filter, and exposes a control+event unix socket. If it dies, the VM's
//! egress dies with it (fail-closed).

pub mod chv;
pub mod config_disk;
pub mod control;
pub mod eventlog;
pub mod fdpass;
pub mod guest;
pub mod netns;
pub mod nft;
pub mod passt;
pub mod proc;
pub mod ssh_forward;
pub mod supervise;
pub mod udp_inject;

use sodabox_common::policy::VmPolicy;

pub struct Supervisor {
    vm: String,
    #[allow(dead_code)]
    policy: VmPolicy,
}

impl Supervisor {
    pub fn new(vm: impl Into<String>, policy: VmPolicy) -> Self {
        Self {
            vm: vm.into(),
            policy,
        }
    }

    /// Bring up the VM's full runtime and serve its control socket. Composition
    /// of the pieces (netns → nft → passt → DNS resolver → filter proxy → chv)
    /// is the remaining supervisor work; the control socket
    /// itself is [`control::ControlServer`], which this will
    /// bind once the runtime state implements [`control::ControlHandler`].
    pub async fn run(self) -> anyhow::Result<()> {
        anyhow::bail!("supervisor for '{}' not yet implemented", self.vm)
    }
}
