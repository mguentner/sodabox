//! cloud-hypervisor process launch + lifecycle wrapper.
//!
//! Turns the boot recipe validated in spike 0001 into a supervised
//! process: build the argv, spawn against `/dev/kvm`, then `wait`/`shutdown`.
//! The wrapper is deliberately namespace-agnostic — the supervisor
//! creates and enters the per-VM user+network namespace and then calls
//! [`Chv::spawn`] from inside it. Passt and the data.img mount
//! plug into [`GuestBoot`] as they land.
//!
//! Validated recipe:
//! ```text
//! cloud-hypervisor \
//!   --kernel <mkGuest.kernel>/bzImage \
//!   --initramfs <mkGuest.initrd>/initrd \
//!   --disk path=<mkGuest.store>,readonly=on,image_type=raw \
//!   --cpus boot=<n> --memory size=<m>M,shared=on \
//!   --cmdline 'console=ttyS0 root=fstab loglevel=4 init=<toplevel>/init'
//! ```
//! `shared=on` is mandatory for the vhost-user net backend (passt);
//! `image_type=raw` is mandatory or cloud-hypervisor refuses sector-0 writes.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::process::{Child, Command};

/// Environment override for the cloud-hypervisor binary. When unset the wrapper
/// relies on `cloud-hypervisor` being on `PATH` (pinned there by the packaging
/// wrapper).
const CHV_BIN_ENV: &str = "SODABOX_CLOUD_HYPERVISOR";
/// Environment override for `ch-remote` (cloud-hypervisor's API client, used for
/// a clean ACPI power-off). Shipped by the same package.
const CH_REMOTE_BIN_ENV: &str = "SODABOX_CH_REMOTE";

fn chv_bin() -> OsString {
    std::env::var_os(CHV_BIN_ENV).unwrap_or_else(|| OsString::from("cloud-hypervisor"))
}

fn ch_remote_bin() -> OsString {
    std::env::var_os(CH_REMOTE_BIN_ENV).unwrap_or_else(|| OsString::from("ch-remote"))
}

/// Ask cloud-hypervisor (over its API socket) to press the guest's ACPI power
/// button (`ch-remote --api-socket <sock> power-button`). Returns once the request
/// is delivered; the guest then powers off asynchronously.
async fn acpi_power_button(sock: &Path) -> std::io::Result<()> {
    let status = Command::new(ch_remote_bin())
        .arg("--api-socket")
        .arg(sock)
        .arg("power-button")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .await?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "ch-remote power-button exited {status}"
        )))
    }
}

/// A virtio-blk disk attached to the guest.
#[derive(Debug, Clone)]
pub struct Disk {
    pub path: PathBuf,
    /// Read-only (the erofs store image); the data.img is read-write.
    pub readonly: bool,
}

impl Disk {
    /// The read-only erofs `/nix/store` image (becomes `/dev/vda`; ADR-0008).
    pub fn store(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            readonly: true,
        }
    }

    /// The read-only per-VM config disk (erofs; becomes `/dev/vdb`; ADR-0011).
    /// Always attached second so its device name is deterministic
    /// regardless of whether a data disk follows.
    pub fn config(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            readonly: true,
        }
    }

    /// A read-write disk: the data disk the guest mounts at `/persistent`
    /// (→ `/dev/vdc`, ADR-0008) or the home disk at `/persistent/home`
    /// (→ `/dev/vdd`, ADR-0014).
    pub fn data(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            readonly: false,
        }
    }

    /// `--disk` value. `image_type=raw` is always set: cloud-hypervisor's format
    /// auto-detection disables sector-0 writes, which broke the boot in spike 0001.
    fn arg(&self) -> String {
        let mut s = format!("path={}", self.path.display());
        if self.readonly {
            s.push_str(",readonly=on");
        }
        s.push_str(",image_type=raw");
        s
    }
}

/// Where the guest serial console (kernel `console=ttyS0`) is wired.
#[derive(Debug, Clone)]
pub enum Serial {
    /// Inherit the supervisor's stdio — foreground / spike-style boots.
    Stdio,
    /// Append the console to a file (default for a backgrounded VM).
    File(PathBuf),
    /// Expose the console on a unix socket (for `soda tui`/attach).
    Socket(PathBuf),
    /// Discard console output.
    Null,
}

impl Serial {
    fn arg(&self) -> String {
        match self {
            Serial::Stdio => "tty".to_string(),
            Serial::File(p) => format!("file={}", p.display()),
            Serial::Socket(p) => format!("socket={}", p.display()),
            Serial::Null => "null".to_string(),
        }
    }
}

/// Everything needed to boot one guest. Produced from a `mkGuest` build result
/// (kernel boot + device wiring) plus per-VM sizing.
#[derive(Debug, Clone)]
pub struct GuestBoot {
    /// `<mkGuest.kernel>/bzImage`.
    pub kernel: PathBuf,
    /// `<mkGuest.initrd>/initrd`.
    pub initramfs: PathBuf,
    /// Full kernel cmdline, including `init=<toplevel>/init`.
    pub cmdline: String,
    pub cpus: u32,
    /// Guest RAM in MiB. Must be >= 2048 for the current guest.
    pub mem_mib: u64,
    /// Disks in bus order: store (→ `/dev/vda`), then the config disk
    /// (→ `/dev/vdb`, ADR-0011), then the optional data and home disks
    /// (→ `/dev/vdc`, `/dev/vdd`; ADR-0014).
    pub disks: Vec<Disk>,
    /// Passt vhost-user socket. `None` = no NIC yet.
    pub net_socket: Option<PathBuf>,
    /// cloud-hypervisor HTTP API socket for lifecycle/control (ch-remote).
    /// `None` runs without the control API — fine for a foreground boot where
    /// shutdown is driven by signal. Note: the path must be < 108 bytes
    /// (`SUN_LEN`); keep it under `$XDG_RUNTIME_DIR`.
    pub api_socket: Option<PathBuf>,
    pub serial: Serial,
}

impl GuestBoot {
    /// Assemble the argv for cloud-hypervisor (pure; unit-tested).
    pub fn args(&self) -> Vec<OsString> {
        let mut a: Vec<OsString> = Vec::new();

        a.push("--kernel".into());
        a.push(self.kernel.clone().into_os_string());
        a.push("--initramfs".into());
        a.push(self.initramfs.clone().into_os_string());

        a.push("--cmdline".into());
        a.push(self.cmdline.clone().into());

        // TODO: the guest sees the host's CPU identity (vendor, model, brand
        // string) through CPUID; cloud-hypervisor only offers the `host` CPU
        // profile. Pin a static one (some Intel i7) once
        // https://github.com/cloud-hypervisor/cloud-hypervisor/issues/7068 lands.
        a.push("--cpus".into());
        a.push(format!("boot={}", self.cpus).into());

        // shared=on is required for the vhost-user net backend (passt).
        a.push("--memory".into());
        a.push(format!("size={}M,shared=on", self.mem_mib).into());

        if let Some(sock) = &self.api_socket {
            a.push("--api-socket".into());
            a.push(sock.clone().into_os_string());
        }

        if !self.disks.is_empty() {
            a.push("--disk".into());
            for d in &self.disks {
                a.push(d.arg().into());
            }
        }

        if let Some(sock) = &self.net_socket {
            // Passt exposes a vhost-user backend; mac is assigned by the guest.
            a.push("--net".into());
            a.push(format!("vhost_user=on,socket={}", sock.display()).into());
        }

        // Kernel console is serial (base.nix: console=ttyS0); disable the
        // virtio console so there is a single, well-defined console sink.
        a.push("--serial".into());
        a.push(self.serial.arg().into());
        a.push("--console".into());
        a.push("off".into());

        a
    }
}

/// A running (or exited) cloud-hypervisor process.
pub struct Chv {
    child: Child,
    api_socket: Option<PathBuf>,
}

impl Chv {
    /// Spawn cloud-hypervisor for `boot`. The caller is responsible for having
    /// entered the target namespace first.
    pub async fn spawn(boot: &GuestBoot) -> std::io::Result<Chv> {
        let (stdout, stderr) = match boot.serial {
            // Only `Serial::Stdio` should reach the terminal; otherwise the
            // console goes to its file/socket and cloud-hypervisor's own logs
            // are the only stdio, which we let inherit for now.
            Serial::Stdio => (Stdio::inherit(), Stdio::inherit()),
            _ => (Stdio::null(), Stdio::inherit()),
        };

        let child = Command::new(chv_bin())
            .args(boot.args())
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            // Own process group: a terminal SIGINT (Ctrl-C) or a
            // group-directed SIGTERM must reach only the supervisor, not
            // cloud-hypervisor — otherwise chv tears itself down concurrently and
            // our clean ACPI power-off (`ch-remote power-button`) races a
            // closing VMM ("receiving on a closed channel"). The supervisor still
            // stops it explicitly (by pid) via `shutdown`, and `kill_on_drop`
            // remains the backstop.
            .process_group(0)
            .kill_on_drop(true)
            .spawn()?;

        Ok(Chv {
            child,
            api_socket: boot.api_socket.clone(),
        })
    }

    /// The child pid, if the process has not been reaped.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn api_socket(&self) -> Option<&Path> {
        self.api_socket.as_deref()
    }

    /// Await guest exit.
    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait().await
    }

    /// Clean shutdown: press the virtual **ACPI power button** via
    /// `ch-remote` so the guest OS shuts down in an orderly way — unmounting and
    /// flushing its disks (`/persistent`, `/persistent/home`) so writes are durable — and wait for
    /// cloud-hypervisor to exit within `grace`. Falls back to a hard stop
    /// (SIGTERM→SIGKILL) if there is no API socket, `ch-remote` fails, or the
    /// guest does not power off in time (e.g. a hung guest).
    pub async fn shutdown(&mut self, grace: Duration) -> std::io::Result<ExitStatus> {
        if let Some(sock) = self.api_socket.clone() {
            match acpi_power_button(&sock).await {
                Ok(()) => match tokio::time::timeout(grace, self.child.wait()).await {
                    Ok(status) => return status,
                    Err(_) => {
                        eprintln!(
                            "soda: guest did not power off within {}s of ACPI power-button; forcing",
                            grace.as_secs()
                        );
                    }
                },
                Err(e) => eprintln!("soda: ACPI power-off failed ({e}); forcing"),
            }
        }
        crate::proc::graceful_shutdown(&mut self.child, grace).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GuestBoot {
        GuestBoot {
            kernel: PathBuf::from("/nix/store/abc-linux/bzImage"),
            initramfs: PathBuf::from("/nix/store/def-initrd/initrd"),
            cmdline: "console=ttyS0 root=fstab loglevel=4 init=/nix/store/top/init".into(),
            cpus: 2,
            mem_mib: 2048,
            disks: vec![
                Disk::store("/nix/store/ghi-store.erofs"),
                Disk::data("/home/u/.local/share/sodabox/vm/data.img"),
            ],
            net_socket: None,
            api_socket: Some(PathBuf::from("/run/user/1000/sodabox/vm/chv-api.sock")),
            serial: Serial::File(PathBuf::from("/run/user/1000/sodabox/vm/console.log")),
        }
    }

    fn args_str(b: &GuestBoot) -> Vec<String> {
        b.args()
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    fn value_after<'a>(args: &'a [String], flag: &str) -> &'a str {
        let i = args.iter().position(|a| a == flag).expect("flag present");
        args[i + 1].as_str()
    }

    #[test]
    fn store_disk_is_readonly_raw_first() {
        let a = args_str(&sample());
        // The first --disk value is the read-only store image (→ /dev/vda).
        let i = a.iter().position(|x| x == "--disk").unwrap();
        assert_eq!(
            a[i + 1],
            "path=/nix/store/ghi-store.erofs,readonly=on,image_type=raw"
        );
        // The data disk follows, read-write, still raw.
        assert_eq!(
            a[i + 2],
            "path=/home/u/.local/share/sodabox/vm/data.img,image_type=raw"
        );
    }

    #[test]
    fn memory_is_shared_for_vhost_user() {
        let a = args_str(&sample());
        assert_eq!(value_after(&a, "--memory"), "size=2048M,shared=on");
    }

    #[test]
    fn cpus_and_cmdline_and_console() {
        let a = args_str(&sample());
        assert_eq!(value_after(&a, "--cpus"), "boot=2");
        assert_eq!(
            value_after(&a, "--cmdline"),
            "console=ttyS0 root=fstab loglevel=4 init=/nix/store/top/init"
        );
        assert_eq!(
            value_after(&a, "--serial"),
            "file=/run/user/1000/sodabox/vm/console.log"
        );
        assert_eq!(value_after(&a, "--console"), "off");
    }

    #[test]
    fn api_socket_added_only_when_present() {
        let a = args_str(&sample());
        assert_eq!(
            value_after(&a, "--api-socket"),
            "/run/user/1000/sodabox/vm/chv-api.sock"
        );

        let mut b = sample();
        b.api_socket = None;
        let a = args_str(&b);
        assert!(!a.iter().any(|x| x == "--api-socket"));
    }

    #[test]
    fn net_socket_added_only_when_present() {
        let a = args_str(&sample());
        assert!(!a.iter().any(|x| x == "--net"));

        let mut b = sample();
        b.net_socket = Some(PathBuf::from("/run/passt.sock"));
        let a = args_str(&b);
        assert_eq!(
            value_after(&a, "--net"),
            "vhost_user=on,socket=/run/passt.sock"
        );
    }
}
