//! Build a guest with sodabox's `mkGuest.nix` and adapt the result into a
//! [`chv::GuestBoot`] (bridging ADR-0012 → the launcher).
//!
//! sodabox owns *how* a guest is built: it invokes an impure `nix-build` of the
//! shipped `mkGuest.nix`, passing the user-owned guest dir (`configuration.nix`
//! plus npins). The build yields four store paths for the kernel, initrd, erofs
//! store image and system toplevel, which map directly onto a direct-kernel-boot
//! `GuestBoot` with no bootloader or firmware path.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use sodabox_common::vm::LaunchDisks;

use crate::chv::{Disk, GuestBoot, Serial};

/// Environment override for the directory holding `mkGuest.nix` (+ `base.nix`,
/// `erofs-store.nix`). Set by the packaging wrapper; in a dev
/// checkout it defaults to the repo's `nix/guest`.
const GUEST_NIX_DIR_ENV: &str = "SODABOX_GUEST_NIX_DIR";

/// Environment override for the cloud-hypervisor-visible `nix` binary.
const NIX_BUILD_ENV: &str = "SODABOX_NIX_BUILD";

fn guest_nix_dir() -> PathBuf {
    if let Some(d) = std::env::var_os(GUEST_NIX_DIR_ENV) {
        return PathBuf::from(d);
    }
    // Dev fallback: the repo checkout next to this crate.
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../nix/guest"))
}

fn nix_build_bin() -> OsString {
    std::env::var_os(NIX_BUILD_ENV).unwrap_or_else(|| OsString::from("nix-build"))
}

/// The store paths produced by `mkGuest` for one guest.
#[derive(Debug, Clone)]
pub struct BuiltGuest {
    /// Kernel derivation dir; the bzImage is `kernel/bzImage`.
    pub kernel: PathBuf,
    /// Initrd derivation dir; the image is `initrd/initrd`.
    pub initrd: PathBuf,
    /// The read-only erofs `/nix/store` image (a file).
    pub store: PathBuf,
    /// System toplevel dir; stage-2 init is `toplevel/init`.
    pub toplevel: PathBuf,
}

/// The `mkGuest` attributes we realise, in the order `nix-build` prints them.
const ATTRS: [&str; 4] = ["kernel", "initrd", "store", "toplevel"];

/// Build `guest_dir` via `mkGuest.nix`. Blocking (spawns `nix-build`); call from
/// `spawn_blocking` on an async runtime.
pub fn build_guest(guest_dir: &Path) -> anyhow::Result<BuiltGuest> {
    let mkguest = guest_nix_dir().join("mkGuest.nix");
    if !mkguest.is_file() {
        anyhow::bail!(
            "mkGuest.nix not found at {} (set {GUEST_NIX_DIR_ENV})",
            mkguest.display()
        );
    }
    if !guest_dir.join("configuration.nix").is_file() {
        anyhow::bail!(
            "no guest configuration at {} — run `soda create` first",
            guest_dir.display()
        );
    }

    let mut cmd = Command::new(nix_build_bin());
    cmd.arg(&mkguest)
        .arg("--no-out-link")
        // The guest's configuration.nix may consume flake inputs pinned via
        // npins through `builtins.getFlake` (e.g. the default guest pulls the
        // llm-agents overlay this way). getFlake needs the flakes feature, so
        // enable it for the build regardless of the host's nix.conf default.
        .arg("--extra-experimental-features")
        .arg("nix-command flakes")
        .arg("--argstr")
        .arg("guestDir")
        .arg(guest_dir);
    for a in ATTRS {
        cmd.arg("-A").arg(a);
    }

    let out = cmd.output().map_err(|e| {
        anyhow::anyhow!(
            "failed to run nix-build ({}): {e}",
            nix_build_bin().to_string_lossy()
        )
    })?;
    if !out.status.success() {
        anyhow::bail!(
            "nix-build failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    // One realised store path per -A, in attribute order.
    let paths: Vec<PathBuf> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect();
    if paths.len() != ATTRS.len() {
        anyhow::bail!(
            "nix-build returned {} paths, expected {} ({:?})",
            paths.len(),
            ATTRS.len(),
            paths
        );
    }

    Ok(BuiltGuest {
        kernel: paths[0].clone(),
        initrd: paths[1].clone(),
        store: paths[2].clone(),
        toplevel: paths[3].clone(),
    })
}

impl BuiltGuest {
    /// The direct-kernel-boot cmdline for this guest: serial console, fstab from
    /// base.nix, and stage-2 init from the toplevel.
    pub fn cmdline(&self) -> String {
        format!(
            "console=ttyS0 root=fstab loglevel=4 init={}/init",
            self.toplevel.display()
        )
    }

    /// Adapt into a launchable [`GuestBoot`]. Disks are attached in a fixed order
    /// so guest device names are deterministic: store (`/dev/vda`), then the
    /// read-only config disk (`/dev/vdb`, ADR-0011) when present, then the
    /// read-write data disk (`/dev/vdc`) and home disk (`/dev/vdd`, ADR-0014)
    /// when present. `net_socket` stays `None` until passt is wired.
    #[allow(clippy::too_many_arguments)]
    pub fn to_boot(
        &self,
        cpus: u32,
        mem_mib: u64,
        config_img: Option<PathBuf>,
        disks: LaunchDisks,
        net_socket: Option<PathBuf>,
        api_socket: Option<PathBuf>,
        serial: Serial,
    ) -> GuestBoot {
        let mut attached = vec![Disk::store(&self.store)];
        if let Some(cfg) = config_img {
            attached.push(Disk::config(cfg));
        }
        if let Some(img) = disks.data {
            attached.push(Disk::data(img));
        }
        if let Some(img) = disks.home {
            debug_assert_eq!(attached.len(), 3, "home disk must land on /dev/vdd");
            attached.push(Disk::data(img));
        }
        GuestBoot {
            kernel: self.kernel.join("bzImage"),
            initramfs: self.initrd.join("initrd"),
            cmdline: self.cmdline(),
            cpus,
            mem_mib,
            disks: attached,
            net_socket,
            api_socket,
            serial,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn built() -> BuiltGuest {
        BuiltGuest {
            kernel: PathBuf::from("/nix/store/aaa-linux"),
            initrd: PathBuf::from("/nix/store/bbb-initrd"),
            store: PathBuf::from("/nix/store/ccc-store.erofs"),
            toplevel: PathBuf::from("/nix/store/ddd-toplevel"),
        }
    }

    #[test]
    fn cmdline_points_init_at_toplevel() {
        assert_eq!(
            built().cmdline(),
            "console=ttyS0 root=fstab loglevel=4 init=/nix/store/ddd-toplevel/init"
        );
    }

    #[test]
    fn boot_maps_paths_and_disks() {
        let b = built().to_boot(
            2,
            2048,
            Some(PathBuf::from("/run/config.img")),
            LaunchDisks {
                data: Some(PathBuf::from("/data/data.img")),
                home: None,
            },
            None,
            Some(PathBuf::from("/run/api.sock")),
            Serial::Stdio,
        );
        assert_eq!(b.kernel, PathBuf::from("/nix/store/aaa-linux/bzImage"));
        assert_eq!(b.initramfs, PathBuf::from("/nix/store/bbb-initrd/initrd"));
        // Fixed order: store (vda, RO), config (vdb, RO), data (vdc, RW).
        assert_eq!(b.disks.len(), 3);
        assert!(b.disks[0].readonly);
        assert_eq!(b.disks[0].path, PathBuf::from("/nix/store/ccc-store.erofs"));
        assert!(b.disks[1].readonly);
        assert_eq!(b.disks[1].path, PathBuf::from("/run/config.img"));
        assert!(!b.disks[2].readonly);
        assert_eq!(b.disks[2].path, PathBuf::from("/data/data.img"));
    }

    #[test]
    fn home_disk_is_vdd() {
        let b = built().to_boot(
            2,
            2048,
            Some(PathBuf::from("/run/config.img")),
            LaunchDisks {
                data: Some(PathBuf::from("/data/data.img")),
                home: Some(PathBuf::from("/data/home.img")),
            },
            None,
            None,
            Serial::Null,
        );
        // store, config, data (vdc), home (vdd, RW).
        assert_eq!(b.disks.len(), 4);
        assert_eq!(b.disks[2].path, PathBuf::from("/data/data.img"));
        assert_eq!(b.disks[3].path, PathBuf::from("/data/home.img"));
        assert!(!b.disks[3].readonly);
        // The guest layout is static: nothing mode-specific on the cmdline.
        assert_eq!(b.cmdline, built().cmdline());
    }

    #[test]
    fn boot_config_is_vdb_even_without_data() {
        // Config must stay the second disk regardless of a data disk, so its
        // guest device name (/dev/vdb) is deterministic.
        let b = built().to_boot(
            1,
            1024,
            Some(PathBuf::from("/run/config.img")),
            LaunchDisks::default(),
            None,
            None,
            Serial::Null,
        );
        assert_eq!(b.disks.len(), 2);
        assert!(b.disks[1].readonly);
        assert_eq!(b.disks[1].path, PathBuf::from("/run/config.img"));
    }

    #[test]
    fn boot_without_extra_disks_has_only_store() {
        let b = built().to_boot(
            1,
            1024,
            None,
            LaunchDisks::default(),
            None,
            None,
            Serial::Null,
        );
        assert_eq!(b.disks.len(), 1);
        assert!(b.disks[0].readonly);
    }
}
