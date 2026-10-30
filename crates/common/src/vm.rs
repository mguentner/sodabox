//! Per-VM metadata (`meta.toml`), written by `sodabox create` and read by
//! `start`/`ls` (ADR-0007/0008). Human-editable TOML, one file per VM.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{paths, ssh, storage};

/// Default size of a VM's home disk (`home.img`). Sparse, so it costs only what
/// the home actually holds.
pub const DEFAULT_HOME_DISK: &str = "1G";

/// What a VM keeps across a stop (ADR-0014).
///
/// Every VM has the same two read-write disks, so the guest layout never
/// depends on the mode: `data.img` (`/persistent`: writable store, work tree)
/// and `home.img` (`/persistent/home`: `/root` and the sshd host key). The mode
/// only decides which of them are **scratch** — a fresh sparse file made at
/// every start and deleted at stop — rather than kept. The guest always runs on
/// disk, never on a RAM disk; but a stopped VM costs no space for its scratch
/// disks, so the combined `--disk` sizes of all VMs may exceed the free space
/// as long as only some of them run at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Persist {
    /// Both disks are kept: home, writable store and work tree all survive
    /// (ADR-0008).
    #[default]
    Full,
    /// Only the home disk is kept — `/root` (tool config) and sodabox's own
    /// guest state (the sshd host key); `data.img` is scratch.
    Home,
    /// Nothing guest-side survives: both disks are scratch. The sshd host key is
    /// held by the host instead (see [`ssh::pinned_guest_host_key`]).
    None,
}

impl Persist {
    pub fn as_str(self) -> &'static str {
        match self {
            Persist::Full => "full",
            Persist::Home => "home",
            Persist::None => "none",
        }
    }

    /// Whether `data.img` is scratch (recreated each start, deleted at stop).
    pub fn scratch_data(self) -> bool {
        self != Persist::Full
    }

    /// Whether `home.img` is scratch (recreated each start, deleted at stop).
    pub fn scratch_home(self) -> bool {
        self == Persist::None
    }
}

impl fmt::Display for Persist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for Persist {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "full" => Ok(Persist::Full),
            "home" => Ok(Persist::Home),
            "none" => Ok(Persist::None),
            other => Err(format!(
                "unknown persist mode '{other}' (expected full, home or none)"
            )),
        }
    }
}

/// The read-write disks of one launch, from [`VmMeta::prepare_disks`]. Either
/// both are present or neither (a diskless debug boot), so the guest device
/// names are fixed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchDisks {
    /// `data.img`, mounted at `/persistent` (→ `/dev/vdc`).
    pub data: Option<PathBuf>,
    /// `home.img`, mounted at `/persistent/home` (→ `/dev/vdd`).
    pub home: Option<PathBuf>,
}

/// Contents of `<data-dir>/<vm>/meta.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmMeta {
    pub name: String,
    pub cpus: u32,
    /// Guest RAM, human size (e.g. `"2048M"`), parsed via `storage::parse_size`.
    pub mem: String,
    /// Data disk size, human size (e.g. `"8G"`).
    pub disk: String,
    /// Host-loopback port of this VM's SSH forward (ADR-0011), assigned
    /// at `create` and then **owned by this VM for its lifetime**. Keeping the
    /// assignment in state is what makes the port stable across restarts and
    /// unique across VMs — nothing is derived or probed per boot.
    pub ssh_port: u16,
    /// What survives a stop (ADR-0014).
    pub persist: Persist,
    /// Size of the home disk (`home.img`, `/persistent/home`); unset means
    /// [`DEFAULT_HOME_DISK`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_disk: Option<String>,
    /// The dotfile collections merged at `create`, in order (ADR-0019). A record
    /// only: the VM's `dotfiles/` copy is what it gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dotfiles: Vec<String>,
    /// Unix seconds at creation.
    pub created: u64,
}

impl VmMeta {
    /// The home disk size (`home.img`).
    pub fn home_disk(&self) -> &str {
        self.home_disk.as_deref().unwrap_or(DEFAULT_HOME_DISK)
    }

    /// Get both read-write disks ready for a launch (ADR-0014). Call with the
    /// data-disk lock held (`storage::DataImgLock`), since this deletes and
    /// recreates scratch disks.
    ///
    /// A kept disk is used as is (created blank if missing); a scratch disk is
    /// always replaced by a blank one — which also reclaims a scratch disk left
    /// behind by a crashed supervisor. The guest formats blank disks on boot.
    ///
    /// The one exception: a `full` VM whose `data.img` is gone boots diskless,
    /// as before, rather than silently starting over on an empty disk.
    pub fn prepare_disks(&self) -> io::Result<LaunchDisks> {
        self.prepare_disks_in(&paths::data_dir(&self.name))
    }

    /// [`VmMeta::prepare_disks`] against an explicit data dir (hermetic; tests).
    pub fn prepare_disks_in(&self, dir: &Path) -> io::Result<LaunchDisks> {
        let data = dir.join(storage::DATA_IMG);
        let home = dir.join(storage::HOME_IMG);
        if !self.persist.scratch_data() && !data.exists() {
            return Ok(LaunchDisks::default());
        }
        prepare_disk(&data, &self.disk, self.persist.scratch_data())?;
        prepare_disk(&home, self.home_disk(), self.persist.scratch_home())?;
        Ok(LaunchDisks {
            data: Some(data),
            home: Some(home),
        })
    }

    /// Delete the scratch disks after the VM has exited (ADR-0014), freeing
    /// their host space. Kept disks are never touched.
    pub fn discard_scratch(&self) -> io::Result<()> {
        self.discard_scratch_in(&paths::data_dir(&self.name))
    }

    /// [`VmMeta::discard_scratch`] against an explicit data dir (tests).
    pub fn discard_scratch_in(&self, dir: &Path) -> io::Result<()> {
        if self.persist.scratch_data() {
            remove_if_present(&dir.join(storage::DATA_IMG))?;
        }
        if self.persist.scratch_home() {
            remove_if_present(&dir.join(storage::HOME_IMG))?;
        }
        Ok(())
    }

    pub fn path(vm: &str) -> PathBuf {
        paths::data_dir(vm).join("meta.toml")
    }

    /// Load `meta.toml` for `vm`. A missing file surfaces as `NotFound`.
    pub fn load(vm: &str) -> io::Result<VmMeta> {
        let text = std::fs::read_to_string(Self::path(vm))?;
        toml::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Enumerate all VMs under the data root (`sodabox ls`), sorted by name. A
    /// directory is a VM iff it holds a readable `meta.toml`; anything else is
    /// skipped. A missing data root just means no VMs yet.
    pub fn list() -> io::Result<Vec<VmMeta>> {
        Self::list_in(&paths::data_root())
    }

    /// [`VmMeta::list`] against an explicit data root (hermetic; used by tests).
    pub fn list_in(root: &Path) -> io::Result<Vec<VmMeta>> {
        let entries = match std::fs::read_dir(root) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let meta = entry.path().join("meta.toml");
            if let Ok(text) = std::fs::read_to_string(&meta) {
                if let Ok(m) = toml::from_str::<VmMeta>(&text) {
                    out.push(m);
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Pick an SSH forward port for VM `name`, avoiding everything in `taken`,
    /// with a message that says what the range is when it is full. Allocation
    /// is the lowest port in the range no *other* VM is assigned (see
    /// [`VmMeta::ssh_ports_taken`]), so it never collides with a VM that happens
    /// to be stopped. Does **not** persist — the caller saves, which is what
    /// makes the assignment durable.
    pub fn allocate_ssh_port(name: &str, taken: &[u16]) -> io::Result<u16> {
        crate::ssh::allocate_port(taken, ssh::HOST_SSH_BASE_PORT, ssh::HOST_SSH_PORTS).ok_or_else(
            || {
                io::Error::other(format!(
                    "no free host SSH port for '{}' in {}..{} — {} already taken; \
                     remove an unused VM (`sodabox rm`) to free one",
                    name,
                    ssh::HOST_SSH_BASE_PORT,
                    ssh::HOST_SSH_BASE_PORT + ssh::HOST_SSH_PORTS - 1,
                    taken.len(),
                ))
            },
        )
    }

    /// The SSH ports every VM *except* `except` has assigned — the allocator's
    /// state, read straight from the on-disk metadata.
    pub fn ssh_ports_taken(except: &str) -> io::Result<Vec<u16>> {
        Self::ssh_ports_taken_in(&paths::data_root(), except)
    }

    /// [`VmMeta::ssh_ports_taken`] against an explicit data root (hermetic; tests).
    pub fn ssh_ports_taken_in(root: &Path, except: &str) -> io::Result<Vec<u16>> {
        Ok(Self::list_in(root)?
            .into_iter()
            .filter(|m| m.name != except)
            .map(|m| m.ssh_port)
            .collect())
    }

    /// Serialize to the VM's `meta.toml` (creating the data dir if needed).
    pub fn save(&self) -> io::Result<()> {
        let path = Self::path(&self.name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = toml::to_string(self).map_err(io::Error::other)?;
        std::fs::write(path, format!("# sodabox VM metadata\n{body}"))
    }
}

/// A disk of human `size` at `path`: replaced by a blank one if `scratch`,
/// otherwise kept (created blank only if missing).
fn prepare_disk(path: &Path, size: &str, scratch: bool) -> io::Result<()> {
    if !scratch {
        return storage::ensure_sparse(path, size).map(|_| ());
    }
    let bytes = storage::parse_size(size).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("size of {}: {e}", path.display()),
        )
    })?;
    storage::recreate_sparse(path, bytes).map(|_| ())
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = VmMeta {
            name: "demo".into(),
            cpus: 2,
            mem: "2048M".into(),
            disk: "8G".into(),
            ssh_port: 3522,
            persist: Persist::Full,
            home_disk: None,
            dotfiles: Vec::new(),
            created: 1_700_000_000,
        };
        let text = toml::to_string(&m).unwrap();
        assert!(text.contains("ssh_port = 3522"));
        // An empty dotfiles list is left out of the file.
        assert!(!text.contains("dotfiles"));
        let back: VmMeta = toml::from_str(&text).unwrap();
        assert_eq!(back.name, "demo");
        assert_eq!(back.cpus, 2);
        assert_eq!(back.mem, "2048M");
        assert_eq!(back.disk, "8G");
        assert_eq!(back.created, 1_700_000_000);
    }

    fn write_vm(root: &Path, name: &str) {
        write_vm_port(root, name, ssh::HOST_SSH_BASE_PORT);
    }

    fn write_vm_port(root: &Path, name: &str, ssh_port: u16) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let m = VmMeta {
            name: name.into(),
            cpus: 1,
            mem: "512M".into(),
            disk: "1G".into(),
            ssh_port,
            persist: Persist::Full,
            home_disk: None,
            dotfiles: Vec::new(),
            created: 0,
        };
        std::fs::write(dir.join("meta.toml"), toml::to_string(&m).unwrap()).unwrap();
    }

    fn meta(name: &str, ssh_port: u16) -> VmMeta {
        VmMeta {
            name: name.into(),
            cpus: 1,
            mem: "512M".into(),
            disk: "1G".into(),
            ssh_port,
            persist: Persist::Full,
            home_disk: None,
            dotfiles: Vec::new(),
            created: 0,
        }
    }

    #[test]
    fn persist_roundtrips_through_toml_and_str() {
        for mode in [Persist::Full, Persist::Home, Persist::None] {
            let mut m = meta("demo", ssh::HOST_SSH_BASE_PORT);
            m.persist = mode;
            let text = toml::to_string(&m).unwrap();
            assert!(text.contains(&format!("persist = \"{mode}\"")), "{text}");
            let back: VmMeta = toml::from_str(&text).unwrap();
            assert_eq!(back.persist, mode);
            assert_eq!(mode.as_str().parse::<Persist>().unwrap(), mode);
        }
        assert!("ephemeral".parse::<Persist>().is_err());
        // Which disks are scratch, per mode.
        let scratch = |p: Persist| (p.scratch_data(), p.scratch_home());
        assert_eq!(scratch(Persist::Full), (false, false));
        assert_eq!(scratch(Persist::Home), (true, false));
        assert_eq!(scratch(Persist::None), (true, true));
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sodabox-disks-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn full_mode_keeps_both_disks() {
        let dir = scratch_dir("full");
        let m = meta("demo", ssh::HOST_SSH_BASE_PORT);
        let (data, home) = (dir.join(storage::DATA_IMG), dir.join(storage::HOME_IMG));
        // No data.img: a diskless boot, nothing created behind the user's back.
        assert_eq!(m.prepare_disks_in(&dir).unwrap(), LaunchDisks::default());
        assert!(!data.exists() && !home.exists());

        // An existing data.img is the VM's state: attached unchanged, with its
        // home disk (made on first use), and neither is discarded at stop.
        std::fs::write(&data, b"state").unwrap();
        let d = m.prepare_disks_in(&dir).unwrap();
        assert_eq!(
            d,
            LaunchDisks {
                data: Some(data.clone()),
                home: Some(home.clone())
            }
        );
        std::fs::write(&home, b"config").unwrap();
        m.discard_scratch_in(&dir).unwrap();
        m.prepare_disks_in(&dir).unwrap();
        assert_eq!(std::fs::read(&data).unwrap(), b"state");
        assert_eq!(std::fs::read(&home).unwrap(), b"config");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn home_mode_recreates_data_and_keeps_home() {
        let dir = scratch_dir("home");
        let mut m = meta("demo", ssh::HOST_SSH_BASE_PORT);
        m.persist = Persist::Home;
        m.disk = "16M".into();
        m.home_disk = Some("4M".into());
        let (data, home) = (dir.join(storage::DATA_IMG), dir.join(storage::HOME_IMG));

        let d = m.prepare_disks_in(&dir).unwrap();
        assert_eq!(
            d,
            LaunchDisks {
                data: Some(data.clone()),
                home: Some(home.clone())
            }
        );
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 16 << 20);
        assert_eq!(std::fs::metadata(&home).unwrap().len(), 4 << 20);

        // Guest writes land on both disks...
        std::fs::write(&data, b"scratch").unwrap();
        std::fs::write(&home, b"config").unwrap();
        // ...stop drops the data disk but never the home.
        m.discard_scratch_in(&dir).unwrap();
        assert!(!data.exists());
        assert_eq!(std::fs::read(&home).unwrap(), b"config");

        // A data disk left by a crash is replaced by a blank one at next start.
        std::fs::write(&data, b"stale").unwrap();
        m.prepare_disks_in(&dir).unwrap();
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 16 << 20);
        assert_ne!(std::fs::read(&data).unwrap()[..5], *b"stale");
        assert_eq!(std::fs::read(&home).unwrap(), b"config");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn none_mode_recreates_and_discards_both_disks() {
        let dir = scratch_dir("none");
        let mut m = meta("demo", ssh::HOST_SSH_BASE_PORT);
        m.persist = Persist::None;
        m.disk = "8M".into();
        let (data, home) = (dir.join(storage::DATA_IMG), dir.join(storage::HOME_IMG));

        // Left over from a crash: both are replaced by blank disks.
        std::fs::write(&home, b"stale").unwrap();
        let d = m.prepare_disks_in(&dir).unwrap();
        assert_eq!(
            d,
            LaunchDisks {
                data: Some(data.clone()),
                home: Some(home.clone())
            }
        );
        assert_ne!(std::fs::read(&home).unwrap()[..5], *b"stale");

        m.discard_scratch_in(&dir).unwrap();
        assert!(!data.exists() && !home.exists());
        // Discarding twice (nothing left) is fine.
        m.discard_scratch_in(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn ssh_ports_taken_reads_other_vms_assignments() {
        let root = std::env::temp_dir().join(format!("sodabox-ports-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        write_vm_port(&root, "alpha", 3522);
        write_vm_port(&root, "beta", 3524);

        // Every other VM's port, excluding the VM doing the asking.
        let mut taken = VmMeta::ssh_ports_taken_in(&root, "beta").unwrap();
        taken.sort_unstable();
        assert_eq!(taken, vec![3522]);

        let mut all = VmMeta::ssh_ports_taken_in(&root, "none").unwrap();
        all.sort_unstable();
        assert_eq!(all, vec![3522, 3524]);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn allocate_ssh_port_fills_the_lowest_gap_and_reports_exhaustion() {
        let base = ssh::HOST_SSH_BASE_PORT;
        assert_eq!(VmMeta::allocate_ssh_port("demo", &[]).unwrap(), base);
        assert_eq!(
            VmMeta::allocate_ssh_port("demo", &[base, base + 2]).unwrap(),
            base + 1
        );

        let full: Vec<u16> = (0..ssh::HOST_SSH_PORTS).map(|i| base + i).collect();
        let err = VmMeta::allocate_ssh_port("demo", &full).unwrap_err();
        assert!(err.to_string().contains("no free host SSH port"), "{err}");
    }

    #[test]
    fn list_finds_only_vm_dirs_sorted() {
        let root = std::env::temp_dir().join(format!("sodabox-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        // Missing root -> empty, not an error.
        assert!(VmMeta::list_in(&root).unwrap().is_empty());

        write_vm(&root, "beta");
        write_vm(&root, "alpha");
        // A stray file and a dir without meta.toml must be ignored.
        std::fs::write(root.join("loose.txt"), "x").unwrap();
        std::fs::create_dir_all(root.join("notavm")).unwrap();

        let vms = VmMeta::list_in(&root).unwrap();
        let names: Vec<_> = vms.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["alpha", "beta"]);

        std::fs::remove_dir_all(&root).unwrap();
    }
}
