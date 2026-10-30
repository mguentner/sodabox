//! Per-VM persistent data disk (ADR-0008).
//!
//! The data disk is a plain, user-owned **sparse raw** file — no loop devices,
//! no LVM, no qcow2. It is created at `soda create` with a user-specified
//! size, attached read-write over virtio-blk by the supervisor (via
//! `chv::Disk::data`), and can be grown later. Being sparse, an 8G disk that is
//! mostly empty costs only its actually-written blocks on the host.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

use crate::paths;

/// File name of the data disk (`/persistent`, → `/dev/vdc`) in a VM's data dir.
/// Persistent for `persist = "full"`, a scratch disk otherwise (ADR-0014).
pub const DATA_IMG: &str = "data.img";
/// File name of the kept home disk of a `persist = "home"` VM (→ `/dev/vdd`,
/// ADR-0014).
pub const HOME_IMG: &str = "home.img";

/// `$XDG_DATA_HOME/sodabox/<vm>/data.img`.
pub fn data_img_path(vm: &str) -> PathBuf {
    paths::data_dir(vm).join(DATA_IMG)
}

/// `$XDG_DATA_HOME/sodabox/<vm>/home.img`.
pub fn home_img_path(vm: &str) -> PathBuf {
    paths::data_dir(vm).join(HOME_IMG)
}

/// `$XDG_DATA_HOME/sodabox/<vm>/data.img.lock` — the advisory lock guarding the
/// data disk against double-attach (ADR-0008; see [`DataImgLock`]).
pub fn data_img_lock_path(vm: &str) -> PathBuf {
    paths::data_dir(vm).join("data.img.lock")
}

/// An exclusive advisory (`flock`) lock held for the lifetime of a running VM so
/// that two supervisors cannot attach the same `data.img` (ADR-0008).
/// The lock lives on a sidecar `data.img.lock` file, so it never
/// interferes with cloud-hypervisor opening the image itself.
///
/// Robustness: the kernel releases an `flock` when the last descriptor of its
/// open file description is closed, so a crashed supervisor leaves **no stale
/// lock** — no PID files or cleanup needed. Dropping this guard in the owning
/// process releases the lock.
///
/// **Fork caveat:** a forked child shares the same open file description, so it
/// must **not** run this guard's destructor — that would `LOCK_UN` the shared
/// description and release the *parent's* lock too. The supervisor's netns child
/// exits via `process::exit`, which skips destructors, so it simply leaves the
/// guard untouched (see `supervise::run`).
#[derive(Debug)]
pub struct DataImgLock {
    // Held solely for its `Drop` (unlock-on-close); never read directly.
    #[allow(dead_code)]
    lock: Flock<std::fs::File>,
    path: PathBuf,
}

impl DataImgLock {
    /// Take the data-disk lock for `vm`. Returns `Ok(None)` when the VM does not
    /// exist (no data dir: nothing to guard), `Ok(Some(_))` on success, and an
    /// error of kind [`io::ErrorKind::WouldBlock`] when another supervisor
    /// already holds it.
    ///
    /// The guard is the VM's data dir rather than `data.img` itself: a scratch
    /// `data.img` (ADR-0014) does not exist between runs, yet must be created
    /// under this very lock so two starts can't recreate it under each other.
    pub fn acquire(vm: &str) -> io::Result<Option<DataImgLock>> {
        Self::acquire_at(
            &paths::data_dir(vm),
            &data_img_lock_path(vm),
            &format!("VM '{vm}'"),
        )
    }

    /// [`DataImgLock::acquire`] against explicit paths (hermetic; used by tests).
    /// Locks only when `guarded` exists.
    fn acquire_at(
        guarded: &Path,
        lock_path: &Path,
        label: &str,
    ) -> io::Result<Option<DataImgLock>> {
        // No VM means there is nothing to protect against double-attach.
        if !guarded.exists() {
            return Ok(None);
        }
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => Ok(Some(DataImgLock { lock, path: lock_path.to_path_buf() })),
            // EWOULDBLOCK (== EAGAIN on Linux) means another holder has it.
            Err((_file, e)) if e == Errno::EWOULDBLOCK => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "data disk for {label} is already in use by a running supervisor (locked at {})",
                    lock_path.display()
                ),
            )),
            Err((_file, errno)) => {
                Err(io::Error::other(format!("locking {}: {errno}", lock_path.display())))
            }
        }
    }

    /// The sidecar lock file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Parse a human disk size (`"8G"`, `"512M"`, `"2048"`) into bytes.
///
/// Suffixes are binary (1024-based): `K`/`M`/`G`/`T`, optionally followed by `B`
/// (so `8G`, `8GB`, and `8GiB` are equal). A bare number is bytes. The value
/// must be positive and a whole number of bytes.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".to_string());
    }

    // Split leading digits from the unit.
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    if num.is_empty() {
        return Err(format!("invalid size '{s}': expected a leading number"));
    }
    let value: u64 = num
        .parse()
        .map_err(|_| format!("invalid size '{s}': number too large"))?;

    // Normalize the unit: strip an optional trailing 'B'/'iB', case-insensitive.
    let u = unit.trim().to_ascii_uppercase();
    let u = u
        .strip_suffix("IB")
        .or_else(|| u.strip_suffix('B'))
        .unwrap_or(&u);
    let mult: u64 = match u {
        "" => 1,
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        "T" => 1 << 40,
        other => return Err(format!("invalid size '{s}': unknown unit '{other}'")),
    };

    let bytes = value
        .checked_mul(mult)
        .ok_or_else(|| format!("size '{s}' overflows u64"))?;
    if bytes == 0 {
        return Err(format!("invalid size '{s}': must be greater than zero"));
    }
    Ok(bytes)
}

/// Parse a human memory size into whole **MiB**. Unlike [`parse_size`], a bare
/// number is MiB, not bytes: `"8192"` and `"8G"` both mean 8192 MiB — matching
/// how a VM's RAM is quoted (and how cloud-hypervisor's `size=` is expressed).
/// A unit-carrying value is parsed as bytes and converted down to MiB. The
/// result must be at least 1 MiB (a VM cannot boot with `size=0M`).
pub fn parse_mem_mib(s: &str) -> Result<u64, String> {
    let t = s.trim();
    // Bare number ⇒ MiB directly (the common `--mem 8192` case; parsing it as
    // bytes and shifting right by 20 would truncate to 0 and wedge the boot).
    if !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit()) {
        let mib: u64 = t
            .parse()
            .map_err(|_| format!("invalid memory '{s}': number too large"))?;
        if mib == 0 {
            return Err(format!("invalid memory '{s}': must be greater than zero"));
        }
        return Ok(mib);
    }
    // Unit-carrying ⇒ bytes, floored to MiB.
    let mib = parse_size(t)? >> 20;
    if mib == 0 {
        return Err(format!("invalid memory '{s}': must be at least 1 MiB"));
    }
    Ok(mib)
}

/// Create the sparse raw data image at `path` with `bytes` capacity, failing if
/// it already exists. Returns the number of bytes provisioned.
///
/// `set_len` on Linux extends the file as a hole, so no host blocks are
/// allocated until the guest writes.
pub fn create_sparse(path: &Path, bytes: u64) -> io::Result<u64> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.set_len(bytes)?;
    Ok(bytes)
}

/// Create the data image for `vm` if absent. Returns `(created, path)`; when
/// `created` is false the existing user-owned image is left untouched.
pub fn ensure_data_img(vm: &str, size: &str) -> io::Result<(bool, PathBuf)> {
    let path = data_img_path(vm);
    let created = ensure_sparse(&path, size)?;
    Ok((created, path))
}

/// Create the kept home disk for `vm` if absent (`persist = "home"`, ADR-0014).
/// Returns `(created, path)` like [`ensure_data_img`].
pub fn ensure_home_img(vm: &str, size: &str) -> io::Result<(bool, PathBuf)> {
    let path = home_img_path(vm);
    let created = ensure_sparse(&path, size)?;
    Ok((created, path))
}

/// Create a sparse image of human `size` at `path` unless one exists; returns
/// whether it was created. An existing image is never touched.
pub fn ensure_sparse(path: &Path, size: &str) -> io::Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    let bytes = parse_size(size).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    create_sparse(path, bytes)?;
    Ok(true)
}

/// Replace whatever is at `path` with a blank sparse image of `bytes` — the
/// scratch data disk of a `home`/`none` VM, fresh at every start (ADR-0014).
/// The guest formats it on boot (`x-systemd.makefs`), as for a new VM.
pub fn recreate_sparse(path: &Path, bytes: u64) -> io::Result<u64> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    create_sparse(path, bytes)
}

/// Grow the data image to `bytes`. Shrinking is refused — it would truncate a
/// filesystem the guest owns. Growing the host file only enlarges the block
/// device; the guest must still grow its own filesystem to use the new space.
pub fn grow(path: &Path, bytes: u64) -> io::Result<()> {
    let f = OpenOptions::new().write(true).open(path)?;
    let current = f.metadata()?.len();
    if bytes < current {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to shrink data disk from {current} to {bytes} bytes (data loss)"),
        ));
    }
    f.set_len(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_units() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("2048M").unwrap(), 2048 * (1 << 20));
        assert_eq!(parse_size("8G").unwrap(), 8 * (1 << 30));
        // Suffix spellings are equivalent.
        assert_eq!(parse_size("8GB").unwrap(), parse_size("8G").unwrap());
        assert_eq!(parse_size("8GiB").unwrap(), parse_size("8G").unwrap());
        assert_eq!(parse_size("1T").unwrap(), 1 << 40);
        // Case-insensitive, whitespace-tolerant.
        assert_eq!(parse_size(" 4g ").unwrap(), 4 * (1 << 30));
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(parse_size("").is_err());
        assert!(parse_size("G").is_err());
        assert!(parse_size("0").is_err());
        assert!(parse_size("0G").is_err());
        assert!(parse_size("8X").is_err());
        assert!(parse_size("1.5G").is_err());
    }

    #[test]
    fn parse_mem_mib_reads_bare_number_as_mib() {
        // a bare `--mem 8192` means 8192 MiB, not 8192 bytes (which
        // would floor to 0 MiB and wedge the boot with size=0M).
        assert_eq!(parse_mem_mib("8192").unwrap(), 8192);
        assert_eq!(parse_mem_mib("2048").unwrap(), 2048);
        // Unit-carrying values match and convert to MiB.
        assert_eq!(parse_mem_mib("8G").unwrap(), 8192);
        assert_eq!(parse_mem_mib("2048M").unwrap(), 2048);
        assert_eq!(parse_mem_mib(" 4g ").unwrap(), 4096);
        // Guard: must be at least 1 MiB, and junk is rejected.
        assert!(parse_mem_mib("0").is_err());
        assert!(parse_mem_mib("512K").is_err()); // < 1 MiB
        assert!(parse_mem_mib("").is_err());
        assert!(parse_mem_mib("8X").is_err());
    }

    fn scratch(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sodabox-storage-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn sparse_create_sets_len_and_is_exclusive() {
        let path = scratch("create");
        let bytes = 16 * (1 << 20);
        assert_eq!(create_sparse(&path, bytes).unwrap(), bytes);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), bytes);
        // Sparse: on-disk blocks are far smaller than the apparent size.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert!(
                meta.blocks() * 512 < bytes,
                "expected a hole, got fully allocated"
            );
        }
        // Second create must not clobber an existing image.
        assert!(create_sparse(&path, bytes).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn data_img_lock_excludes_a_second_holder() {
        let img = scratch("lock-img");
        std::fs::write(&img, b"disk").unwrap();
        let lock = scratch("lock-img.lock");

        // First holder wins.
        let g1 = DataImgLock::acquire_at(&img, &lock, "VM 'x'").unwrap();
        assert!(g1.is_some());

        // A second acquisition (a distinct open file description) is refused.
        let err = DataImgLock::acquire_at(&img, &lock, "VM 'x'").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        // Releasing the first lets the next caller in — no stale lock.
        drop(g1);
        let g3 = DataImgLock::acquire_at(&img, &lock, "VM 'x'").unwrap();
        assert!(g3.is_some());

        drop(g3);
        std::fs::remove_file(&img).unwrap();
        let _ = std::fs::remove_file(&lock);
    }

    #[test]
    fn data_img_lock_absent_without_a_vm() {
        let img = scratch("nolock-img"); // deliberately not created
        let lock = scratch("nolock-img.lock");
        // Nothing to guard => Ok(None), and no lock file created.
        assert!(DataImgLock::acquire_at(&img, &lock, "VM 'y'")
            .unwrap()
            .is_none());
        assert!(!lock.exists());
    }

    #[test]
    fn recreate_replaces_content_with_a_blank_sparse_image() {
        let path = scratch("recreate");
        // Absent: just created.
        recreate_sparse(&path, 1 << 20).unwrap();
        std::fs::write(&path, b"old scratch").unwrap();
        // Present: replaced by a blank image of the requested size.
        recreate_sparse(&path, 2 << 20).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 2 << 20);
        assert!(bytes.iter().all(|b| *b == 0));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn ensure_sparse_never_touches_an_existing_image() {
        let path = scratch("ensure");
        assert!(ensure_sparse(&path, "1M").unwrap());
        std::fs::write(&path, b"kept").unwrap();
        assert!(!ensure_sparse(&path, "4M").unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"kept");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn grow_extends_and_refuses_shrink() {
        let path = scratch("grow");
        create_sparse(&path, 8 * (1 << 20)).unwrap();
        grow(&path, 32 * (1 << 20)).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 32 * (1 << 20));
        assert!(grow(&path, 4 * (1 << 20)).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 32 * (1 << 20));
        std::fs::remove_file(&path).unwrap();
    }
}
