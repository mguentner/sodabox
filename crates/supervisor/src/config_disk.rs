//! Per-VM config disk (ADR-0011): a tiny read-only erofs image,
//! built at launch, carrying host→guest launch data the guest reads. Today that
//! is just `ssh/authorized_keys` (the tool pubkey, nothing else); it is
//! attached as the guest's **second** virtio-blk disk (→ `/dev/vdb`) and mounted
//! read-only. Rebuilding it every launch means key changes take effect
//! immediately, without rebuilding the immutable store image.
//!
//! For a VM that keeps no guest state (`persist = "none"`, ADR-0014) it also
//! carries the VM's host-held sshd host key (`ssh/ssh_host_ed25519_key`, 0600),
//! which the guest installs before sshd starts.
//!
//! A VM created with dotfile collections (ADR-0019) also gets its `dotfiles/`
//! copy here, under `dotfiles/`, which the guest copies into `/root` once.

use std::path::Path;
use std::process::Command;

/// Environment override for `mkfs.erofs` (pinned on PATH by the wrapper).
const MKFS_EROFS_ENV: &str = "SODABOX_MKFS_EROFS";

fn mkfs_erofs_bin() -> std::ffi::OsString {
    std::env::var_os(MKFS_EROFS_ENV).unwrap_or_else(|| "mkfs.erofs".into())
}

/// The `mkfs.erofs` argv (pure; unit-tested). `--all-root` forces every file in
/// the image to be owned by **root** (uid/gid 0) regardless of who runs the
/// (rootless) supervisor. This is essential for `ssh/authorized_keys`: the guest
/// sshd enforces `StrictModes`, which refuses an `authorized_keys` (or a parent
/// dir) not owned by root or the login user — so without `--all-root` the image
/// carries the invoking user's uid, which is not root inside the guest, and every
/// `sodabox ssh` fails with `Permission denied (publickey)`.
fn mkfs_erofs_args(out: &Path, staging: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "--all-root".into(),
        out.as_os_str().to_os_string(),
        staging.as_os_str().to_os_string(),
    ]
}

/// Build the config disk at `out` from `authorized_keys` content and an optional
/// sshd `host_key` (private key text) and an optional `dotfiles` tree,
/// overwriting any existing image (the
/// content is regenerated every launch). The image is left mode 0600, as it may
/// hold that private key. Blocking — spawns `mkfs.erofs`; call from
/// `spawn_blocking` on an async runtime.
pub fn build_config_disk(
    out: &Path,
    authorized_keys: &str,
    host_key: Option<&str>,
    dotfiles: Option<&Path>,
) -> anyhow::Result<()> {
    // erofs images a source directory; stage the tree next to the output image.
    let staging = out.with_extension("stage");
    let _ = std::fs::remove_dir_all(&staging);
    let ssh_dir = staging.join("ssh");
    std::fs::create_dir_all(&ssh_dir)?;
    let ak = ssh_dir.join("authorized_keys");
    std::fs::write(&ak, authorized_keys)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ak, std::fs::Permissions::from_mode(0o444))?;
    }
    if let Some(key) = host_key {
        let path = ssh_dir.join("ssh_host_ed25519_key");
        std::fs::write(&path, key)?;
        // sshd refuses a host key readable by anyone but root; erofs keeps the
        // mode and `--all-root` the owner.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    if let Some(dir) = dotfiles {
        // Modes are kept (a 0600 credentials file stays 0600); `--all-root`
        // makes everything root-owned in the guest.
        sodabox_common::dotfiles::copy_tree(dir, &staging.join("dotfiles"))
            .map_err(|e| anyhow::anyhow!("staging dotfiles from {}: {e}", dir.display()))?;
    }

    // mkfs.erofs refuses to overwrite an existing target; clear it first.
    let _ = std::fs::remove_file(out);
    let output = Command::new(mkfs_erofs_bin())
        .args(mkfs_erofs_args(out, &staging))
        .output()
        .map_err(|e| anyhow::anyhow!("running mkfs.erofs: {e}"))?;
    let _ = std::fs::remove_dir_all(&staging);
    if !output.status.success() {
        anyhow::bail!(
            "mkfs.erofs failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn which(name: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|d| d.join(name))
            .find(|p| p.exists())
    }

    #[test]
    fn args_force_root_ownership() {
        let args: Vec<String> = mkfs_erofs_args(Path::new("/out.img"), Path::new("/stage"))
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // --all-root must be present so the guest sshd's StrictModes accepts the
        // config disk's authorized_keys (owned by root, not the rootless user).
        assert!(
            args.contains(&"--all-root".to_string()),
            "missing --all-root: {args:?}"
        );
        // Output image before the source directory (mkfs.erofs argument order).
        let out = args.iter().position(|a| a == "/out.img").unwrap();
        let stage = args.iter().position(|a| a == "/stage").unwrap();
        assert!(out < stage);
    }

    #[test]
    fn builds_a_nonempty_erofs_image() {
        if which("mkfs.erofs").is_none() {
            eprintln!("mkfs.erofs not found; skipping");
            return;
        }
        let dir = std::env::temp_dir().join(format!("sodabox-cfgdisk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("config.img");

        let dotfiles = dir.join("dotfiles");
        std::fs::create_dir_all(dotfiles.join(".claude")).unwrap();
        std::fs::write(dotfiles.join(".claude/settings.json"), "{}").unwrap();

        build_config_disk(
            &out,
            "ssh-ed25519 AAAA sodabox\n",
            Some("PRIVATE KEY\n"),
            Some(&dotfiles),
        )
        .unwrap();
        let len = std::fs::metadata(&out).unwrap().len();
        assert!(len > 0, "config image is empty");
        // The erofs magic (0xE0F5E1E2, little-endian) sits at offset 1024.
        let bytes = std::fs::read(&out).unwrap();
        assert!(bytes.len() > 1028);
        assert_eq!(&bytes[1024..1028], &[0xe2, 0xe1, 0xf5, 0xe0]);
        // The staging tree is cleaned up.
        assert!(!out.with_extension("stage").exists());
        // It may carry a private host key: owner-only.
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
