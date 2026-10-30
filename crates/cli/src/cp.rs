//! `sodabox cp <src> <dst>` — copy individual files between the host and a VM.
//!
//! Exactly one side is `<vm>:<path>`. Shells out to the system `scp` with the
//! same hardened, pinned-identity option set as `sodabox ssh` and sync
//! ([`sodabox_common::ssh::hardened_ssh_opts`], ADR-0011). Whole-tree transfer
//! stays with `sync-vm`/`sync-host`; this is for the odd single file. Relative
//! guest paths resolve against the guest work dir, not the login user's home.
//! Copying *into* the host asks before overwriting an existing path, since scp
//! itself overwrites silently.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sodabox_common::ssh::{hardened_ssh_opts, scp_bin, SshEndpoint};
use sodabox_common::vm::VmMeta;

use crate::sync::DEFAULT_REMOTE_DIR;

/// One `cp` operand.
#[derive(Debug, PartialEq, Eq)]
enum Operand {
    Local(PathBuf),
    /// `path` is already absolute (resolved against the work dir).
    Remote {
        vm: String,
        path: String,
    },
}

/// Parse an operand: `<vm>:<path>` when the part before the first `:` names a
/// VM (`is_vm`) and holds no `/`, else a host path. Pure over `is_vm`.
fn parse_operand(s: &str, is_vm: impl Fn(&str) -> bool) -> Operand {
    if let Some((vm, path)) = s.split_once(':') {
        if !vm.is_empty() && !vm.contains('/') && is_vm(vm) {
            return Operand::Remote {
                vm: vm.to_string(),
                path: resolve_remote(path),
            };
        }
    }
    Operand::Local(PathBuf::from(s))
}

/// Anchor a relative (or empty) guest path at the guest work dir.
fn resolve_remote(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if path.is_empty() {
        DEFAULT_REMOTE_DIR.to_string()
    } else {
        format!("{DEFAULT_REMOTE_DIR}/{path}")
    }
}

/// A host path as an scp operand. scp reads `foo:bar` as remote unless a `/`
/// comes before the colon, so such relative paths get a `./` prefix.
fn local_arg(p: &Path) -> OsString {
    let s = p.as_os_str();
    let has_colon = s.as_encoded_bytes().contains(&b':');
    if has_colon && !p.is_absolute() && !p.starts_with(".") {
        Path::new(".").join(p).into_os_string()
    } else {
        s.to_os_string()
    }
}

/// `user@host:path`, bracketing an IPv6 host.
fn remote_arg(ep: &SshEndpoint, user: &str, path: &str) -> OsString {
    let host = if ep.host.contains(':') {
        format!("[{}]", ep.host)
    } else {
        ep.host.clone()
    };
    format!("{user}@{host}:{path}").into()
}

/// Build the full `scp` argv (pure; unit-tested).
fn build_argv(
    vm: &str,
    ep: &SshEndpoint,
    user: &str,
    recursive: bool,
    src: &Operand,
    dst: &Operand,
) -> Vec<OsString> {
    let operand = |o: &Operand| match o {
        Operand::Local(p) => local_arg(p),
        Operand::Remote { path, .. } => remote_arg(ep, user, path),
    };
    let mut argv: Vec<OsString> = vec![scp_bin()];
    argv.extend(hardened_ssh_opts(vm));
    argv.push("-P".into());
    argv.push(ep.port.to_string().into());
    if recursive {
        argv.push("-r".into());
    }
    // `--` guards against an operand that begins with a dash.
    argv.push("--".into());
    argv.push(operand(src));
    argv.push(operand(dst));
    argv
}

/// The host path a pull will write: into `dst` if it is a directory, else `dst`.
fn pull_target(remote_path: &str, dst: &Path) -> PathBuf {
    if dst.is_dir() {
        let name = remote_path.trim_end_matches('/').rsplit('/').next();
        dst.join(name.unwrap_or_default())
    } else {
        dst.to_path_buf()
    }
}

/// `sodabox cp`: copy `src` to `dst`, one of which is `<vm>:<path>`, as `user`.
/// Replaces this process with `scp`.
pub fn run(src: &str, dst: &str, user: &str, recursive: bool, yes: bool) -> anyhow::Result<()> {
    let is_vm = |n: &str| VmMeta::path(n).is_file();
    let src = parse_operand(src, is_vm);
    let dst = parse_operand(dst, is_vm);
    let vm = match (&src, &dst) {
        (Operand::Remote { vm, .. }, Operand::Local(_))
        | (Operand::Local(_), Operand::Remote { vm, .. }) => vm.clone(),
        (Operand::Remote { .. }, Operand::Remote { .. }) => {
            anyhow::bail!("both operands are in a VM — one side must be a host path")
        }
        (Operand::Local(_), Operand::Local(_)) => {
            anyhow::bail!("neither operand is <vm>:<path> of a known VM")
        }
    };

    if let (Operand::Remote { path, .. }, Operand::Local(dst)) = (&src, &dst) {
        let target = pull_target(path, dst);
        if !yes && target.exists() && !crate::confirm(&format!("overwrite {}?", target.display()))?
        {
            println!("aborted");
            return Ok(());
        }
    }

    crate::ssh::require_tool_key(&vm)?;
    let ep = SshEndpoint::load(&vm)?;
    let argv = build_argv(&vm, &ep, user, recursive, &src, &dst);

    // exec: scp owns the terminal (progress meter) and signals.
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    let err = cmd.exec();
    Err(anyhow::anyhow!(
        "running {}: {err}",
        argv[0].to_string_lossy()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep() -> SshEndpoint {
        SshEndpoint {
            host: "127.0.0.1".into(),
            port: 2233,
        }
    }

    fn as_strings(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect()
    }

    fn only_web(n: &str) -> bool {
        n == "web"
    }

    #[test]
    fn operand_is_remote_only_for_a_known_vm() {
        assert_eq!(
            parse_operand("web:/etc/hosts", only_web),
            Operand::Remote {
                vm: "web".into(),
                path: "/etc/hosts".into()
            }
        );
        assert_eq!(
            parse_operand("other:foo", only_web),
            Operand::Local("other:foo".into())
        );
        assert_eq!(
            parse_operand("dir/web:foo", only_web),
            Operand::Local("dir/web:foo".into())
        );
        assert_eq!(
            parse_operand(":foo", only_web),
            Operand::Local(":foo".into())
        );
    }

    #[test]
    fn relative_remote_paths_resolve_against_work_dir() {
        assert_eq!(
            resolve_remote("a/b.txt"),
            format!("{DEFAULT_REMOTE_DIR}/a/b.txt")
        );
        assert_eq!(resolve_remote(""), DEFAULT_REMOTE_DIR);
        assert_eq!(resolve_remote("/tmp/x"), "/tmp/x");
    }

    #[test]
    fn local_paths_with_colons_are_not_read_as_remote() {
        assert_eq!(local_arg(Path::new("a:b")), "./a:b");
        assert_eq!(local_arg(Path::new("./a:b")), "./a:b");
        assert_eq!(local_arg(Path::new("/x/a:b")), "/x/a:b");
        assert_eq!(local_arg(Path::new("plain.txt")), "plain.txt");
    }

    #[test]
    fn argv_pushes_with_hardened_opts_and_port() {
        let src = Operand::Local("foo.txt".into());
        let dst = Operand::Remote {
            vm: "web".into(),
            path: "/var/work/project/foo.txt".into(),
        };
        let argv = as_strings(&build_argv("web", &ep(), "root", false, &src, &dst));
        assert!(argv.windows(2).any(|w| w == ["-P", "2233"]));
        assert!(argv.iter().any(|a| a == "IdentitiesOnly=yes"));
        assert!(!argv.contains(&"-r".to_string()));
        let sep = argv.iter().position(|a| a == "--").expect("-- separator");
        assert_eq!(
            &argv[sep + 1..],
            ["foo.txt", "root@127.0.0.1:/var/work/project/foo.txt"]
        );
    }

    #[test]
    fn argv_brackets_ipv6_and_passes_recursive() {
        let ep = SshEndpoint {
            host: "::1".into(),
            port: 2233,
        };
        let src = Operand::Remote {
            vm: "web".into(),
            path: "/d".into(),
        };
        let dst = Operand::Local(".".into());
        let argv = as_strings(&build_argv("web", &ep, "dev", true, &src, &dst));
        assert!(argv.contains(&"-r".to_string()));
        assert!(argv.contains(&"dev@[::1]:/d".to_string()));
    }

    #[test]
    fn pull_target_lands_inside_a_directory() {
        let dir = std::env::temp_dir();
        assert_eq!(pull_target("/a/b.txt", &dir), dir.join("b.txt"));
        assert_eq!(pull_target("/a/d/", &dir), dir.join("d"));
        let file = dir.join("sodabox-cp-test-no-such-file");
        assert_eq!(pull_target("/a/b.txt", &file), file);
    }
}
