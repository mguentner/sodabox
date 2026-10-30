//! `soda ssh <vm> [command…]` (ADR-0011).
//!
//! Shells out to the system `ssh` with the single hardened, pinned-identity
//! option set ([`sodabox_common::ssh::hardened_ssh_opts`], shared verbatim with
//! sync) against the VM's live host-loopback forward ([`SshEndpoint`], written by
//! the supervisor). We `exec()` ssh so it fully owns the terminal and
//! signals — an interactive session behaves exactly like a direct `ssh`.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Command;

use sodabox_common::ssh::{hardened_ssh_opts, ssh_bin, tool_key_path, SshEndpoint};

/// Build the full `ssh` argv (pure; unit-tested). `command` is the optional
/// remote command; empty means an interactive login shell.
fn build_argv(vm: &str, ep: &SshEndpoint, user: &str, command: &[String]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![ssh_bin()];
    argv.extend(hardened_ssh_opts(vm));
    argv.push("-p".into());
    argv.push(ep.port.to_string().into());
    argv.push(format!("{user}@{}", ep.host).into());
    // `--` guards against a remote command that begins with a dash being parsed
    // as an ssh option.
    if !command.is_empty() {
        argv.push("--".into());
        argv.extend(command.iter().map(OsString::from));
    }
    argv
}

/// Fail with a hint if the tool SSH key hasn't been generated yet.
pub(crate) fn require_tool_key(name: &str) -> anyhow::Result<()> {
    let key = tool_key_path();
    if !key.exists() {
        anyhow::bail!(
            "tool SSH key {} is missing — start the VM once so it is generated (`soda start {name} --net --foreground`)",
            key.display()
        );
    }
    Ok(())
}

/// `soda ssh`: connect to `name` as `user` (default root) and either open an
/// interactive shell or run `command`. Replaces this process with `ssh`.
pub fn run(name: &str, user: &str, command: &[String]) -> anyhow::Result<()> {
    require_tool_key(name)?;
    let ep = SshEndpoint::load(name)?;
    let argv = build_argv(name, &ep, user, command);

    // exec: hand the tty and signals entirely to ssh. Returns only on failure to
    // launch (e.g. ssh not found); a successful exec never returns.
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

    #[test]
    fn argv_targets_endpoint_with_hardened_opts() {
        let argv = as_strings(&build_argv("web", &ep(), "root", &[]));
        assert!(argv.windows(2).any(|w| w == ["-p", "2233"]));
        assert!(argv.contains(&"root@127.0.0.1".to_string()));
        // Hardened opts are threaded through.
        assert!(argv.iter().any(|a| a == "IdentitiesOnly=yes"));
        assert!(argv.windows(2).any(|w| w == ["-F", "/dev/null"]));
        // No remote command → no `--` separator.
        assert!(!argv.contains(&"--".to_string()));
    }

    #[test]
    fn argv_appends_remote_command_after_separator() {
        let cmd = vec!["echo".to_string(), "-n".to_string(), "hi".to_string()];
        let argv = as_strings(&build_argv("web", &ep(), "dev", &cmd));
        let sep = argv.iter().position(|a| a == "--").expect("-- separator");
        // user@host precedes the separator; the command (incl. its leading dash) follows.
        assert!(argv[..sep].contains(&"dev@127.0.0.1".to_string()));
        assert_eq!(&argv[sep + 1..], ["echo", "-n", "hi"]);
    }
}
