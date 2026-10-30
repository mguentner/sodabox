//! Git-native host↔guest sync (ADR-0013): the host's own `git` treats a VM as
//! a plain remote via git's `ext::` helper, routed through the same hardened
//! SSH identity as `soda ssh`/sync (ADR-0011). `soda git-remote`
//! configures the remote; push/pull are plain, unwrapped `git push <vm>` /
//! `git pull <vm>` — no confirm/dry-run layer (ADR-0013: git's own
//! non-fast-forward + `updateInstead` refusals already cover what rsync's
//! confirm step exists for).

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Command;

use sodabox_common::git::{git_bin, remote_ext_url};
use sodabox_common::ssh::{hardened_ssh_opts, ssh_bin, tool_key_path, SshEndpoint};

/// Service names the proxy will exec on the guest. Defensive allowlist: the
/// service string is the one piece of this command line not authored by
/// sodabox itself (git supplies it).
const ALLOWED_SERVICES: [&str; 2] = ["git-upload-pack", "git-receive-pack"];

/// `soda git-proxy`: build the ssh argv and `exec()` it — git-remote-ext
/// has already wired this process's stdio straight to the local `git`
/// process, so exec splices it into the ssh session (same pattern as
/// `ssh::run`).
pub fn git_proxy(vm: &str, user: &str, service: &str) -> anyhow::Result<()> {
    if !ALLOWED_SERVICES.contains(&service) {
        anyhow::bail!("refusing unknown git service '{service}'");
    }
    let key = tool_key_path();
    if !key.exists() {
        anyhow::bail!(
            "tool SSH key {} is missing — start the VM once so it is generated",
            key.display()
        );
    }
    let ep = SshEndpoint::load(vm)?;
    let argv = build_proxy_argv(vm, &ep, user, service);

    // exec: hand stdio entirely to ssh, which carries the git pack protocol.
    // Returns only on failure to launch; a successful exec never returns.
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    let err = cmd.exec();
    Err(anyhow::anyhow!(
        "running {}: {err}",
        argv[0].to_string_lossy()
    ))
}

/// Pure ssh argv for the proxy (unit-tested, mirrors `ssh.rs::build_argv`):
/// hardened opts + live endpoint, then `<service> <guest work dir>` as the
/// remote command.
fn build_proxy_argv(vm: &str, ep: &SshEndpoint, user: &str, service: &str) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![ssh_bin()];
    argv.extend(hardened_ssh_opts(vm));
    argv.push("-p".into());
    argv.push(ep.port.to_string().into());
    argv.push(format!("{user}@{}", ep.host).into());
    argv.push(service.into());
    argv.push(crate::sync::DEFAULT_REMOTE_DIR.into());
    argv
}

/// `soda git-remote`: configure (add/repoint) or remove the cwd repo's
/// `<vm>` remote. Idempotent — see `plan_remote_write`.
pub fn git_remote(vm: &str, user: &str, force: bool, remove: bool) -> anyhow::Result<()> {
    if remove {
        run_git(&["remote", "remove", vm])?;
        println!("removed remote '{vm}'");
        return Ok(());
    }
    let desired = remote_ext_url(vm, user);
    let existing = current_remote_url(vm)?;
    match plan_remote_write(existing.as_deref(), &desired, force) {
        RemoteAction::NoOp => println!("remote '{vm}' already configured for sodabox"),
        RemoteAction::Add => {
            run_git(&["remote", "add", vm, &desired])?;
            println!(
                "added remote '{vm}' -> {desired}\n  now: git push {vm} <branch> \
                 (lands as host/<branch> in the VM; merge it there) / git pull {vm}"
            );
        }
        RemoteAction::Overwrite => {
            run_git(&["remote", "set-url", vm, &desired])?;
            println!("repointed remote '{vm}' -> {desired}");
        }
        RemoteAction::Refuse(url) => anyhow::bail!(
            "remote '{vm}' already exists ({url}) and isn't sodabox's — pass --force to repoint it"
        ),
    }
    set_host_push_refspec(vm)?;
    allow_ext_protocol()
}

/// Where host pushes land in the guest repo: the host's branches become
/// `host/<branch>` remote-tracking refs there, never the guest's own
/// `refs/heads/*`. A push therefore can't collide with the guest's checked-out
/// branch or its in-VM commits; the guest integrates with a plain
/// `git merge host/<branch>` (ADR-0013 "Push lands in `host/*`"). Forced
/// (`+`), like a fetch refspec: `host/*` only mirrors the host and never holds
/// guest work, so a rebased host branch should just replace it.
const HOST_PUSH_REFSPEC: &str = "+refs/heads/*:refs/remotes/host/*";

/// Pin `remote.<vm>.push` to [`HOST_PUSH_REFSPEC`]. git consults it both for a
/// bare `git push <vm>` and to map the `<dst>` of `git push <vm> <branch>`, so
/// both forms land in `host/*`. `--replace-all` keeps re-runs idempotent and
/// upgrades remotes configured before this refspec existed (re-running
/// `git-remote` on them hits the NoOp branch, then lands here).
fn set_host_push_refspec(vm: &str) -> anyhow::Result<()> {
    let key = format!("remote.{vm}.push");
    run_git(&[
        "config",
        "--local",
        "--replace-all",
        &key,
        HOST_PUSH_REFSPEC,
    ])
}

/// git refuses the `ext` transport by default (it can run an arbitrary
/// command, so git treats it like `fd`: opt-in only) — without this, every
/// unwrapped `git push <vm>` / `git pull <vm>` ADR-0013 promises would fail
/// with "transport 'ext' not allowed". `git-remote` is the one place sodabox
/// creates such a remote, so it's the right place to opt the repo in, scoped
/// to local config rather than the user's global git config.
fn allow_ext_protocol() -> anyhow::Result<()> {
    run_git(&["config", "--local", "protocol.ext.allow", "always"])
}

/// What `git_remote` should do, given the remote's current URL (`None` if it
/// doesn't exist yet). Pure; unit-tested without touching git (mirrors
/// `sync.rs::plan_pull`'s injected-decision test style).
fn plan_remote_write(existing: Option<&str>, desired: &str, force: bool) -> RemoteAction {
    match existing {
        None => RemoteAction::Add,
        Some(u) if u == desired => RemoteAction::NoOp,
        Some(_) if force => RemoteAction::Overwrite,
        Some(u) => RemoteAction::Refuse(u.to_string()),
    }
}

enum RemoteAction {
    Add,
    Overwrite,
    NoOp,
    Refuse(String),
}

/// `git remote get-url <vm>` in the cwd; a non-zero exit (no such remote) is
/// `None` rather than an error.
fn current_remote_url(vm: &str) -> anyhow::Result<Option<String>> {
    let out = Command::new(git_bin())
        .args(["remote", "get-url", vm])
        .output()
        .map_err(|e| anyhow::anyhow!("running git: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    ))
}

fn run_git(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(git_bin())
        .args(args)
        .status()
        .map_err(|e| anyhow::anyhow!("running git: {e}"))?;
    if !status.success() {
        anyhow::bail!("git {} failed ({status})", args.join(" "));
    }
    Ok(())
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
    fn proxy_argv_targets_endpoint_with_hardened_opts_and_service() {
        let argv = as_strings(&build_proxy_argv("web", &ep(), "root", "git-upload-pack"));
        assert!(argv.windows(2).any(|w| w == ["-p", "2233"]));
        assert!(argv.contains(&"root@127.0.0.1".to_string()));
        assert!(argv.iter().any(|a| a == "IdentitiesOnly=yes"));
        // Trailing two elements are exactly the service then the work dir.
        assert_eq!(
            &argv[argv.len() - 2..],
            ["git-upload-pack", "/var/work/project"]
        );
    }

    #[test]
    fn allowed_services_covers_upload_and_receive_pack_only() {
        assert!(ALLOWED_SERVICES.contains(&"git-upload-pack"));
        assert!(ALLOWED_SERVICES.contains(&"git-receive-pack"));
        assert!(!ALLOWED_SERVICES.contains(&"anything-else"));
    }

    #[test]
    fn host_push_refspec_targets_remote_tracking_refs_not_guest_branches() {
        let (src, dst) = HOST_PUSH_REFSPEC.split_once(':').unwrap();
        assert_eq!(src, "+refs/heads/*");
        assert_eq!(dst, "refs/remotes/host/*");
    }

    #[test]
    fn plan_remote_write_covers_all_branches() {
        let desired = "ext::soda git-proxy web --user root";
        assert!(matches!(
            plan_remote_write(None, desired, false),
            RemoteAction::Add
        ));
        assert!(matches!(
            plan_remote_write(Some(desired), desired, false),
            RemoteAction::NoOp
        ));
        assert!(matches!(
            plan_remote_write(Some("other-url"), desired, true),
            RemoteAction::Overwrite
        ));
        assert!(matches!(
            plan_remote_write(Some("other-url"), desired, false),
            RemoteAction::Refuse(u) if u == "other-url"
        ));
    }
}
