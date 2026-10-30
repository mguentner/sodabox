//! `soda sync-vm` / `soda sync-host` (ADR-0011).
//!
//! File sync is `rsync` over the *same* hardened SSH transport as `soda ssh`
//! ([`sodabox_common::ssh::ssh_rsh_command`]). It is deliberately **asymmetric**
//! and **delete-free** so a hostile or messy guest can never silently trash the
//! host:
//!
//! - `sync-vm` **pushes** the host cwd → the guest work dir with no confirmation
//!   (the source is the user's own tree). `.git` is pushed so an in-guest agent
//!   can commit/branch.
//! - `sync-host` **pulls** the guest work dir → the host cwd — the only direction
//!   that overwrites host files — behind a dry-run summary and a confirm prompt
//!   (all / interactive per-entry / no). `.git` is **not** pulled unless
//!   `--sync-git`, so a guest repo can't clobber host history.
//!
//! Neither direction uses `--delete`: sync is additive/overwrite only.

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::{Command, Stdio};

use sodabox_common::ssh::{rsync_bin, ssh_rsh_command, tool_key_path, SshEndpoint};

/// Default guest work dir (on the persistent disk, bound to /var/work by the base
/// guest module — outside $HOME, and where an interactive login lands). Sync
/// operates on its contents.
pub(crate) const DEFAULT_REMOTE_DIR: &str = "/var/work/project";

/// Options common to both directions, resolved from the CLI.
pub struct SyncArgs {
    pub vm: String,
    pub user: String,
    /// Extra `--exclude` patterns (applied both ways).
    pub excludes: Vec<String>,
    /// Pull `.git` too (default: push-only).
    pub sync_git: bool,
}

/// The remote rsync location `user@host:/dir/`, plus the ssh port for `-e`.
struct Remote {
    rsh: String,
    spec: String,
}

impl Remote {
    fn resolve(args: &SyncArgs) -> anyhow::Result<Remote> {
        let key = tool_key_path();
        if !key.exists() {
            anyhow::bail!(
                "tool SSH key {} is missing — start the VM once so it is generated",
                key.display()
            );
        }
        let ep = SshEndpoint::load(&args.vm)?;
        Ok(Remote {
            rsh: format!("{} -p {}", ssh_rsh_command(&args.vm), ep.port),
            // Trailing slash: operate on the *contents* of the work dir.
            spec: format!("{}@{}:{}/", args.user, ep.host, DEFAULT_REMOTE_DIR),
        })
    }
}

/// Render `--exclude=<pat>` args from a pattern list (pure).
fn exclude_args(patterns: &[String]) -> Vec<OsString> {
    patterns
        .iter()
        .map(|p| OsString::from(format!("--exclude={p}")))
        .collect()
}

/// `soda sync-vm`: push the host cwd into the guest work dir. No confirmation
/// (the source is the user's own tree); `.git` is included.
pub fn sync_vm(args: &SyncArgs) -> anyhow::Result<()> {
    let remote = Remote::resolve(args)?;
    let mut argv: Vec<OsString> = vec![
        "-a".into(),
        // Create the remote work dir (and parents) if this is the first push.
        "--mkpath".into(),
        "-e".into(),
        remote.rsh.clone().into(),
    ];
    argv.extend(exclude_args(&args.excludes)); // push keeps .git
    argv.push("./".into());
    argv.push(remote.spec.clone().into());

    println!("sync-vm: pushing ./ -> {}", remote.spec);
    run_rsync(&argv)
}

/// `soda sync-host`: pull the guest work dir into the host cwd, carefully.
pub fn sync_host(args: &SyncArgs) -> anyhow::Result<()> {
    let remote = Remote::resolve(args)?;

    // `.git` is push-only: excluded on pull unless the user opts in.
    let mut excludes = args.excludes.clone();
    if !args.sync_git {
        excludes.push(".git".to_string());
    }

    // Dry run first: list exactly what a real pull would change.
    let dry = pull_argv(&remote, &excludes, /*dry_run=*/ true, &[]);
    let out = capture_rsync(&dry)?;
    let changes = parse_changes(&out);

    if changes.is_empty() {
        println!(
            "sync-host: host cwd is already up to date with {}",
            remote.spec
        );
        return Ok(());
    }

    println!(
        "sync-host: pulling {} -> ./  (host files may be overwritten)",
        remote.spec
    );
    println!("{} path(s) would change:", changes.len());
    for c in &changes {
        println!("    {c}");
    }

    match prompt_mode()? {
        Mode::No => {
            println!("aborted; no files changed.");
            Ok(())
        }
        Mode::All => {
            let argv = pull_argv(&remote, &excludes, false, &[]);
            run_rsync(&argv)
        }
        Mode::Interactive => {
            let Some(extra) = plan_pull(&changes, &mut ask_stdin) else {
                println!("aborted; no files changed.");
                return Ok(());
            };
            if extra.len() == changes.len() {
                println!("all entries declined; no files changed.");
                return Ok(());
            }
            let argv = pull_argv(&remote, &excludes, false, &extra);
            run_rsync(&argv)
        }
    }
}

/// Build a pull argv (remote -> cwd). `extra_excludes` are the per-entry
/// declines from interactive mode. Pure.
fn pull_argv(
    remote: &Remote,
    excludes: &[String],
    dry_run: bool,
    extra_excludes: &[String],
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec!["-a".into()];
    if dry_run {
        // `%n` prints just the path of each changed item, one per line — a clean
        // list to summarize and drive the per-entry prompt.
        argv.push("-n".into());
        argv.push("--out-format=%n".into());
    }
    argv.push("-e".into());
    argv.push(remote.rsh.clone().into());
    argv.extend(exclude_args(excludes));
    argv.extend(exclude_args(extra_excludes));
    argv.push(remote.spec.clone().into());
    argv.push("./".into());
    argv
}

/// Parse the `--out-format=%n` dry-run output into a list of changed paths
/// (relative to the work dir; directories keep their trailing slash). Pure.
fn parse_changes(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        // Defensive: drop the odd non-path notice rsync may emit.
        .filter(|l| !l.starts_with("created directory") && !l.starts_with("sent "))
        .map(str::to_string)
        .collect()
}

/// User's choice at the pull confirmation prompt.
enum Mode {
    All,
    Interactive,
    No,
}

/// A single interactive answer.
enum Answer {
    Yes,
    No,
    Quit,
}

/// Walk the change list, asking `ask` per entry, and return the `--exclude`
/// patterns for everything declined (so a real pull transfers the rest). A
/// declined **directory** suppresses its children (they are auto-declined
/// without prompting). Returns `None` if the user quit (abort the whole pull).
/// Pure over the injected `ask`, so it is unit-tested without stdin.
fn plan_pull(paths: &[String], ask: &mut impl FnMut(&str) -> Answer) -> Option<Vec<String>> {
    let mut excludes = Vec::new();
    let mut declined_dirs: Vec<String> = Vec::new();
    for p in paths {
        if declined_dirs.iter().any(|d| p.starts_with(d)) {
            // Already covered by an excluded ancestor directory.
            continue;
        }
        match ask(p) {
            Answer::Yes => {}
            Answer::No => {
                // Anchor the exclude to the transfer root; strip the trailing
                // slash so the pattern matches the dir itself (stopping recursion).
                excludes.push(format!("/{}", p.trim_end_matches('/')));
                if p.ends_with('/') {
                    declined_dirs.push(p.clone());
                }
            }
            Answer::Quit => return None,
        }
    }
    Some(excludes)
}

/// Prompt for the pull mode on stdin.
fn prompt_mode() -> io::Result<Mode> {
    loop {
        print!("Pull? [a]ll / [i]nteractive / [N]o: ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            return Ok(Mode::No); // EOF
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "a" | "all" => return Ok(Mode::All),
            "i" | "interactive" => return Ok(Mode::Interactive),
            "" | "n" | "no" => return Ok(Mode::No),
            _ => println!("please answer a, i, or n."),
        }
    }
}

/// Per-entry prompt for interactive mode.
fn ask_stdin(path: &str) -> Answer {
    loop {
        print!("  pull {path}? [y/N/q]: ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
            return Answer::Quit; // EOF = stop
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Answer::Yes,
            "" | "n" | "no" => return Answer::No,
            "q" | "quit" => return Answer::Quit,
            _ => println!("  please answer y, n, or q."),
        }
    }
}

/// Run rsync inheriting stdio, mapping a non-zero exit to an error.
fn run_rsync(argv: &[OsString]) -> anyhow::Result<()> {
    let status = Command::new(rsync_bin())
        .args(argv)
        .status()
        .map_err(|e| anyhow::anyhow!("running rsync: {e}"))?;
    if !status.success() {
        anyhow::bail!("rsync failed ({status})");
    }
    Ok(())
}

/// Run rsync capturing stdout (for the dry-run listing); stderr passes through.
fn capture_rsync(argv: &[OsString]) -> anyhow::Result<String> {
    let out = Command::new(rsync_bin())
        .args(argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| anyhow::anyhow!("running rsync: {e}"))?;
    if !out.status.success() {
        anyhow::bail!("rsync dry-run failed ({})", out.status);
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote() -> Remote {
        Remote {
            rsh: "ssh -F /dev/null -p 2222".into(),
            spec: "root@127.0.0.1:/var/work/project/".into(),
        }
    }

    fn strs(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|o| o.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn pull_dry_run_lists_paths_and_excludes_git() {
        let argv = strs(&pull_argv(&remote(), &[".git".into()], true, &[]));
        assert!(argv.contains(&"-n".to_string()));
        assert!(argv.contains(&"--out-format=%n".to_string()));
        assert!(argv.contains(&"--exclude=.git".to_string()));
        // remote (src) precedes local (dest).
        let src = argv.iter().position(|a| a.starts_with("root@")).unwrap();
        let dst = argv.iter().position(|a| a == "./").unwrap();
        assert!(src < dst);
        // Never deletes.
        assert!(!argv.iter().any(|a| a.contains("--delete")));
    }

    #[test]
    fn real_pull_drops_dry_run_flags_and_adds_interactive_excludes() {
        let argv = strs(&pull_argv(&remote(), &[], false, &["/secret".into()]));
        assert!(!argv.contains(&"-n".to_string()));
        assert!(!argv.iter().any(|a| a.starts_with("--out-format")));
        assert!(argv.contains(&"--exclude=/secret".to_string()));
    }

    #[test]
    fn parse_changes_keeps_paths_drops_noise() {
        let out = "src/main.rs\ndir/\n\ncreated directory /var/work\nsent 123 bytes\n";
        assert_eq!(
            parse_changes(out),
            vec!["src/main.rs".to_string(), "dir/".to_string()]
        );
    }

    #[test]
    fn plan_pull_declined_dir_suppresses_children() {
        let paths = vec![
            "keep.txt".to_string(),
            "skip/".to_string(),
            "skip/a.txt".to_string(),
            "skip/nested/b.txt".to_string(),
            "also_keep.txt".to_string(),
        ];
        // Decline the directory; accept the two top-level files. Children of the
        // declined dir must never be asked (assert via a counter).
        let mut asked = Vec::new();
        let mut ask = |p: &str| {
            asked.push(p.to_string());
            if p == "skip/" {
                Answer::No
            } else {
                Answer::Yes
            }
        };
        let excludes = plan_pull(&paths, &mut ask).unwrap();
        assert_eq!(excludes, vec!["/skip".to_string()]);
        // Only the two files and the dir were prompted — never the children.
        assert_eq!(asked, vec!["keep.txt", "skip/", "also_keep.txt"]);
    }

    #[test]
    fn plan_pull_quit_aborts() {
        let paths = vec!["a".to_string(), "b".to_string()];
        let mut ask = |p: &str| if p == "a" { Answer::Quit } else { Answer::Yes };
        assert!(plan_pull(&paths, &mut ask).is_none());
    }
}
