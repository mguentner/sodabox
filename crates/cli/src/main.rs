use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::engine::ArgValueCandidates;
use clap_complete::CompleteEnv;
use sodabox_common::vm::Persist;

mod complete;
mod cp;
mod daemonize;
mod gateway;
mod git;
mod guest;
mod logs;
mod preflight;
mod profile;
mod ssh;
mod sync;
mod tui;

#[derive(Parser)]
#[command(
    name = "soda",
    version,
    about = "🍋 - rootless microVMs based on NixOS"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// create a new VM
    Create {
        name: String,
        #[arg(long)]
        cpus: Option<u32>,
        #[arg(long)]
        mem: Option<String>,
        /// data disk size (sparse; store writes, /var/work)
        #[arg(long)]
        disk: Option<String>,
        /// `full`: everything
        /// `home` keeps only /root (tool config)
        /// `none` persist nothing
        #[arg(long, default_value = "full", value_parser = parse_persist)]
        persist: Persist,
        /// home disk size (sparse; /root and the sshd host key; default 1G).
        #[arg(long)]
        home_disk: Option<String>,
        /// guest hostname, written into this VM's guest configuration.nix
        #[arg(long, value_enum, default_value = "name")]
        hostname: guest::HostnameMode,
        /// policy profiles to merge into the new VM's policy, e.g. claudecode,mistral
        #[arg(long, value_delimiter = ',', add = ArgValueCandidates::new(complete::profiles))]
        profiles: Vec<String>,
        /// dotfile collections to copy into the new VM's /root, e.g. claudecode,pi
        /// (later ones win on conflicts)
        #[arg(long, value_delimiter = ',', add = ArgValueCandidates::new(complete::dotfiles))]
        dotfiles: Vec<String>,
    },
    /// start a VM
    Start {
        #[arg(add = ArgValueCandidates::new(complete::vms))]
        name: String,
        // stay attached
        #[arg(long)]
        foreground: bool,
        /// bring up the policy-enforced network stack
        #[arg(long)]
        net: bool,
    },
    /// ssh into a running VM
    Ssh {
        #[arg(add = ArgValueCandidates::new(complete::vms))]
        name: String,
        /// login user in the guest (default: root)
        #[arg(long, short = 'l', default_value = "root")]
        user: String,
        /// optional remote command; omit for an interactive shell
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// copy files between the host and a running VM (scp); one side is
    /// <vm>:<path>, relative guest paths are under the guest work dir
    Cp {
        /// source: a host path or <vm>:<path>
        src: String,
        /// destination: a host path or <vm>:<path>
        dst: String,
        /// login user in the guest (default: root)
        #[arg(long, short = 'l', default_value = "root")]
        user: String,
        /// copy directories recursively
        #[arg(short, long)]
        recursive: bool,
        /// overwrite an existing host path without asking
        #[arg(short, long)]
        yes: bool,
    },
    /// push the host cwd into a running VM's work dir
    SyncVm {
        #[arg(add = ArgValueCandidates::new(complete::vms))]
        name: String,
        #[arg(long, short = 'l', default_value = "root")]
        user: String,
        /// extra rsync exclude pattern (repeatable; applies both ways)
        #[arg(long = "exclude")]
        excludes: Vec<String>,
    },
    /// pull a running VM's work dir into the host cwd
    SyncHost {
        #[arg(add = ArgValueCandidates::new(complete::vms))]
        name: String,
        #[arg(long, short = 'l', default_value = "root")]
        user: String,
        /// Extra rsync exclude pattern (repeatable; applies both ways).
        #[arg(long = "exclude")]
        excludes: Vec<String>,
        /// Also pull `.git` (default: push-only, so a guest can't clobber history).
        #[arg(long)]
        sync_git: bool,
        /// What to pull, instead of asking after the dry-run summary.
        #[arg(long, value_enum)]
        mode: Option<sync::Mode>,
    },
    /// configure the VM `name` as a git remote in the cwd's repo
    GitRemote {
        #[arg(add = ArgValueCandidates::new(complete::vms))]
        name: String,
        #[arg(long, short = 'l', default_value = "root")]
        user: String,
        /// repoint an existing remote of the same name at sodabox's URL
        #[arg(long)]
        force: bool,
        /// remove the configured remote instead of adding/updating it
        #[arg(long)]
        remove: bool,
    },
    /// internal: the `ext::` transport helper git invokes once per push/fetch
    /// Never run this directly!
    #[command(hide = true)]
    GitProxy {
        name: String,
        #[arg(long, short = 'l', default_value = "root")]
        user: String,
        service: String,
    },
    /// stop a running VM
    Stop {
        #[arg(add = ArgValueCandidates::new(complete::vms))]
        name: String,
    },
    /// list VMs
    Ls,
    /// add an allow rule to a VM's egress policy
    Allow {
        #[command(subcommand)]
        what: AllowWhat,
    },
    /// remove/deny a rule from a VM's egress policy
    Deny {
        rule: String,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
    /// show or edit a VM's policy
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// list, show or apply policy profiles
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// switch a VM's inference gateway on or off
    Gateway {
        #[command(subcommand)]
        action: gateway::GatewayAction,
    },
    /// list or show inference providers
    Provider {
        #[command(subcommand)]
        action: gateway::ProviderAction,
    },
    /// manage a VM's model aliases for the inference gateway
    Model {
        #[command(subcommand)]
        action: gateway::ModelAction,
    },
    /// show or change a VM's token quotas
    Quota {
        #[command(subcommand)]
        action: gateway::QuotaAction,
    },
    /// live TUI monitor for a VM
    Tui {
        #[arg(add = ArgValueCandidates::new(complete::vms))]
        name: String,
    },
    /// print a VM's persisted event log (post-hoc audit)
    Logs {
        #[arg(add = ArgValueCandidates::new(complete::vms))]
        name: String,
        /// show only the last N events
        #[arg(long, short = 'n')]
        lines: Option<usize>,
        /// emit the raw stored JSON lines instead of the formatted view
        #[arg(long)]
        json: bool,
    },
    /// remove a VM and its config (and its data unless --keep-disk)
    Rm {
        #[arg(add = ArgValueCandidates::new(complete::vms))]
        name: String,
        #[arg(long)]
        keep_disk: bool,
        /// don't ask for confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// check host prerequisites (KVM access, unprivileged userns)
    Preflight,
}

#[derive(Subcommand)]
enum AllowWhat {
    /// allow egress to an IP/CIDR
    Ip {
        cidr: String,
        #[arg(long)]
        ports: Option<String>,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
    /// allow resolution + egress for a domain
    Domain {
        name: String,
        #[arg(long, group = "scope")]
        exact: bool,
        #[arg(long, group = "scope")]
        wildcard: bool,
        #[arg(long)]
        ports: Option<String>,
        #[arg(long, value_parser = ["tcp", "udp"])]
        proto: Option<String>,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
    /// allow the guest to use a service sodabox offers (`inference`)
    Service {
        #[arg(add = ArgValueCandidates::new(complete::services))]
        name: String,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    Show(PolicyTarget),
    Edit(PolicyTarget),
}

#[derive(Args)]
struct PolicyTarget {
    #[arg(long, add = ArgValueCandidates::new(complete::vms))]
    vm: Option<String>,
}

#[derive(Subcommand)]
enum ProfileAction {
    /// list vendor and user profiles
    Ls,
    /// print a profile
    Show {
        #[arg(add = ArgValueCandidates::new(complete::profiles))]
        name: String,
    },
    /// merge profiles into an existing VM's policy, e.g. claudecode,mistral
    Add {
        #[arg(value_delimiter = ',', required = true, add = ArgValueCandidates::new(complete::profiles))]
        names: Vec<String>,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
}

fn parse_persist(s: &str) -> Result<Persist, String> {
    s.parse()
}

fn main() -> anyhow::Result<()> {
    // Fast path: the hidden namespace probe must run single-threaded (a
    // `CLONE_NEWUSER` requirement), before any async runtime spawns threads.
    if std::env::args().nth(1).as_deref() == Some(preflight::PROBE_ARG) {
        std::process::exit(preflight::probe_namespaces());
    }
    // `COMPLETE=<shell> soda …` is the shell asking for completions (or, with
    // no further args, for its registration script): answer and exit.
    CompleteEnv::with_factory(Cli::command).complete();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Preflight => preflight::run(),
        // Async commands will build a tokio runtime here once implemented.
        Cmd::Create {
            name,
            cpus,
            mem,
            disk,
            persist,
            home_disk,
            hostname,
            profiles,
            dotfiles,
        } => create(
            &name,
            cpus,
            mem.as_deref(),
            disk.as_deref(),
            persist,
            home_disk.as_deref(),
            hostname,
            &profiles,
            &dotfiles,
        ),
        Cmd::Start {
            name,
            foreground,
            net,
        } => start(&name, foreground, net),
        Cmd::Ssh {
            name,
            user,
            command,
        } => ssh::run(&name, &user, &command),
        Cmd::Cp {
            src,
            dst,
            user,
            recursive,
            yes,
        } => cp::run(&src, &dst, &user, recursive, yes),
        Cmd::SyncVm {
            name,
            user,
            excludes,
        } => sync::sync_vm(&sync::SyncArgs {
            vm: name,
            user,
            excludes,
            sync_git: false,
            mode: None,
        }),
        Cmd::SyncHost {
            name,
            user,
            excludes,
            sync_git,
            mode,
        } => sync::sync_host(&sync::SyncArgs {
            vm: name,
            user,
            excludes,
            sync_git,
            mode,
        }),
        Cmd::GitRemote {
            name,
            user,
            force,
            remove,
        } => git::git_remote(&name, &user, force, remove),
        Cmd::GitProxy {
            name,
            user,
            service,
        } => git::git_proxy(&name, &user, &service),
        Cmd::Stop { name } => stop(&name),
        Cmd::Ls => ls(),
        Cmd::Allow { what } => allow(what),
        Cmd::Deny { rule, vm } => deny(&rule, vm),
        Cmd::Policy { action } => policy(action),
        Cmd::Profile { action } => match action {
            ProfileAction::Ls => profile::ls(),
            ProfileAction::Show { name } => profile::show(&name),
            ProfileAction::Add { names, vm } => profile_add(&names, vm),
        },
        Cmd::Gateway { action } => gateway::gateway(action),
        Cmd::Provider { action } => gateway::provider(action),
        Cmd::Model { action } => gateway::model(action),
        Cmd::Quota { action } => gateway::quota(action),
        Cmd::Tui { name } => tui::run(&name),
        Cmd::Logs { name, lines, json } => logs::run(&name, lines, json),
        Cmd::Rm {
            name,
            keep_disk,
            yes,
        } => rm(&name, keep_disk, yes),
    }
}

/// `soda create` — materialize the user-owned guest input (ADR-0012), the
/// per-VM data dir + metadata, and the disks its persistence mode keeps (sparse
/// raw): data + home disk for `full`, the home disk for `home`, nothing
/// for `none` (ADR-0014; scratch disks are made at start).
#[allow(clippy::too_many_arguments)]
fn create(
    name: &str,
    cpus: Option<u32>,
    mem: Option<&str>,
    disk: Option<&str>,
    persist: Persist,
    home_disk: Option<&str>,
    hostname: guest::HostnameMode,
    profiles: &[String],
    dotfiles: &[String],
) -> anyhow::Result<()> {
    use sodabox_common::paths;
    use sodabox_common::policy::PolicyFile;
    use sodabox_common::vm::VmMeta;
    use std::time::{SystemTime, UNIX_EPOCH};

    let cpus = cpus.unwrap_or(2);
    let mem = mem.unwrap_or("2048M");
    let disk = disk.unwrap_or("8G");

    // Validate sizes up front, before any side effects. `parse_mem_mib` reads a
    // bare `--mem 8192` as MiB (not bytes), so it can't silently store a value
    // that later boots as `size=0M`.
    sodabox_common::storage::parse_size(disk).map_err(|e| anyhow::anyhow!("--disk: {e}"))?;
    sodabox_common::storage::parse_mem_mib(mem).map_err(|e| anyhow::anyhow!("--mem: {e}"))?;
    if let Some(h) = home_disk {
        sodabox_common::storage::parse_size(h).map_err(|e| anyhow::anyhow!("--home-disk: {e}"))?;
    }

    // Resolve and merge the profiles before any side effects too, so an unknown
    // or invalid profile creates nothing (ADR-0015).
    let policy_path = PolicyFile::path(name);
    let initial_policy = if profiles.is_empty() {
        None
    } else {
        if policy_path.is_file() {
            anyhow::bail!(
                "VM '{name}' already has a policy; apply profiles to it with `soda profile add {} --vm {name}`",
                profiles.join(",")
            );
        }
        let mut file = PolicyFile::new();
        for p in profile::load_all(profiles)? {
            let report = file.merge_profile(&p).map_err(|e| anyhow::anyhow!(e))?;
            println!("profile '{}': {report}", p.name());
            gateway::warn_conflicts(p.name(), &report);
        }
        let policy = file.policy().map_err(|e| anyhow::anyhow!(e))?;
        sodabox_common::allowlist::Allowlist::from_policy(&policy)
            .map_err(|e| anyhow::anyhow!("merged policy is invalid: {e}"))?;
        policy
            .validate_models()
            .map_err(|e| anyhow::anyhow!("merged policy is invalid: {e}"))?;
        gateway::warn_missing_providers(&policy);
        file.set_version(1);
        Some(file)
    };

    // Dotfiles are copied in only when the VM is made (ADR-0019).
    if !dotfiles.is_empty() && VmMeta::path(name).is_file() {
        anyhow::bail!(
            "VM '{name}' already exists; dotfiles are only copied in when a VM is created"
        );
    }

    // 1) User-owned guest input (ADR-0012): write the shipped default if absent.
    let (created, guest_dir) = guest::ensure_default_guest_input()?;
    println!(
        "{} guest input at {}",
        if created {
            "materialized default"
        } else {
            "using existing"
        },
        guest_dir.display()
    );

    // Merge the dotfile collections (ADR-0019) before anything VM-specific is
    // written, so an unknown or invalid collection creates no VM. A `default.nix`
    // is evaluated with the shared guest's pinned nixpkgs, hence after it exists.
    let dotfiles_tree = if dotfiles.is_empty() {
        None
    } else {
        let mut loaded = Vec::new();
        for c in dotfiles {
            loaded.push(
                sodabox_common::dotfiles::load(c, &guest_dir).map_err(|e| anyhow::anyhow!(e))?,
            );
        }
        let merged = sodabox_common::dotfiles::merge(loaded);
        for w in &merged.warnings {
            eprintln!("warning: {w}");
        }
        Some(merged)
    };

    // This VM's own layer on top of the shared input: its hostname, plus
    // whatever the user adds later. Never rewritten once it exists.
    let (vm_created, vm_dir) =
        guest::ensure_vm_guest_input(name, || guest::resolve_hostname(hostname, name))?;
    if vm_created {
        println!(
            "wrote {} (imports the shared guest input)",
            vm_dir.join("configuration.nix").display()
        );
    }
    println!(
        "guest for '{name}' -> {}",
        paths::resolve_guest_dir(name).display()
    );

    // 2) Per-VM data dir + metadata.
    let data = paths::data_dir(name);
    std::fs::create_dir_all(&data)?;

    let meta_path = data.join("meta.toml");
    let meta = if meta_path.is_file() {
        println!(
            "VM '{name}' already exists at {} (metadata left as-is)",
            data.display()
        );
        VmMeta::load(name)?
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Claim this VM's SSH forward port now and record it (ADR-0011):
        // the assignment is state, so the VM keeps the port across restarts and
        // no other VM is ever handed it.
        let ssh_port = VmMeta::allocate_ssh_port(name, &VmMeta::ssh_ports_taken(name)?)?;
        let meta = VmMeta {
            name: name.to_string(),
            cpus,
            mem: mem.to_string(),
            disk: disk.to_string(),
            ssh_port,
            persist,
            home_disk: home_disk.map(str::to_string),
            dotfiles: dotfiles.to_vec(),
            created: now,
        };
        meta.save()?;
        println!("wrote {} (ssh port {ssh_port})", meta_path.display());
        meta
    };

    if let Some(file) = initial_policy {
        file.save(name)?;
        println!(
            "wrote {} (deny-by-default + profiles {})",
            policy_path.display(),
            profiles.join(", ")
        );
    } else if !policy_path.is_file() {
        PolicyFile::new().save(name)?;
        println!("wrote {} (deny-by-default)", policy_path.display());
    }

    if let Some(tree) = dotfiles_tree {
        let dir = paths::vm_dotfiles_dir(name);
        sodabox_common::dotfiles::write_tree(&tree, &dir)?;
        println!(
            "wrote {} ({} file(s) from {})",
            dir.display(),
            tree.files.len(),
            dotfiles.join(", ")
        );
    }

    // 3) The disks this VM keeps (ADR-0014), per the *stored* mode so re-running
    //    create on an existing VM never provisions a disk it doesn't use.
    //    Sparse raw, user-owned, resizable, attached RW.
    if !meta.persist.scratch_data() {
        let (img_created, img) = sodabox_common::storage::ensure_data_img(name, &meta.disk)?;
        if img_created {
            println!("provisioned {} ({}, sparse)", img.display(), meta.disk);
        } else {
            println!("data disk exists at {} (left as-is)", img.display());
        }
    }
    if !meta.persist.scratch_home() {
        let size = meta.home_disk();
        let (img_created, img) = sodabox_common::storage::ensure_home_img(name, size)?;
        if img_created {
            println!("provisioned {} ({size}, sparse)", img.display());
        } else {
            println!("home disk exists at {} (left as-is)", img.display());
        }
    }

    let disks = match meta.persist {
        Persist::Full => format!("{} data + {} home disk", meta.disk, meta.home_disk()),
        Persist::Home => {
            format!(
                "{} scratch data + {} kept home disk",
                meta.disk,
                meta.home_disk()
            )
        }
        Persist::None => {
            format!(
                "{} data + {} home disk, both scratch",
                meta.disk,
                meta.home_disk()
            )
        }
    };
    println!(
        "created VM '{name}' ({} vCPU, {} RAM, {disks}; persist = {}).",
        meta.cpus, meta.mem, meta.persist
    );
    Ok(())
}

/// `soda start` — build the guest via mkGuest (ADR-0012) and boot it with
/// cloud-hypervisor. This first cut runs in the foreground with no
/// networking; the netns owner + passt and backgrounding come
/// next.
fn start(name: &str, foreground: bool, net: bool) -> anyhow::Result<()> {
    use sodabox_common::{paths, storage, vm::VmMeta};

    // Networked start: the full supervisor orchestration (netns + passt + filter
    // proxy + DNS resolver + control socket), fail-closed. It forks and unshares,
    // so it must run before any tokio runtime — hand off directly (no runtime here).
    if net {
        if foreground {
            return sodabox_supervisor::supervise::run(name);
        }
        return start_background(name);
    }

    if !foreground {
        // The no-network boot is a foreground-only debug path: it has no control
        // socket, so a detached run could be neither monitored nor stopped. The
        // networked stack (`--net`) is the one that backgrounds.
        anyhow::bail!(
            "no-network start is foreground-only (debug); re-run with --foreground, or use --net for a backgrounded VM"
        );
    }

    let meta = VmMeta::load(name).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            anyhow::anyhow!("no such VM '{name}' — run `soda create {name}` first")
        }
        _ => anyhow::anyhow!("reading meta.toml for '{name}': {e}"),
    })?;

    let guest_dir = paths::resolve_guest_dir(name);
    let mem_mib =
        storage::parse_mem_mib(&meta.mem).map_err(|e| anyhow::anyhow!("meta mem: {e}"))?;

    // Prevent two boots from attaching the same data disk (ADR-0008). Held
    // for this foreground boot; released when the guard drops at function exit.
    let _data_lock = storage::DataImgLock::acquire(name)?;
    let result = start_foreground_locked(name, &meta, &guest_dir, mem_mib);
    // A `home`/`none` VM's scratch disk goes with the VM (ADR-0014), lock held.
    if let Err(e) = meta.discard_scratch() {
        eprintln!("soda: could not delete the scratch disk of '{name}': {e}");
    }
    result
}

/// The no-network foreground boot of [`start`], with the data-disk lock held.
fn start_foreground_locked(
    name: &str,
    meta: &sodabox_common::vm::VmMeta,
    guest_dir: &std::path::Path,
    mem_mib: u64,
) -> anyhow::Result<()> {
    use sodabox_common::paths;
    use sodabox_supervisor::chv::{Chv, Serial};
    use sodabox_supervisor::guest::build_guest;
    use std::time::Duration;

    // Clear stale runtime state from an unclean shutdown: holding the data-disk
    // lock above proves no live supervisor, so a chv-api.sock left behind would
    // block the next bind (ADR-0007).
    paths::wipe_runtime_dir(name)?;
    std::fs::create_dir_all(paths::runtime_dir(name))?;
    // ADR-0007 runtime layout: this process supervises the VM, publish its pid.
    std::fs::write(paths::pid_path(name), std::process::id().to_string())?;

    // SSH access (ADR-0011): authorized_keys holds only the tool key, on the
    // read-only config disk attached as the guest's second disk (/dev/vdb).
    let config_img = sodabox_supervisor::supervise::build_config_disk_for(name, meta)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        println!("building guest for '{name}' (nix-build mkGuest)…");
        let gd = guest_dir.to_path_buf();
        let built = tokio::task::spawn_blocking(move || build_guest(&gd)).await??;
        println!("  kernel:   {}", built.kernel.display());
        println!("  store:    {}", built.store.display());
        println!("  toplevel: {}", built.toplevel.display());

        // Read-write disks per persistence mode (ADR-0014; fresh scratch for
        // `home`/`none`), after the build so a failed build leaves none behind.
        let disks = meta.prepare_disks()?;

        // cloud-hypervisor's API socket drives a clean ACPI power-off on stop so
        // the data disk is flushed. Short path to stay under SUN_LEN.
        let api_socket = paths::chv_api_sock_path(name);
        let boot = built.to_boot(
            meta.cpus,
            mem_mib,
            config_img,
            disks,
            None,
            Some(api_socket),
            Serial::Stdio,
        );
        println!(
            "launching cloud-hypervisor ({} vCPU, {mem_mib} MiB)…",
            meta.cpus
        );
        let mut chv = Chv::spawn(&boot).await?;
        if let Some(pid) = chv.pid() {
            println!("cloud-hypervisor pid {pid}; Ctrl-C to shut down");
        }

        tokio::select! {
            status = chv.wait() => println!("guest exited: {}", status?),
            _ = tokio::signal::ctrl_c() => {
                println!("\nshutting down…");
                let status = chv.shutdown(Duration::from_secs(10)).await?;
                println!("guest stopped: {status}");
            }
        }
        // Clean exit: leave no runtime state behind (ADR-0007).
        let _ = paths::wipe_runtime_dir(name);
        Ok::<(), anyhow::Error>(())
    })
}

/// Detached (default) networked start (ADR-0007): spawn the
/// supervisor as a background process and wait for the VM to come up before
/// returning. The supervisor's own output goes to `supervisor.log`; this launcher
/// prints only the user-facing status.
fn start_background(name: &str) -> anyhow::Result<()> {
    use sodabox_common::paths;

    // Fail fast, on the terminal, if it's already up — before we fork/daemonize.
    if rt()?.block_on(is_running(name)) {
        anyhow::bail!("VM '{name}' is already running (stop it with `soda stop {name}`)");
    }

    // The supervisor logs here; create the dir now so the daemonizer can validate
    // it and the child can open the log. The supervisor wipes+recreates this dir
    // under the data-disk lock and only then opens the log, so nothing is lost.
    let runtime_dir = paths::runtime_dir(name);
    std::fs::create_dir_all(&runtime_dir)?;
    let log = paths::supervisor_log_path(name);

    match daemonize::daemonize(&runtime_dir)? {
        daemonize::Daemon::Child => {
            // Detached supervisor: run the full stack with output to the log. This
            // never returns to the shell — exit with the run's status.
            let code = match sodabox_supervisor::supervise::run_with_log(name, Some(log)) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("soda supervisor: {e}");
                    1
                }
            };
            std::process::exit(code);
        }
        daemonize::Daemon::Launcher { child } => {
            println!("starting VM '{name}' in the background…");
            wait_for_ready(name, child, &log)
        }
    }
}

/// Poll for the background supervisor to bring the VM up: success once its control
/// socket accepts a connection, failure if the supervisor process exits first.
/// nix-build on a first start can take minutes, so there is no hard timeout while
/// the child is alive — after a short delay we note it is still coming up so a slow
/// build does not look hung.
fn wait_for_ready(
    name: &str,
    child: nix::unistd::Pid,
    log: &std::path::Path,
) -> anyhow::Result<()> {
    use std::time::{Duration, Instant};

    let rt = rt()?;
    let start = Instant::now();
    let mut hinted = false;
    loop {
        if rt.block_on(is_running(name)) {
            println!(
                "VM '{name}' is up (supervisor pid {child}, {}s).",
                start.elapsed().as_secs()
            );
            println!("  ssh:  soda ssh {name}");
            println!("  stop: soda stop {name}");
            println!("  log:  {}", log.display());
            return Ok(());
        }
        if let Some(code) = daemonize::child_exit_status(child)? {
            anyhow::bail!(
                "VM '{name}' failed to start (supervisor exited with status {code}).\n\
                 --- {} (tail) ---\n{}",
                log.display(),
                log_tail(log, 20)
            );
        }
        if !hinted && start.elapsed() >= Duration::from_secs(5) {
            println!("  …still starting (building the guest can take a while on first run)");
            hinted = true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The last `n` lines of `path`, for surfacing a failed background start. Returns a
/// short placeholder rather than erroring if the log can't be read.
fn log_tail(path: &std::path::Path, n: usize) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let lines: Vec<&str> = s.lines().collect();
            lines[lines.len().saturating_sub(n)..].join("\n")
        }
        Err(e) => format!("(could not read {}: {e})", path.display()),
    }
}

/// A small current-thread runtime for the short-lived control-socket commands.
fn rt() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

/// Resolve the target VM for a policy command: the explicit `--vm`, or — when a
/// single VM exists — that one. Ambiguity (0 or >1) is an error asking for `--vm`,
/// so a policy edit never silently lands on the wrong VM.
fn resolve_vm(vm: Option<String>) -> anyhow::Result<String> {
    use sodabox_common::vm::VmMeta;
    if let Some(v) = vm {
        return Ok(v);
    }
    let vms = VmMeta::list()?;
    match vms.as_slice() {
        [only] => Ok(only.name.clone()),
        [] => anyhow::bail!("no VMs exist — create one with `soda create <name>`"),
        _ => {
            let names: Vec<_> = vms.iter().map(|m| m.name.as_str()).collect();
            anyhow::bail!("multiple VMs ({}) — specify --vm <name>", names.join(", "))
        }
    }
}

/// Load `<vm>`'s persisted policy, apply `mutate`, validate + version-bump, then
/// **persist to `policy.toml` and, if the VM is running, push it live** over the
/// control socket (ADR-0009/0006). `mutate` returns a human
/// summary of what changed, or `Ok(None)` for a no-op (skip the write, still push).
///
/// The persisted file is the source of truth; the live push is best-effort in the
/// sense that a stopped VM simply picks the new policy up at next start. Validation
/// (compiling the allowlist) happens before any write, so a bad edit changes nothing.
/// The edit goes through [`PolicyFile`], so comments in `policy.toml` survive it.
///
/// [`PolicyFile`]: sodabox_common::policy::PolicyFile
fn apply_edit(
    vm: &str,
    mutate: impl FnOnce(&mut sodabox_common::policy::PolicyFile) -> anyhow::Result<Option<String>>,
) -> anyhow::Result<()> {
    use sodabox_common::allowlist::Allowlist;
    use sodabox_common::policy::PolicyFile;

    // A VM must exist to have a policy (catches typos before we write a file).
    if !sodabox_common::vm::VmMeta::path(vm).is_file() {
        anyhow::bail!("no such VM '{vm}' — run `soda create {vm}` first");
    }

    let _lock = PolicyFile::lock(vm)?;
    let mut file = PolicyFile::load(vm).map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
    let Some(summary) = mutate(&mut file)? else {
        // Nothing to save, but the file isn't necessarily live (a failed push, a
        // hand edit), and repeating the command has to be able to repair that.
        println!("no change");
        let policy = file.policy().map_err(|e| anyhow::anyhow!(e))?;
        return push_live(vm, &policy);
    };

    // Validate the whole policy compiles before persisting (fail-closed).
    let policy = file
        .policy()
        .map_err(|e| anyhow::anyhow!("invalid policy after edit: {e}"))?;
    Allowlist::from_policy(&policy)
        .map_err(|e| anyhow::anyhow!("invalid policy after edit: {e}"))?;
    policy
        .validate_models()
        .map_err(|e| anyhow::anyhow!("invalid policy after edit: {e}"))?;
    file.set_version(policy.version + 1);
    file.save(vm)
        .map_err(|e| anyhow::anyhow!("writing policy.toml: {e}"))?;
    let policy = file.policy().map_err(|e| anyhow::anyhow!(e))?;
    println!("{summary}");
    println!("persisted policy v{} for '{vm}'", policy.version);

    push_live(vm, &policy)
}

/// Push `policy` to the running supervisor via `PolicySet`. If the VM is not
/// running, that is fine — say so and leave the persisted file for next start.
fn push_live(vm: &str, policy: &sodabox_common::policy::VmPolicy) -> anyhow::Result<()> {
    use sodabox_common::protocol::{Request, Response};
    use sodabox_supervisor::control::ControlClient;

    rt()?.block_on(async {
        let mut client = match ControlClient::connect(vm).await {
            Ok(c) => c,
            Err(e) if is_not_running(&e) => {
                println!("VM '{vm}' is not running — new policy applies at next start");
                return Ok(());
            }
            Err(e) => anyhow::bail!("connecting to '{vm}' control socket: {e}"),
        };
        match client
            .request(&Request::PolicySet {
                policy: policy.clone(),
            })
            .await?
        {
            Response::Ok => {
                println!("pushed live to running VM '{vm}'");
                Ok(())
            }
            Response::Error { msg } => anyhow::bail!("supervisor rejected policy: {msg}"),
            other => anyhow::bail!("unexpected response from '{vm}': {other:?}"),
        }
    })
}

/// `soda allow ip|domain …` — add a rule (persist + push live).
fn allow(what: AllowWhat) -> anyhow::Result<()> {
    use sodabox_common::policy::DomainScope;
    match what {
        AllowWhat::Ip { cidr, ports, vm } => {
            let vm = resolve_vm(vm)?;
            apply_edit(&vm, |p| {
                let added = p
                    .add_ip(&cidr, ports.as_deref())
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok(added.then(|| {
                    let ps = ports
                        .as_deref()
                        .map(|p| format!(" ports {p}"))
                        .unwrap_or_default();
                    format!("allow ip {cidr}{ps}")
                }))
            })
        }
        AllowWhat::Domain {
            name,
            exact,
            wildcard,
            ports,
            proto,
            vm,
        } => {
            let vm = resolve_vm(vm)?;
            let scope = if exact {
                DomainScope::Exact
            } else if wildcard {
                DomainScope::Wildcard
            } else {
                DomainScope::Subdomains
            };
            apply_edit(&vm, |p| {
                let added = p
                    .add_domain_for_proto(&name, scope, ports.as_deref(), proto.as_deref())
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok(added.then(|| {
                    let ps = ports
                        .as_deref()
                        .map(|p| format!(" ports {p}"))
                        .unwrap_or_default();
                    let pr = proto
                        .as_deref()
                        .map(|p| format!(" proto {p}"))
                        .unwrap_or_default();
                    format!("allow domain {name} ({scope:?}){ps}{pr}")
                }))
            })
        }
        AllowWhat::Service { name, vm } => {
            let vm = resolve_vm(vm)?;
            apply_edit(&vm, |p| {
                let added = p.add_service(&name).map_err(|e| anyhow::anyhow!(e))?;
                let enabled = p
                    .policy()
                    .map_err(|e| anyhow::anyhow!(e))?
                    .gateway
                    .is_some_and(|g| g.enabled);
                if added && !enabled {
                    println!(
                        "note: the gateway is switched off; turn it on with `soda gateway enable --vm {vm}`"
                    );
                }
                Ok(added.then(|| format!("allow service {name}")))
            })
        }
    }
}

/// `soda deny <rule>` — remove matching rule(s) (persist + push live).
fn deny(rule: &str, vm: Option<String>) -> anyhow::Result<()> {
    let vm = resolve_vm(vm)?;
    apply_edit(&vm, |p| {
        let n = p.remove_matching(rule).map_err(|e| anyhow::anyhow!(e))?;
        if n == 0 {
            anyhow::bail!("no allow rule matching '{rule}' — nothing to deny");
        }
        Ok(Some(format!("removed {n} rule(s) matching '{rule}'")))
    })
}

/// `soda profile add <names> [--vm]` — merge profiles into an existing VM's
/// policy (persist + push live), like appending each profile's rules to
/// `policy.toml` with a provenance comment per rule (ADR-0015).
fn profile_add(names: &[String], vm: Option<String>) -> anyhow::Result<()> {
    let vm = resolve_vm(vm)?;
    let profiles = profile::load_all(names)?;
    apply_edit(&vm, |file| {
        let mut parts = Vec::new();
        let mut changed = false;
        for p in &profiles {
            let report = file.merge_profile(p).map_err(|e| anyhow::anyhow!(e))?;
            gateway::warn_conflicts(p.name(), &report);
            parts.push(format!("'{}' {report}", p.name()));
            changed |= report.changed();
        }
        if changed {
            gateway::warn_missing_providers(&file.policy().map_err(|e| anyhow::anyhow!(e))?);
        }
        Ok(changed.then(|| format!("applied profiles {}", parts.join("; "))))
    })
}

/// `soda policy show|edit`.
fn policy(action: PolicyAction) -> anyhow::Result<()> {
    match action {
        PolicyAction::Show(t) => policy_show(resolve_vm(t.vm)?),
        PolicyAction::Edit(t) => policy_edit(resolve_vm(t.vm)?),
    }
}

/// Print the persisted `policy.toml` as written (comments, including profile
/// provenance, included), plus the live version if the VM is running.
fn policy_show(vm: String) -> anyhow::Result<()> {
    use sodabox_common::policy::PolicyFile;
    use sodabox_common::protocol::{Request, Response};
    use sodabox_supervisor::control::ControlClient;

    let file = PolicyFile::load(&vm).map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
    let policy = file
        .policy()
        .map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
    println!("# policy for '{vm}' (persisted)\n{file}");

    // If it's running, report the live version so drift is visible.
    let live = rt()?.block_on(async {
        let mut c = ControlClient::connect(&vm).await.ok()?;
        match c.request(&Request::Status).await.ok()? {
            Response::Status { policy_version, .. } => Some(policy_version),
            _ => None,
        }
    });
    match live {
        Some(v) if v == policy.version => println!("# live: running, policy v{v} (in sync)"),
        Some(v) => println!(
            "# live: running, policy v{v} (persisted is v{})",
            policy.version
        ),
        None => println!("# live: not running"),
    }
    Ok(())
}

/// Open the persisted `policy.toml` in `$EDITOR`, then validate and push live.
fn policy_edit(vm: String) -> anyhow::Result<()> {
    use sodabox_common::allowlist::Allowlist;
    use sodabox_common::policy::PolicyFile;

    if !sodabox_common::vm::VmMeta::path(&vm).is_file() {
        anyhow::bail!("no such VM '{vm}' — run `soda create {vm}` first");
    }
    // Ensure the file exists so the editor opens something meaningful.
    let path = PolicyFile::path(&vm);
    {
        let _lock = PolicyFile::lock(&vm)?;
        if !path.is_file() {
            PolicyFile::new().save(&vm)?;
        }
    }
    let before = std::fs::read_to_string(&path).unwrap_or_default();

    // The editor gets a copy: it can stay open for as long as the user likes, so
    // it can't hold the policy lock, and the live file must not be half-edited
    // meanwhile. Per process, so a kept copy (below) isn't overwritten by the next
    // edit.
    let copy = path.with_file_name(format!(".policy.edit.{}.toml", std::process::id()));
    std::fs::write(&copy, &before)?;

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = std::process::Command::new(&editor)
        .arg(&copy)
        .status()
        .map_err(|e| anyhow::anyhow!("launching editor '{editor}': {e}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&copy);
        anyhow::bail!("editor '{editor}' exited with {status}; policy left unchanged");
    }

    let after = std::fs::read_to_string(&copy)?;
    if after == before {
        let _ = std::fs::remove_file(&copy);
        println!("no change");
        return Ok(());
    }

    // Validate the edit; on failure the user's text stays in the copy for a re-edit.
    // Only `version` is rewritten, so the user's comments and layout stay.
    let kept = copy.display();
    let mut file = PolicyFile::parse(&after)
        .map_err(|e| anyhow::anyhow!("edited policy is not valid (kept at {kept}): {e}"))?;
    let policy = file
        .policy()
        .map_err(|e| anyhow::anyhow!("edited policy is not valid (kept at {kept}): {e}"))?;
    Allowlist::from_policy(&policy)
        .map_err(|e| anyhow::anyhow!("edited policy is invalid (kept at {kept}): {e}"))?;

    // Saving replaces the whole file, so anything written while the editor was
    // open would be lost: refuse instead. The version is tool-managed; the user's
    // typed one is overridden so the live push always registers as newer.
    let _lock = PolicyFile::lock(&vm)?;
    if std::fs::read_to_string(&path).unwrap_or_default() != before {
        anyhow::bail!(
            "policy.toml changed while you were editing; left it as it is (your edit is kept at {kept})"
        );
    }
    let prior = PolicyFile::load(&vm).map(|f| f.version()).unwrap_or(0);
    file.set_version(prior + 1);
    file.save(&vm)?;
    let _ = std::fs::remove_file(&copy);
    let policy = file.policy().map_err(|e| anyhow::anyhow!(e))?;
    println!("saved edited policy v{} for '{vm}'", policy.version);
    push_live(&vm, &policy)
}

/// A connect error meaning "no live supervisor": no socket file (`NotFound`) or a
/// stale socket nobody is accepting on (`ConnectionRefused`).
fn is_not_running(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

/// Running iff the VM's control socket accepts a connection (ADR-0007).
async fn is_running(name: &str) -> bool {
    sodabox_supervisor::control::ControlClient::connect(name)
        .await
        .is_ok()
}

/// `soda stop` — ask the VM's supervisor to tear down via its control socket.
fn stop(name: &str) -> anyhow::Result<()> {
    use sodabox_common::protocol::{Request, Response};
    use sodabox_supervisor::control::ControlClient;

    rt()?.block_on(async {
        let mut client = match ControlClient::connect(name).await {
            Ok(c) => c,
            Err(e) if is_not_running(&e) => anyhow::bail!("VM '{name}' is not running"),
            Err(e) => anyhow::bail!("connecting to '{name}' control socket: {e}"),
        };
        match client.request(&Request::Stop).await? {
            Response::Ok => {
                println!("stopping VM '{name}'…");
                Ok(())
            }
            Response::Error { msg } => anyhow::bail!("stop refused: {msg}"),
            other => anyhow::bail!("unexpected response from '{name}': {other:?}"),
        }
    })
}

/// `soda ls` — enumerate VMs from the data root and probe each control socket
/// for liveness (ADR-0007/0009).
fn ls() -> anyhow::Result<()> {
    use sodabox_common::vm::VmMeta;

    let vms = VmMeta::list()?;
    if vms.is_empty() {
        println!("no VMs — create one with `soda create <name>`");
        return Ok(());
    }

    let rt = rt()?;
    println!(
        "{:<16} {:>4} {:>8} {:>8}  {:<7}  STATE",
        "NAME", "CPUS", "MEM", "DISK", "PERSIST"
    );
    for m in vms {
        let state = if rt.block_on(is_running(&m.name)) {
            "running"
        } else {
            "stopped"
        };
        println!(
            "{:<16} {:>4} {:>8} {:>8}  {:<7}  {}",
            m.name, m.cpus, m.mem, m.disk, m.persist, state
        );
    }
    Ok(())
}

/// `soda rm` — remove a stopped VM. Deletes the whole data dir, or with
/// `--keep-disk` keeps the disks holding the VM's kept state: `data.img` and
/// `home.img` for `persist = "full"`, `home.img` for `home`, nothing for `none`
/// (ADR-0014). Also deletes the VM's config dir. Asks for confirmation unless
/// `yes`. Refuses while the VM is running (ADR-0008).
fn rm(name: &str, keep_disk: bool, yes: bool) -> anyhow::Result<()> {
    use sodabox_common::{paths, storage, vm::VmMeta};

    if !VmMeta::path(name).is_file() {
        anyhow::bail!("no such VM '{name}'");
    }
    // An unreadable meta.toml must not make a VM unremovable; without a mode,
    // assume the stateful default so --keep-disk errs on the side of keeping.
    let persist = VmMeta::load(name).map(|m| m.persist).unwrap_or_default();
    if rt()?.block_on(is_running(name)) {
        anyhow::bail!("VM '{name}' is running — stop it first (`soda stop {name}`)");
    }

    let data = paths::data_dir(name);
    let config = paths::vm_config_dir(name);
    if !yes {
        let what = if keep_disk {
            "its config"
        } else {
            "its disks and config"
        };
        println!("This will remove VM '{name}' and {what}:");
        println!("  {}", data.display());
        if config.exists() {
            println!("  {}", config.display());
        }
        if !confirm("Continue?")? {
            println!("aborted");
            return Ok(());
        }
    }
    let mut kept = Vec::new();
    if keep_disk {
        if !persist.scratch_data() {
            kept.push(storage::data_img_path(name));
        }
        if !persist.scratch_home() {
            kept.push(storage::home_img_path(name));
        }
        kept.retain(|p| p.exists());
        if kept.is_empty() {
            println!("'{name}' has no kept disk (persist = {persist}); removing everything");
        }
    }
    if kept.is_empty() {
        std::fs::remove_dir_all(&data)?;
        println!("removed VM '{name}' and its disks");
    } else {
        // Drop the registration (meta/policy/…) but preserve the user's disks.
        for entry in std::fs::read_dir(&data)? {
            let p = entry?.path();
            if kept.contains(&p) {
                continue;
            }
            if p.is_dir() {
                std::fs::remove_dir_all(&p)?;
            } else {
                std::fs::remove_file(&p)?;
            }
        }
        let shown: Vec<_> = kept.iter().map(|p| p.display().to_string()).collect();
        println!("removed VM '{name}' (kept {})", shown.join(", "));
    }
    paths::remove_dir_quiet(&config)?;

    // Best-effort cleanup of any stale runtime dir (sockets from an old boot).
    let runtime = paths::runtime_dir(name);
    if runtime.exists() {
        let _ = std::fs::remove_dir_all(&runtime);
    }
    Ok(())
}

/// Ask a `[y/N]` question on stdin; anything but y/yes (including EOF) is no.
/// Without a terminal on stdin it is an error, never a wait (callers offer
/// `--yes`).
fn confirm(question: &str) -> std::io::Result<bool> {
    use std::io::{IsTerminal, Write};
    // Without a terminal nobody can answer: a script or test harness would
    // wait forever on a stdin that never closes. Fail at once instead.
    if !std::io::stdin().is_terminal() {
        return Err(std::io::Error::other(format!(
            "{question} needs an answer, but stdin is not a terminal; pass --yes to confirm"
        )));
    }
    print!("{question} [y/N]: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_domain_takes_ports_and_a_known_proto() {
        let parse = |args: &[&str]| {
            Cli::try_parse_from(
                ["soda", "allow", "domain", "example.com"]
                    .iter()
                    .chain(args),
            )
        };
        assert!(parse(&["--ports", "80,443", "--proto", "tcp"]).is_ok());
        assert!(parse(&["--proto", "udp", "--exact"]).is_ok());
        assert!(parse(&["--proto", "icmp"]).is_err());
    }

    #[test]
    fn log_tail_returns_last_n_lines() {
        let dir = std::env::temp_dir().join(format!("sodabox-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("supervisor.log");
        std::fs::write(&path, "a\nb\nc\nd\ne\n").unwrap();

        // Fewer lines than exist → only the tail.
        assert_eq!(log_tail(&path, 2), "d\ne");
        // More lines requested than exist → the whole file (no panic on saturating).
        assert_eq!(log_tail(&path, 99), "a\nb\nc\nd\ne");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_tail_of_a_missing_file_is_a_placeholder_not_a_panic() {
        let missing = std::env::temp_dir().join("sodabox-cli-does-not-exist.log");
        let _ = std::fs::remove_file(&missing);
        assert!(log_tail(&missing, 10).starts_with("(could not read"));
    }
}
