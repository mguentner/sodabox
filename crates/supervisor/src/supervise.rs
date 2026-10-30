//! The supervisor orchestration capstone: compose every built
//! piece into a live, policy-enforced VM and supervise it fail-closed.
//!
//! # Topology (ADR-0004 / ADR-0007)
//!
//! The proxy and DNS resolver must **dial from the host netns** (the VM netns has
//! no route to the internet — that is the enforcement boundary), yet their
//! *listening* sockets must live **in the VM netns** (the TPROXY TCP listener
//! needs `IP_TRANSPARENT`/CAP_NET_ADMIN there; the resolver's UDP listener must
//! receive passt's forwarded queries in-netns). A rootless process cannot
//! `setns` back to the host netns once it unshares, so we **fork**:
//!
//! ```text
//! run() [single-threaded, pre-tokio]
//!  ├─ build guest (nix-build), compute LaunchPlan
//!  ├─ socketpair(parent, child)
//!  └─ fork
//!      ├─ CHILD  (VM netns): PDEATHSIG=KILL → enter_new → lo up → nft.apply
//!      │         → create TPROXY-TCP + resolver-UDP listeners → send fds
//!      │         → spawn passt (PDEATHSIG=KILL) → wait(passt)
//!      └─ PARENT (host netns): recv listener fds → tokio runtime:
//!                proxy(tcp fd)+PolicyDialer · resolver(udp fd) · ControlServer
//!                · spawn cloud-hypervisor · supervise
//!                · teardown: kill child ⇒ passt dies ⇒ netns torn down (fail-closed)
//! ```
//!
//! Killing the child collapses the whole egress path: passt (PDEATHSIG child of
//! the child) dies with it, the netns empties and the kernel tears it down, and
//! the proxy's listener fds go dead. The child's own PDEATHSIG means a parent
//! crash triggers the same collapse — egress can never outlive the supervisor.
//!
//! The pure wiring ([`LaunchPlan::wire`]) and the control handler
//! ([`SupervisorState`]) are unit-tested here; the fork/live path needs a real
//! userns + KVM + passt + nft and is exercised by `sodabox start --net` on a host.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixDatagram as StdUnixDatagram, UnixStream as StdUnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sodabox_common::allowlist::{Allowlist, Proto, SharedAllowlist};
use sodabox_common::event::Event;
use sodabox_common::policy::VmPolicy;
use sodabox_common::vm::{LaunchDisks, Persist, VmMeta};
use sodabox_common::{paths, storage};

use sodabox_dns::domain::SharedDomainAllowlist;
use sodabox_dns::events::DnsEvents;
use sodabox_dns::frontend::DnsFrontend;
use sodabox_dns::FilteringResolver;

use sodabox_proxy::events::EgressEvents;
use sodabox_proxy::policy::{shared, PolicyDialer};
use sodabox_proxy::tcp::{self, DirectDialer, TransparentProxy};
use sodabox_proxy::udp::{self, DirectUdpConnector, TransparentUdpProxy};

use tokio::sync::{broadcast, Notify};

use crate::chv::{Chv, Serial};
use crate::control::{ControlHandler, ControlServer};
use crate::fdpass::Listeners;
use crate::guest::build_guest;
use crate::nft::EgressRules;
use crate::passt::PasstConfig;

/// The transparent TCP proxy's TPROXY target port (nft diverts guest TCP here).
const PROXY_TCP_PORT: u16 = 18443;
/// The UDP TPROXY target port: the transparent UDP filter proxy listens here.
/// Non-DNS guest UDP is diverted to it, allow/deny-evaluated,
/// and allowed flows are relayed with replies injected back via the netns child.
const PROXY_UDP_PORT: u16 = 18444;
/// In-netns address the filtering resolver listens on, and passt's DNS redirect
/// target (`--dns-host`). It sits on the outbound interface [`OUTBOUND_IF`] (see
/// there) rather than on loopback: passt binds its outbound sockets to that
/// interface, so a `127.0.0.53` resolver would be unreachable from passt's DNS
/// forward (verified: guest DNS to loopback resolver times out; spike 0002 put
/// the resolver on the same in-netns address passt uses outbound). Bypassed from
/// TPROXY via nft `direct_daddrs` so the forward is not itself intercepted; the
/// subnet is private to the netns (a black-hole dummy interface).
const RESOLVER_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 53);
const RESOLVER_PORT: u16 = 53;
/// Dummy in-netns interface passt binds its outbound sockets to. passt needs a
/// usable non-loopback interface or it ignores `-a`/`-g` and hands the guest a
/// link-local `169.254.x` address (spike 0002). Its address is [`RESOLVER_IP`]
/// (passt's outbound source doubles as the DNS redirect target, as in the spike),
/// in a subnet distinct from the guest's `10.0.2.0/24`; real egress never leaves
/// via it — it is marked and TPROXY'd onto `lo` to the filter proxy first.
const OUTBOUND_IF: &str = "sb0";
const OUTBOUND_ADDR: Ipv4Addr = RESOLVER_IP;
const OUTBOUND_PREFIX: u8 = 24;
/// Grace before SIGKILL when shutting a child process down.
const GRACE: Duration = Duration::from_secs(10);

/// Everything needed to launch and enforce one VM, computed before the fork so
/// both processes share it (the child inherits it as forked memory).
pub struct LaunchPlan {
    pub name: String,
    /// cloud-hypervisor boot spec (its `net_socket` is passt's vhost-user socket).
    pub boot: crate::chv::GuestBoot,
    /// passt config (upstream DNS pointed at the in-netns resolver).
    pub passt: PasstConfig,
    /// nftables egress interception for the netns.
    pub egress: EgressRules,
    /// Where the resolver's UDP listener binds, in the netns.
    pub resolver_addr: SocketAddr,
    /// Where the TPROXY TCP listener binds, in the netns.
    pub tproxy_addr: SocketAddr,
    /// Where the TPROXY UDP listener binds, in the netns.
    pub udp_tproxy_addr: SocketAddr,
    /// The VM's egress policy (static rules + limits).
    pub policy: VmPolicy,
    /// Upstream DNS servers the resolver forwards allowed names to (host netns).
    pub upstreams: Vec<SocketAddr>,
    /// The host-loopback port of this VM's SSH forward, from its `meta.toml`
    /// (ADR-0011) — an assignment the VM owns, not a per-boot choice.
    pub host_ssh_port: u16,
}

impl LaunchPlan {
    /// Load metadata, build the guest, and wire the plan for `name`. Blocking
    /// (runs `nix-build`); call before the fork, single-threaded.
    pub fn build(name: &str) -> anyhow::Result<LaunchPlan> {
        let meta = VmMeta::load(name).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => {
                anyhow::anyhow!("no such VM '{name}' — run `sodabox create {name}` first")
            }
            _ => anyhow::anyhow!("reading meta.toml for '{name}': {e}"),
        })?;
        let mem_mib =
            storage::parse_mem_mib(&meta.mem).map_err(|e| anyhow::anyhow!("meta mem: {e}"))?;

        let host_ssh_port = meta.ssh_port;

        let policy = VmPolicy::load(name).map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
        let upstreams = FilteringResolver::upstreams_from_resolv_conf().unwrap_or_default();

        println!("building guest for '{name}' (nix-build mkGuest)…");
        let built = build_guest(&paths::resolve_guest_dir(name))?;
        println!("  kernel:   {}", built.kernel.display());
        println!("  toplevel: {}", built.toplevel.display());

        // SSH access (ADR-0011): ensure the tool key and build the
        // read-only config disk carrying authorized_keys. Rebuilt every launch so
        // key changes apply without rebuilding the immutable store image.
        std::fs::create_dir_all(paths::runtime_dir(name))?;
        let config_img = build_config_disk_for(name, &meta)?;

        // Read-write disks per persistence mode (ADR-0014): scratch disks are
        // laid down fresh. Done after the build, so a failing nix-build doesn't
        // leave one behind.
        let disks = meta.prepare_disks()?;
        println!("  persist:  {}", meta.persist);

        Ok(Self::wire(
            name,
            meta.cpus,
            mem_mib,
            &built,
            config_img,
            disks,
            policy,
            upstreams,
            host_ssh_port,
        ))
    }

    /// Pure wiring of the component configs from resolved inputs (unit-tested).
    #[allow(clippy::too_many_arguments)]
    pub fn wire(
        name: &str,
        cpus: u32,
        mem_mib: u64,
        built: &crate::guest::BuiltGuest,
        config_img: Option<PathBuf>,
        disks: LaunchDisks,
        policy: VmPolicy,
        upstreams: Vec<SocketAddr>,
        host_ssh_port: u16,
    ) -> LaunchPlan {
        let passt_socket = paths::passt_sock_path(name);
        let console = paths::console_path(name);
        // cloud-hypervisor's API socket: used only to request a clean ACPI
        // power-off on stop. Short path (runtime dir) to stay under
        // SUN_LEN, like passt.sock.
        let api_socket = paths::chv_api_sock_path(name);

        // cloud-hypervisor talks to passt's vhost-user socket; the API socket
        // drives the clean shutdown.
        let boot = built.to_boot(
            cpus,
            mem_mib,
            config_img,
            disks,
            Some(passt_socket.clone()),
            Some(api_socket),
            Serial::File(console),
        );

        let passt = PasstConfig::new(passt_socket)
            .with_resolver(RESOLVER_IP)
            .with_outbound(OUTBOUND_ADDR)
            // Inbound SSH forward (ADR-0011): passt listens on the netns
            // loopback and forwards to guest:22; the supervisor bridges host
            // loopback into it (see `serve`/`child_main` + `crate::ssh_forward`).
            .with_inbound_ssh(crate::ssh_forward::PASST_SSH_PORT);

        // Deny-by-default TPROXY interception; the resolver address bypasses so
        // passt's DNS forward reaches it directly, and loopback↔loopback bypasses
        // so the SSH forward relay can reach passt's in-netns inbound listener
        // without being diverted to the filter proxy and denied.
        let mut egress = EgressRules::new(PROXY_TCP_PORT, PROXY_UDP_PORT);
        egress.direct_daddrs = vec![RESOLVER_IP];
        egress.allow_loopback = true;

        LaunchPlan {
            name: name.to_string(),
            boot,
            passt,
            egress,
            resolver_addr: SocketAddr::from((RESOLVER_IP, RESOLVER_PORT)),
            tproxy_addr: SocketAddr::from((Ipv4Addr::UNSPECIFIED, PROXY_TCP_PORT)),
            udp_tproxy_addr: SocketAddr::from((Ipv4Addr::UNSPECIFIED, PROXY_UDP_PORT)),
            policy,
            upstreams,
            host_ssh_port,
        }
    }
}

/// Assemble the guest `authorized_keys` (the tool key only; ADR-0011) and build
/// the read-only config disk for `name`, returning its path. Rebuilt every launch.
///
/// A `persist = "none"` VM cannot keep its own sshd host key, so its host-held,
/// pre-pinned key rides along on the config disk (ADR-0014).
/// So does the VM's `dotfiles/` copy, when it has one (ADR-0019).
pub fn build_config_disk_for(name: &str, meta: &VmMeta) -> anyhow::Result<Option<PathBuf>> {
    let authorized_keys = sodabox_common::ssh::authorized_keys()
        .map_err(|e| anyhow::anyhow!("assembling authorized_keys: {e}"))?;
    let host_key = match meta.persist {
        Persist::None => Some(
            sodabox_common::ssh::pinned_guest_host_key(name)
                .map_err(|e| anyhow::anyhow!("preparing the host-held sshd host key: {e}"))?,
        ),
        Persist::Full | Persist::Home => None,
    };
    let out = paths::config_img_path(name);
    // The VM's dotfiles (ADR-0019), if it was created with any.
    let dotfiles = paths::vm_dotfiles_dir(name);
    let dotfiles = dotfiles.is_dir().then_some(dotfiles.as_path());
    crate::config_disk::build_config_disk(&out, &authorized_keys, host_key.as_deref(), dotfiles)?;
    Ok(Some(out))
}

/// Launch, enforce and supervise VM `name` until it exits or is stopped. Must be
/// called single-threaded, before any tokio runtime exists (it forks and the
/// child unshares a user namespace).
///
/// Runs attached, writing progress to stdout/stderr. When `log` is `Some`, the
/// process's stdout/stderr are redirected to that file *after* the stale runtime
/// dir is wiped and recreated — this is how a detached/background start (the
/// default) captures supervisor output where the launcher can tail
/// it. The foreground path passes `None` and keeps the terminal.
pub fn run(name: &str) -> anyhow::Result<()> {
    run_with_log(name, None)
}

/// [`run`], optionally redirecting stdout/stderr to `log` once the runtime dir is
/// prepared (see [`run`]).
pub fn run_with_log(name: &str, log: Option<PathBuf>) -> anyhow::Result<()> {
    // Take the data-disk lock before any expensive work (nix-build, fork), so a
    // second supervisor for the same VM fails fast rather than racing to attach
    // the same data.img (ADR-0008). The host-netns parent holds it
    // for the VM's lifetime; it is released when the parent exits, or by the
    // kernel if it crashes (no stale lock).
    let data_lock = storage::DataImgLock::acquire(name)?;

    let result = launch_locked(name, log, &data_lock);

    // Whatever the outcome (clean stop, crash of the guest, failed launch), a
    // `home`/`none` VM's scratch disk goes now, while the lock still proves no
    // one else is using it (ADR-0014). Only the host-netns parent gets here: the
    // forked child exits inside `launch_locked`.
    if let Ok(meta) = VmMeta::load(name) {
        if let Err(e) = meta.discard_scratch() {
            eprintln!("sodabox: could not delete the scratch disk of '{name}': {e}");
        }
    }
    // The VM is gone; release the data-disk lock explicitly.
    drop(data_lock);
    result
}

/// The body of [`run_with_log`], run with the data-disk lock held.
fn launch_locked(
    name: &str,
    log: Option<PathBuf>,
    data_lock: &Option<storage::DataImgLock>,
) -> anyhow::Result<()> {
    // Clear any stale runtime state from an unclean shutdown (crashed kill,
    // old boot): old chv-api.sock/passt.sock/control.sock files would block
    // rebinds (ADR-0007). Holding the data-disk lock above proves no live
    // supervisor for this VM, so whatever is left in the runtime dir is stale.
    // Before `build` so it cannot delete a freshly built config.img.
    paths::wipe_runtime_dir(name)?;

    // Detached start: send supervisor output to the log now — after the wipe (so
    // it isn't immediately unlinked) but before the slow `build`, so nix-build
    // progress and any failure land where the launcher can read them.
    if let Some(log) = &log {
        std::fs::create_dir_all(paths::runtime_dir(name))?;
        redirect_stdio_to(log)?;
    }

    let plan = LaunchPlan::build(name)?;

    // Ensure the runtime dir exists before either side needs it (sockets, fds).
    std::fs::create_dir_all(paths::runtime_dir(name))?;
    // Publish the host-side supervisor pid (ADR-0007 runtime layout): it marks
    // the dir as live while the VM runs, so a crashed supervisor's leftovers
    // are recognizable as stale.
    std::fs::write(paths::pid_path(name), std::process::id().to_string())?;

    let (parent_sock, child_sock) = StdUnixStream::pair()?;
    // The UDP reply channel: the host-netns proxy frames replies onto `inj_parent`
    // and the netns child injects them from `inj_child`.
    let (inj_parent, inj_child) = StdUnixDatagram::pair()?;
    // The SSH forward channel (ADR-0011): the host-netns parent accepts SSH
    // clients on host loopback and passes each accepted fd to the netns child over
    // `ssh_fd_*`, which splices it to passt's in-netns forward (→ guest:22).
    let (ssh_fd_parent, ssh_fd_child) = StdUnixStream::pair()?;

    // SAFETY: single-threaded here (no runtime started yet); the child touches
    // only async-signal-safe / fork-safe operations before it either execs
    // subprocesses or exits.
    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Child => {
            drop(parent_sock);
            drop(inj_parent);
            drop(ssh_fd_parent);
            // The child shares the parent's data-lock fd. It must NOT release it
            // (dropping the guard would LOCK_UN the shared open file description
            // and unlock the parent too). `process::exit` below skips destructors,
            // so we deliberately leave `data_lock` untouched here.
            let _ = data_lock;
            // The child never returns to the caller; it exits with a status code.
            let code = match child_main(&plan, child_sock, inj_child, ssh_fd_child) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("sodabox supervisor child: {e}");
                    1
                }
            };
            std::process::exit(code);
        }
        nix::unistd::ForkResult::Parent { child } => {
            drop(child_sock);
            drop(inj_child);
            drop(ssh_fd_child);
            parent_main(plan, parent_sock, inj_parent, ssh_fd_parent, child)
        }
    }
}

/// Child (VM netns owner): build the namespace, install egress rules, create the
/// listener sockets, hand them to the parent, then run passt and keep the netns
/// alive for the VM's lifetime.
fn child_main(
    plan: &LaunchPlan,
    sock: StdUnixStream,
    inj_child: StdUnixDatagram,
    ssh_fd_child: StdUnixStream,
) -> anyhow::Result<()> {
    // Die if the supervisor (our parent) dies: collapses passt + the netns.
    set_pdeathsig_kill()?;

    crate::netns::enter_new()?;
    crate::netns::bring_up_loopback()?;
    // passt's outbound interface: without it passt ignores our addressing and the
    // guest gets a useless 169.254.x address (spike 0002). Real egress out of it
    // is marked + TPROXY'd onto `lo` by the rules below, so it is a black hole.
    crate::netns::create_outbound_iface(OUTBOUND_IF, OUTBOUND_ADDR, OUTBOUND_PREFIX)?;
    plan.egress.apply()?;

    // Create the listeners *in the netns* (CAP_NET_ADMIN held here) and pass them
    // to the host-netns parent; the sockets stay bound to this netns.
    let tproxy = tcp::bind_transparent_std(plan.tproxy_addr)?;
    let resolver = std::net::UdpSocket::bind(plan.resolver_addr)?;
    let tproxy_udp = udp::bind_transparent_udp_std(plan.udp_tproxy_addr)?;
    Listeners::send(&sock, tproxy.as_fd(), resolver.as_fd(), tproxy_udp.as_fd())?;
    // The parent owns dup'd copies now; drop ours so only it holds them.
    drop(tproxy);
    drop(resolver);
    drop(tproxy_udp);

    // Run the UDP reply injector for the VM's lifetime. It owns the
    // transparent forged-source sends the host-netns proxy cannot do; a thread is
    // fine now that the single-threaded unshare is done. It exits when the channel
    // closes (parent gone) — and PDEATHSIG collapses us first anyway.
    std::thread::spawn(move || {
        if let Err(e) = crate::udp_inject::run_injector(inj_child) {
            eprintln!("sodabox udp injector: {e}");
        }
    });

    // SSH forward relay (ADR-0011): splice each host-loopback connection
    // the parent hands us into passt's in-netns forward (127.0.0.1:<port> →
    // guest:22). Only active when the plan enabled the inbound forward.
    if let Some(passt_port) = plan.passt.inbound_ssh_port {
        std::thread::spawn(move || {
            crate::ssh_forward::serve_netns_relay(ssh_fd_child, passt_port);
        });
    } else {
        drop(ssh_fd_child);
    }

    // Spawn passt as our child so it inherits the netns; PDEATHSIG ties it to us,
    // so it dies when we do (and thus when the supervisor does).
    let mut cmd = std::process::Command::new(passt_bin());
    cmd.args(plan.passt.args())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    // SAFETY: only an async-signal-safe prctl between fork and exec.
    unsafe {
        cmd.pre_exec(set_pdeathsig_kill);
    }
    let mut passt = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn passt: {e}"))?;

    // Keep the netns alive until passt exits (or the parent kills us).
    let status = passt.wait()?;
    if !status.success() {
        anyhow::bail!("passt exited: {status}");
    }
    Ok(())
}

/// Redirect this process's stdout and stderr to `log` (created `0600`, appended
/// to), for a detached supervisor. stdin is left as the daemonizer set it
/// (`/dev/null`). Uses `dup2` so `println!`/`eprintln!` and any child that
/// inherits fds 1/2 all land in the same file.
fn redirect_stdio_to(log: &std::path::Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log)?;
    let fd = file.as_raw_fd();
    for target in [nix::libc::STDOUT_FILENO, nix::libc::STDERR_FILENO] {
        // SAFETY: dup2 onto the standard fds; `fd` is a valid open file.
        if unsafe { nix::libc::dup2(fd, target) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn passt_bin() -> std::ffi::OsString {
    std::env::var_os("SODABOX_PASST").unwrap_or_else(|| "passt".into())
}

/// Arrange for `SIGKILL` when this process's parent dies (`PR_SET_PDEATHSIG`).
/// Async-signal-safe (a single `prctl`), so it is usable in a `pre_exec` hook.
fn set_pdeathsig_kill() -> io::Result<()> {
    // SAFETY: prctl with PR_SET_PDEATHSIG is a plain syscall with no memory effects.
    let rc = unsafe {
        nix::libc::prctl(
            nix::libc::PR_SET_PDEATHSIG,
            nix::libc::SIGKILL as nix::libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Parent (host netns): adopt the listener fds and run the enforcement + control
/// plane, spawn cloud-hypervisor, and supervise until exit — then tear the child
/// (and with it the whole egress path) down.
fn parent_main(
    plan: LaunchPlan,
    sock: StdUnixStream,
    inj_parent: StdUnixDatagram,
    ssh_fd_parent: StdUnixStream,
    child: nix::unistd::Pid,
) -> anyhow::Result<()> {
    // Blocking receive of the three listener fds the child created in the netns.
    let listeners = Listeners::recv(&sock).map_err(|e| {
        // If the child failed before sending, reap it and surface that.
        let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(child, None);
        anyhow::anyhow!("receiving listener fds from netns child: {e}")
    })?;

    let name = plan.name.clone();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(serve(plan, listeners, inj_parent, ssh_fd_parent, child));

    // Teardown always runs: kill the netns owner so passt + the netns collapse.
    teardown_child(child);
    // Clean exit: the VM keeps no state in its runtime dir (data lives in
    // $XDG_DATA_HOME, ADR-0008), so a clean stop leaves no sockets, the old
    // chv-api/passt files, console.log or the ssh endpoint (ADR-0007).
    let _ = paths::wipe_runtime_dir(&name);
    result
}

/// The async body running in the host netns: enforcement, DNS, control, guest.
async fn serve(
    plan: LaunchPlan,
    listeners: Listeners,
    inj_parent: StdUnixDatagram,
    ssh_fd_parent: StdUnixStream,
    child: nix::unistd::Pid,
) -> anyhow::Result<()> {
    // Adopt the netns-created listeners into this (host-netns) runtime.
    let tcp_listener = unsafe { tcp::listener_from_raw_fd(listeners.tproxy_tcp.into_raw_fd()) }?;
    // SAFETY: fresh owned fd from SCM_RIGHTS; nobody else holds it.
    let udp_std = unsafe { std::net::UdpSocket::from_raw_fd(listeners.resolver_udp.into_raw_fd()) };
    // SAFETY: as above — the passed transparent-UDP TPROXY listener.
    let udp_tproxy_std =
        unsafe { std::net::UdpSocket::from_raw_fd(listeners.tproxy_udp.into_raw_fd()) };

    // Shared, deny-by-default allowlist the resolver admits into and the proxy
    // reads; fail-closed on a poisoned lock (both sides treat it as Deny).
    let allowlist = shared(
        Allowlist::from_policy(&plan.policy).map_err(|e| anyhow::anyhow!("invalid policy: {e}"))?,
    );

    // Event fan-out for the control socket's `subscribe`. One `BroadcastEvents`
    // sink serves both the proxy's egress verdicts (`EgressEvents`) and the
    // resolver's DNS verdicts (`DnsEvents`) — same allocation, two trait views.
    let (events_tx, _keepalive) = broadcast::channel::<Event>(1024);
    // Persist the stream to the per-VM log for post-hoc audit.
    // Subscribe before any producer starts so no event is missed; the writer is
    // best-effort and detached (losing the audit log must never fail the VM).
    tokio::spawn(crate::eventlog::run(
        paths::event_log_path(&plan.name),
        events_tx.subscribe(),
    ));
    let event_sink = Arc::new(BroadcastEvents(events_tx.clone()));
    let events: Arc<dyn EgressEvents> = event_sink.clone();

    // Filter proxy: enforce the allowlist, dial the allow-path from *this* (host)
    // netns so it isn't re-intercepted, and emit allowed/blocked events.
    let dialer = Arc::new(
        PolicyDialer::new(allowlist.clone(), Arc::new(DirectDialer), Proto::Tcp)
            .with_events(events.clone()),
    );
    // The proxy and resolver are the **egress-control plane** — the guest must
    // never run without them (fail-closed). Their JoinHandles are
    // supervised in the select! below: if either `serve()` loop returns or panics,
    // we power the guest off rather than leave it running with a dead/absent
    // filter. (Egress is already denied structurally when the proxy is gone —
    // nothing accepts the TPROXY-diverted connections — but a silent zombie is
    // not an acceptable state; we make the failure deterministic and observable.)
    let mut proxy_task = tokio::spawn(TransparentProxy::new(tcp_listener, dialer).serve());

    // Filtering DNS resolver on the passed netns UDP listener; emits DNS
    // allowed/refused verdicts onto the same event stream.
    let resolver = Arc::new(
        FilteringResolver::new(&plan.policy, allowlist.clone(), plan.upstreams.clone())
            .map_err(|e| anyhow::anyhow!("resolver: {e}"))?
            .with_events(event_sink.clone()),
    );
    // Grab the resolver's live domain-allowlist handle *before* it is moved into
    // the serve task, so a `PolicySet` can swap the resolver's domain rules too —
    // without it, allowing a new domain updates the proxy + UI but the resolver
    // keeps refusing the name, so the proxy never sees an allow.
    let domains = resolver.domains();
    let mut dns_task = tokio::spawn(DnsFrontend::from_std(udp_std)?.serve(resolver));

    // Transparent UDP filter proxy: recover each datagram's
    // original dst, enforce the allowlist, and relay allowed flows — replies go
    // through `inj_parent` to the netns-child injector (forged source = orig dst).
    // Also fail-closed-critical (a dead UDP filter must not leave the guest up).
    inj_parent
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("set udp reply channel nonblocking: {e}"))?;
    udp_tproxy_std
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("set udp tproxy socket nonblocking: {e}"))?;
    let udp_tproxy = tokio::net::UdpSocket::from_std(udp_tproxy_std)?;
    let sink = Arc::new(crate::udp_inject::ChannelReplySink::new(inj_parent));
    let udp_proxy = TransparentUdpProxy::new(
        udp_tproxy,
        allowlist.clone(),
        Arc::new(DirectUdpConnector),
        sink,
    )
    .with_events(events);
    let mut udp_task = tokio::spawn(udp_proxy.serve());

    // Control + event socket. Unlike the proxy/resolver, this is *not*
    // fail-closed-critical: losing the management socket costs observability and
    // control but cannot open egress, so its exit does not tear the guest down.
    let state = Arc::new(SupervisorState::new(
        plan.policy.clone(),
        allowlist.clone(),
        domains,
        events_tx,
    ));
    let control = ControlServer::bind(&plan.name, state.clone())?;
    tokio::spawn(control.serve());

    // SSH forward (ADR-0011): bind the host-loopback listener, publish the
    // live `host:port` for the CLI, and hand accepted connections to the netns
    // child (which splices them into passt's in-netns forward → guest:22). Bound
    // before the guest boots so the endpoint file is ready by the time it is up.
    if plan.passt.inbound_ssh_port.is_some() {
        match crate::ssh_forward::bind_vm_forward(&plan.name, plan.host_ssh_port) {
            Ok((listener, port)) => {
                let endpoint = format!("{}:{port}", Ipv4Addr::LOCALHOST);
                let path = paths::ssh_endpoint_path(&plan.name);
                if let Err(e) = std::fs::write(&path, format!("{endpoint}\n")) {
                    eprintln!(
                        "sodabox: could not write ssh endpoint {}: {e}",
                        path.display()
                    );
                }
                println!(
                    "ssh forward: {endpoint} -> guest:22 (sodabox ssh {})",
                    plan.name
                );
                std::thread::spawn(move || {
                    crate::ssh_forward::serve_host_listener(listener, ssh_fd_parent);
                });
            }
            Err(e) => {
                // Non-fatal: the guest still runs (console/other access remains);
                // only the SSH forward is unavailable.
                eprintln!("sodabox: SSH forward disabled (no host loopback port): {e}");
                drop(ssh_fd_parent);
            }
        }
    } else {
        drop(ssh_fd_parent);
    }

    // cloud-hypervisor connects to passt's vhost-user socket, which the netns
    // child brings up in parallel — wait for it so the connect doesn't race.
    if let Some(sock) = plan.boot.net_socket.clone() {
        wait_for_path(&sock, Duration::from_secs(10))
            .await
            .map_err(|_| {
                anyhow::anyhow!("passt vhost-user socket {} did not appear", sock.display())
            })?;
    }

    // Finally the guest.
    println!(
        "launching cloud-hypervisor for '{}' ({} vCPU)…",
        plan.name, plan.boot.cpus
    );
    let mut chv = Chv::spawn(&plan.boot).await?;
    if let Some(pid) = chv.pid() {
        println!("guest running (chv pid {pid}, netns child {child}); Ctrl-C to stop");
    }

    // SIGTERM is the systemd/`kill` stop signal (and what a supervising parent
    // sends), so it must trigger the same graceful teardown as Ctrl-C (SIGINT) —
    // otherwise the supervisor dies without powering off cloud-hypervisor, leaking
    // the guest (egress still fails closed via PDEATHSIG, but the VM lingers).
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("install SIGTERM handler: {e}"))?;

    tokio::select! {
        status = chv.wait() => {
            println!("guest exited: {}", status?);
        }
        _ = state.stopped() => {
            println!("stop requested; powering off guest…");
            let status = chv.shutdown(GRACE).await?;
            println!("guest stopped: {status}");
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nshutting down…");
            let status = chv.shutdown(GRACE).await?;
            println!("guest stopped: {status}");
        }
        _ = sigterm.recv() => {
            println!("\nSIGTERM; powering off guest…");
            let status = chv.shutdown(GRACE).await?;
            println!("guest stopped: {status}");
        }
        // Fail-closed: the egress filter died — its `serve()`
        // loop returned (fatal accept error) or the task panicked. Never keep the
        // guest running without its filter; power it off and fail loudly.
        r = &mut proxy_task => {
            let status = chv.shutdown(GRACE).await?;
            println!("guest stopped: {status}");
            anyhow::bail!("egress filter proxy exited ({}); powered off guest (fail-closed)", describe_join(r));
        }
        r = &mut dns_task => {
            let status = chv.shutdown(GRACE).await?;
            println!("guest stopped: {status}");
            anyhow::bail!("filtering resolver exited ({}); powered off guest (fail-closed)", describe_join(r));
        }
        r = &mut udp_task => {
            let status = chv.shutdown(GRACE).await?;
            println!("guest stopped: {status}");
            anyhow::bail!("udp filter proxy exited ({}); powered off guest (fail-closed)", describe_join(r));
        }
    }
    Ok(())
}

/// Render the outcome of a supervised enforcement-plane task for a fail-closed
/// error message: an `Err(io::Error)` from `serve()`, a clean `Ok(())` return
/// (the loop should never terminate normally), or a `JoinError` (task panicked or
/// was cancelled). Kept pure so it is unit-testable without a live runtime.
fn describe_join(res: Result<io::Result<()>, tokio::task::JoinError>) -> String {
    match res {
        Ok(Ok(())) => "serve loop returned unexpectedly".to_string(),
        Ok(Err(e)) => format!("serve error: {e}"),
        Err(join) if join.is_panic() => "task panicked".to_string(),
        Err(join) => format!("task cancelled: {join}"),
    }
}

/// Poll for `path` to exist, up to `timeout`. Used to wait for passt to bind its
/// vhost-user socket before cloud-hypervisor connects.
async fn wait_for_path(path: &std::path::Path, timeout: Duration) -> Result<(), ()> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if path.exists() {
        Ok(())
    } else {
        Err(())
    }
}

/// SIGTERM then SIGKILL the netns-owning child, and reap it. Idempotent-ish:
/// ESRCH (already gone) is ignored.
fn teardown_child(child: nix::unistd::Pid) {
    use nix::sys::signal::{kill, Signal};
    let _ = kill(child, Signal::SIGTERM);
    // Give it a moment, then make sure.
    std::thread::sleep(Duration::from_millis(200));
    let _ = kill(child, Signal::SIGKILL);
    let _ = nix::sys::wait::waitpid(child, None);
}

/// Forwards events onto the broadcast channel the control socket serves. Both
/// the proxy (egress verdicts) and the resolver (DNS verdicts) emit through it.
struct BroadcastEvents(broadcast::Sender<Event>);
impl EgressEvents for BroadcastEvents {
    fn emit(&self, event: Event) {
        // No subscribers is fine; drop the event.
        let _ = self.0.send(event);
    }
}
impl DnsEvents for BroadcastEvents {
    fn emit(&self, event: Event) {
        let _ = self.0.send(event);
    }
}

/// The live VM runtime state the control socket ([`ControlHandler`]) operates on.
pub struct SupervisorState {
    policy: Mutex<VmPolicy>,
    allowlist: SharedAllowlist,
    domains: SharedDomainAllowlist,
    events: broadcast::Sender<Event>,
    stop: Notify,
}

impl SupervisorState {
    pub fn new(
        policy: VmPolicy,
        allowlist: SharedAllowlist,
        domains: SharedDomainAllowlist,
        events: broadcast::Sender<Event>,
    ) -> Self {
        Self {
            policy: Mutex::new(policy),
            allowlist,
            domains,
            events,
            stop: Notify::new(),
        }
    }

    /// Completes once `stop` has been requested over the control socket.
    pub async fn stopped(&self) {
        self.stop.notified().await;
    }
}

impl ControlHandler for SupervisorState {
    fn status(&self) -> (String, u32) {
        (
            "running".to_string(),
            self.policy.lock().map(|p| p.version).unwrap_or(0),
        )
    }

    fn policy_get(&self) -> VmPolicy {
        self.policy.lock().map(|p| p.clone()).unwrap_or_default()
    }

    fn policy_set(&self, policy: VmPolicy) -> Result<(), String> {
        // Live swap: atomically replace static rules + version and
        // purge only the ephemerals of removed domains, keeping surviving domains'
        // cached IPs (working flows are not disrupted). `swap_policy` validates the
        // new policy before mutating, so a bad policy is rejected leaving the live
        // allowlist untouched; the write lock makes the swap atomic to readers.
        {
            let mut al = self
                .allowlist
                .write()
                .map_err(|_| "allowlist poisoned".to_string())?;
            al.swap_policy(&policy)?;
        }
        // Swap the DNS filter's domain rules too: the resolver is a
        // third policy consumer whose domain allowlist would otherwise stay frozen
        // at boot, so a newly-allowed domain would keep being refused and never
        // reach the proxy as an admitted ephemeral. `swap_policy` validates before
        // mutating; the write lock keeps it atomic to the query path.
        {
            let mut d = self
                .domains
                .write()
                .map_err(|_| "domain allowlist poisoned".to_string())?;
            d.swap_policy(&policy)?;
        }
        let mut p = self
            .policy
            .lock()
            .map_err(|_| "policy poisoned".to_string())?;
        *p = policy;
        Ok(())
    }

    // Raw single-rule editing over the socket is intentionally not a write path:
    // the CLI is the sole writer of policy.toml — it parses the
    // rule, updates the file, and pushes the whole new policy via `PolicySet`
    // (see `policy_set`). Keeping one writer avoids file/live split-brain.
    fn allow(&self, _rule: &str) -> Result<(), String> {
        Err("use `sodabox allow …` (it edits policy.toml and pushes PolicySet)".to_string())
    }

    fn deny(&self, _rule: &str) -> Result<(), String> {
        Err("use `sodabox deny …` (it edits policy.toml and pushes PolicySet)".to_string())
    }

    fn stop(&self) {
        // notify_one stores a permit even if `stopped()` isn't awaiting yet, so a
        // stop that races the select! is never lost.
        self.stop.notify_one();
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodabox_common::event::{Event, Verdict};
    use sodabox_common::policy::{Rule, VmPolicy};
    use sodabox_dns::domain::{self, DomainAllowlist};

    /// An empty shared domain allowlist for wiring [`SupervisorState`] in tests.
    fn empty_domains() -> SharedDomainAllowlist {
        domain::shared(DomainAllowlist::from_policy(&VmPolicy::default()).unwrap())
    }

    fn built() -> crate::guest::BuiltGuest {
        crate::guest::BuiltGuest {
            kernel: PathBuf::from("/nix/store/k"),
            initrd: PathBuf::from("/nix/store/i"),
            store: PathBuf::from("/nix/store/s.erofs"),
            toplevel: PathBuf::from("/nix/store/t"),
        }
    }

    #[test]
    fn wire_connects_the_components() {
        let plan = LaunchPlan::wire(
            "web",
            2,
            2048,
            &built(),
            None,
            LaunchDisks::default(),
            VmPolicy::default(),
            vec![],
            3522,
        );

        // cloud-hypervisor is pointed at the same passt socket passt is told to
        // create — the vhost-user rendezvous.
        assert_eq!(plan.boot.net_socket.as_ref(), Some(&plan.passt.socket));

        // passt redirects intercepted guest DNS to the in-netns resolver
        // (--dns-host), which nft bypasses so the forward is not itself TPROXY'd.
        // The guest itself is told the guest-facing forward address, not the resolver.
        assert_eq!(plan.passt.dns_host, Some(RESOLVER_IP));
        assert!(plan.egress.direct_daddrs.contains(&RESOLVER_IP));
        assert_eq!(
            plan.resolver_addr,
            SocketAddr::from((RESOLVER_IP, RESOLVER_PORT))
        );

        // The TPROXY listener port the proxy binds matches the nft divert target.
        assert_eq!(plan.tproxy_addr.port(), plan.egress.tcp_port);
        assert_eq!(plan.tproxy_addr.port(), PROXY_TCP_PORT);

        // The SSH forward is wired: passt gets the in-netns inbound listener and
        // the plan carries the VM's assigned host-side port.
        assert_eq!(
            plan.passt.inbound_ssh_port,
            Some(crate::ssh_forward::PASST_SSH_PORT)
        );
        assert_eq!(plan.host_ssh_port, 3522);
    }

    #[test]
    fn state_status_and_stop() {
        let (tx, _rx) = broadcast::channel(4);
        let al = shared(
            Allowlist::from_policy(&VmPolicy {
                version: 3,
                ..VmPolicy::default()
            })
            .unwrap(),
        );
        let state = SupervisorState::new(
            VmPolicy {
                version: 3,
                ..VmPolicy::default()
            },
            al,
            empty_domains(),
            tx,
        );

        let (s, v) = state.status();
        assert_eq!(s, "running");
        assert_eq!(v, 3);

        // stop() before stopped() is awaited must still resolve (notify_one permit).
        state.stop();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async { state.stopped().await });
    }

    #[test]
    fn policy_set_rebuilds_allowlist_and_rejects_bad() {
        let (tx, _rx) = broadcast::channel(4);
        let al = shared(Allowlist::from_policy(&VmPolicy::default()).unwrap());
        let state = SupervisorState::new(VmPolicy::default(), al.clone(), empty_domains(), tx);

        // Valid update takes effect and is reflected by policy_get.
        let good = VmPolicy {
            version: 9,
            rules: vec![Rule::Ip {
                cidr: "10.0.0.0/8".into(),
                ports: None,
                proto: None,
            }],
            ..VmPolicy::default()
        };
        assert!(state.policy_set(good).is_ok());
        assert_eq!(state.policy_get().version, 9);

        // Invalid policy is rejected and leaves the live policy unchanged.
        let bad = VmPolicy {
            version: 10,
            rules: vec![Rule::Ip {
                cidr: "not-a-cidr".into(),
                ports: None,
                proto: None,
            }],
            ..VmPolicy::default()
        };
        assert!(state.policy_set(bad).is_err());
        assert_eq!(state.policy_get().version, 9);
    }

    #[test]
    fn policy_set_swaps_the_resolver_domain_rules_live() {
        // a live PolicySet that allows a new domain must update the
        // DNS filter's domain allowlist too, or the resolver keeps refusing the
        // name and the proxy never sees an admitted ephemeral for that host.
        let (tx, _rx) = broadcast::channel(4);
        let al = shared(Allowlist::from_policy(&VmPolicy::default()).unwrap());
        let domains = empty_domains();
        let state = SupervisorState::new(VmPolicy::default(), al, domains.clone(), tx);

        // Boot state: nothing allowed, so the resolver refuses the domain.
        assert!(domains.read().unwrap().matches("api.example.com").is_none());

        // Allow it live.
        let good = VmPolicy {
            version: 1,
            rules: vec![Rule::Domain {
                name: "example.com".into(),
                scope: sodabox_common::policy::DomainScope::Subdomains,
                ports: None,
                proto: None,
            }],
            ..VmPolicy::default()
        };
        assert!(state.policy_set(good).is_ok());

        // The resolver's shared handle now matches the newly-allowed domain.
        assert!(domains.read().unwrap().matches("api.example.com").is_some());
    }

    #[test]
    fn describe_join_covers_every_failclosed_outcome() {
        // A clean return is itself anomalous for an enforcement loop.
        assert_eq!(
            describe_join(Ok(Ok(()))),
            "serve loop returned unexpectedly"
        );
        // A fatal accept error is surfaced verbatim.
        let msg = describe_join(Ok(Err(io::Error::other("boom"))));
        assert!(msg.contains("serve error: boom"), "{msg}");

        // A panicked task maps to the panic branch (build a real JoinError).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let panic_err = rt.block_on(async {
            tokio::spawn(async { panic!("filter down") })
                .await
                .unwrap_err()
        });
        assert!(panic_err.is_panic());
        assert_eq!(describe_join(Err(panic_err)), "task panicked");
    }

    #[test]
    fn subscribe_receives_broadcast_events() {
        let (tx, _rx) = broadcast::channel(4);
        let al = shared(Allowlist::from_policy(&VmPolicy::default()).unwrap());
        let state = SupervisorState::new(VmPolicy::default(), al, empty_domains(), tx.clone());

        let mut sub = state.subscribe();
        let ev = Event::Egress {
            ts: 1,
            verdict: Verdict::Blocked,
            proto: "tcp".into(),
            daddr: "203.0.113.1".into(),
            dport: 443,
            rule: None,
        };
        tx.send(ev).unwrap();
        let got = sub.try_recv().unwrap();
        assert!(matches!(got, Event::Egress { dport: 443, .. }));
    }
}
