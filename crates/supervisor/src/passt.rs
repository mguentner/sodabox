//! passt as cloud-hypervisor's vhost-user network backend, run inside the
//! per-VM network namespace (spike 0002).
//!
//! The supervisor has already entered the netns ([`crate::netns`]); passt is
//! spawned as its child so it inherits that netns, which means passt's *outbound*
//! sockets live in the netns and are therefore subject to the nftables egress
//! interception installed there. cloud-hypervisor connects to passt's
//! `--vhost-user` unix socket ([`chv::GuestBoot::net_socket`]) and the two move
//! guest L2 frames over shared memory (`--memory shared=on`, enforced in chv).
//!
//! passt also terminates the guest's DNS. Per passt's model (`passt(1)`): `-D`
//! tells the guest (via DHCP) which nameserver to use, `--dns-forward addr`
//! intercepts guest queries sent to `addr`, and `--dns-host` is the real resolver
//! those intercepted queries are redirected to. sodabox hands the guest
//! `dns_forward` (`-D` + `--dns-forward`, both 10.0.2.3) and redirects to the
//! in-netns filtering resolver via `--dns-host` (`dns_host`; ADR-0005).
//! (Note: `-D` must be the *guest-facing* address, not the resolver — passt gives
//! `-D` to the guest unremapped, so a loopback resolver there would be unreachable.)
//!
//! The DNS search list is pinned too (`-S`, [`GUEST_SEARCH_DOMAIN`]): by default
//! passt hands the guest the host's `/etc/resolv.conf` search domains via
//! DHCP/DHCPv6/NDP, which would leak the host's network identity.

use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::process::{Child, Command};

/// Environment override for the passt binary (pinned on PATH by the
/// packaging wrapper).
const PASST_BIN_ENV: &str = "SODABOX_PASST";

/// Static DNS search domain handed to every guest in place of the host's.
/// `.internal` is reserved for private use, so it never resolves publicly.
pub const GUEST_SEARCH_DOMAIN: &str = "sodabox.internal";

fn passt_bin() -> OsString {
    std::env::var_os(PASST_BIN_ENV).unwrap_or_else(|| OsString::from("passt"))
}

/// Configuration for one passt instance. Addresses default to passt's usual
/// 10.0.2.0/24 slirp-style layout; all of them are private to the per-VM netns
/// and fully under sodabox's control.
#[derive(Debug, Clone)]
pub struct PasstConfig {
    /// `--vhost-user --socket`: the unix socket cloud-hypervisor connects to.
    pub socket: PathBuf,
    /// `-a`: address handed to the guest.
    pub guest_addr: Ipv4Addr,
    /// `-n`: prefix length of the guest network.
    pub prefix_len: u8,
    /// `-g`: gateway advertised to the guest.
    pub gateway: Ipv4Addr,
    /// The guest-facing DNS address: emitted as both `-D` (told to the guest as
    /// its nameserver) and `--dns-forward` (passt intercepts queries to it).
    pub dns_forward: Ipv4Addr,
    /// `--dns-host`: the real resolver passt redirects intercepted DNS to. Wired
    /// to the in-netns filtering resolver; `None` = passt's default
    /// (first `/etc/resolv.conf` nameserver).
    pub dns_host: Option<Ipv4Addr>,
    /// `-S`: DNS search domain told to the guest. Always set, so passt never
    /// falls back to the host's `/etc/resolv.conf` search list.
    pub search_domain: String,
    /// `-M`: guest MAC, if pinned.
    pub mac: Option<String>,
    /// `-o`: outbound source address passt binds to. **Required in a per-VM
    /// netns:** passt derives its template interface from the route to this
    /// address; without it (and a matching interface + default route) passt
    /// ignores `-a`/`-g` and hands the guest a link-local `169.254.x` address
    /// (verified against passt 2025_09; spike 0002). Deliberately *not*
    /// `--outbound-if4`: that sets `SO_BINDTODEVICE`, which forces egress out the
    /// dummy interface and bypasses the fwmark policy route to the TPROXY proxy.
    pub outbound_addr: Option<Ipv4Addr>,
    /// `-P`: pid file, if the supervisor wants one.
    pub pid_file: Option<PathBuf>,
    /// Inbound SSH forward (ADR-0011): if set, emit
    /// `-t 127.0.0.1/<port>:22` so passt listens on `127.0.0.1:<port>` **inside
    /// the netns** and forwards accepted connections to the guest's `:22`. The
    /// host cannot reach this netns-local listener directly; the supervisor
    /// bridges it from host loopback (see [`crate::ssh_forward`]).
    pub inbound_ssh_port: Option<u16>,
    /// `-q`: quiet passt's own logging.
    pub quiet: bool,
}

impl PasstConfig {
    /// Defaults for `socket`: guest 10.0.2.15/24, gateway 10.0.2.2, guest-facing
    /// DNS 10.0.2.3, search domain [`GUEST_SEARCH_DOMAIN`], no upstream override yet.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            guest_addr: Ipv4Addr::new(10, 0, 2, 15),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            dns_forward: Ipv4Addr::new(10, 0, 2, 3),
            dns_host: None,
            search_domain: GUEST_SEARCH_DOMAIN.to_string(),
            mac: None,
            outbound_addr: None,
            pid_file: None,
            inbound_ssh_port: None,
            quiet: true,
        }
    }

    /// Bind passt's outbound sockets to source `addr` (emits `-o`). The supervisor
    /// must have created an in-netns interface carrying `addr` with a default route
    /// out of it, so passt can derive its template from that route; see
    /// [`crate::netns::create_outbound_iface`].
    pub fn with_outbound(mut self, addr: Ipv4Addr) -> Self {
        self.outbound_addr = Some(addr);
        self
    }

    /// Wire the guest's DNS to the in-netns filtering resolver
    /// (ADR-0005): the guest is handed `dns_forward` as its resolver, passt
    /// intercepts those queries and redirects them (`--dns-host`) to `resolver_ip`,
    /// where the DNS front-end (`sodabox_dns::frontend::DnsFrontend`) listens on 53.
    ///
    /// The caller must also add `resolver_ip` to the nft `direct_daddrs` bypass
    /// ([`crate::nft::EgressRules`]) so passt's forward to the resolver is not
    /// itself TPROXY-intercepted.
    pub fn with_resolver(mut self, resolver_ip: Ipv4Addr) -> Self {
        self.dns_host = Some(resolver_ip);
        self
    }

    /// Forward an in-netns loopback port to the guest's SSH port (ADR-0011):
    /// passt listens on `127.0.0.1:<port>` in the netns and bridges it to
    /// the guest's `:22`. The supervisor relays host loopback into this listener
    /// (the netns is otherwise unreachable from the host); see
    /// [`crate::ssh_forward`].
    pub fn with_inbound_ssh(mut self, port: u16) -> Self {
        self.inbound_ssh_port = Some(port);
        self
    }

    /// Build the passt argv (pure; unit-tested).
    pub fn args(&self) -> Vec<OsString> {
        // Foreground (`-f`): the supervisor owns passt's lifetime (fail-closed).
        let mut a: Vec<OsString> = vec![
            "--vhost-user".into(),
            "-s".into(),
            self.socket.clone().into_os_string(),
            "-f".into(),
            "-a".into(),
            self.guest_addr.to_string().into(),
            "-n".into(),
            self.prefix_len.to_string().into(),
            "-g".into(),
            self.gateway.to_string().into(),
            // The guest is told to use `dns_forward` (`-D`, unremapped) and passt
            // intercepts queries to it (`--dns-forward`), redirecting to dns_host.
            "-D".into(),
            self.dns_forward.to_string().into(),
            "--dns-forward".into(),
            self.dns_forward.to_string().into(),
            // Static search list instead of the host's resolv.conf one.
            "-S".into(),
            self.search_domain.clone().into(),
        ];
        if let Some(host) = &self.dns_host {
            a.push("--dns-host".into());
            a.push(host.to_string().into());
        }
        if let Some(mac) = &self.mac {
            a.push("-M".into());
            a.push(mac.clone().into());
        }
        if let Some(addr) = &self.outbound_addr {
            a.push("-o".into());
            a.push(addr.to_string().into());
        }
        if let Some(pid) = &self.pid_file {
            a.push("-P".into());
            a.push(pid.clone().into_os_string());
        }
        if let Some(port) = self.inbound_ssh_port {
            // `-t 127.0.0.1/<port>:22`: listen on the netns loopback only (not the
            // dummy outbound iface) and forward to the guest's SSH port. Loopback
            // scope keeps the forward off any address a stray route could expose.
            a.push("-t".into());
            a.push(format!("127.0.0.1/{port}:22").into());
        }
        if self.quiet {
            a.push("-q".into());
        }
        a
    }
}

/// A running passt backend.
pub struct Passt {
    child: Child,
}

impl Passt {
    /// Spawn passt for `cfg`. The caller must already be inside the target netns
    /// (so passt inherits it). passt runs in the foreground; we supervise it.
    pub async fn spawn(cfg: &PasstConfig) -> std::io::Result<Passt> {
        let child = Command::new(passt_bin())
            .args(cfg.args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        Ok(Passt { child })
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait().await
    }

    /// SIGTERM, then SIGKILL after `grace`.
    pub async fn shutdown(&mut self, grace: Duration) -> std::io::Result<ExitStatus> {
        crate::proc::graceful_shutdown(&mut self.child, grace).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_str(c: &PasstConfig) -> Vec<String> {
        c.args()
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    fn value_after<'a>(args: &'a [String], flag: &str) -> &'a str {
        let i = args.iter().position(|a| a == flag).expect("flag present");
        args[i + 1].as_str()
    }

    #[test]
    fn defaults_are_vhost_user_foreground_on_socket() {
        let a = args_str(&PasstConfig::new("/run/vm/passt.sock"));
        assert!(a.contains(&"--vhost-user".to_string()));
        assert!(a.contains(&"-f".to_string())); // foreground / supervised
        assert_eq!(value_after(&a, "-s"), "/run/vm/passt.sock");
        assert_eq!(value_after(&a, "-a"), "10.0.2.15");
        assert_eq!(value_after(&a, "-n"), "24");
        assert_eq!(value_after(&a, "-g"), "10.0.2.2");
        assert_eq!(value_after(&a, "--dns-forward"), "10.0.2.3");
        // The guest is always told a nameserver (`-D` = the guest-facing forward
        // address), but with no resolver wired there is no `--dns-host` and no mac.
        assert_eq!(value_after(&a, "-D"), "10.0.2.3");
        // The host's search domains are never forwarded: a static one is pinned.
        assert_eq!(value_after(&a, "-S"), "sodabox.internal");
        assert!(!a.contains(&"--dns-host".to_string()));
        assert!(!a.contains(&"-M".to_string()));
    }

    #[test]
    fn with_resolver_redirects_guest_dns_to_filter() {
        // the guest is told to use the guest-facing forward address
        // (`-D`/`--dns-forward` = 10.0.2.3, unremapped and reachable), and passt
        // redirects those intercepted queries to the in-netns resolver (--dns-host).
        let c = PasstConfig::new("/s.sock").with_resolver(Ipv4Addr::new(127, 0, 0, 53));
        let a = args_str(&c);
        assert_eq!(value_after(&a, "-D"), "10.0.2.3"); // guest-facing, not the resolver
        assert_eq!(value_after(&a, "--dns-forward"), "10.0.2.3");
        assert_eq!(value_after(&a, "--dns-host"), "127.0.0.53"); // filter resolver
    }

    #[test]
    fn outbound_and_mac_set() {
        let mut c = PasstConfig::new("/s.sock").with_outbound(Ipv4Addr::new(10, 255, 255, 53));
        c.mac = Some("9a:55:9a:55:9a:66".into());
        let a = args_str(&c);
        assert_eq!(value_after(&a, "-o"), "10.255.255.53");
        // Deliberately no --outbound-if4 (it would SO_BINDTODEVICE and bypass TPROXY).
        assert!(!a.contains(&"--outbound-if4".to_string()));
        assert_eq!(value_after(&a, "-M"), "9a:55:9a:55:9a:66");
    }

    #[test]
    fn inbound_ssh_forwards_netns_loopback_to_guest_22() {
        // `-t 127.0.0.1/<port>:22` — passt listens on the netns loopback
        // and forwards to guest:22; absent by default.
        let base = args_str(&PasstConfig::new("/s.sock"));
        assert!(!base.contains(&"-t".to_string()));

        let c = PasstConfig::new("/s.sock").with_inbound_ssh(2222);
        let a = args_str(&c);
        assert_eq!(value_after(&a, "-t"), "127.0.0.1/2222:22");
    }
}
