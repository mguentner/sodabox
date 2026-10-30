//! Transparent TCP proxy for TPROXY-diverted guest egress
//! (mechanism from spike 0003).
//!
//! The nft rules TPROXY every guest TCP connection to this proxy's
//! listener. Because TPROXY does no NAT, the accepted socket keeps the guest's
//! **original destination** as its *local* address — recovered here with
//! `getsockname()` (`TcpStream::local_addr`), not `SO_ORIGINAL_DST` (which is the
//! REDIRECT/TCP-only fallback the ticket title referenced). The proxy then dials
//! that destination and splices the two streams.
//!
//! What lands in later increments: allowlist evaluation on the original dst,
//! dialing from the **host** netns to avoid re-interception plus
//! allowed/blocked events, and fail-closed behaviour. To keep
//! those swappable, the dial step is abstracted behind [`Dialer`]; this
//! increment ships [`DirectDialer`] (connect straight to the original dst).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

/// Bind a TCP listener with `IP_TRANSPARENT` so the kernel will deliver
/// TPROXY-diverted connections to it (requires CAP_NET_ADMIN, held in the owned
/// netns). IPv4.
pub fn bind_transparent(addr: SocketAddr) -> io::Result<TcpListener> {
    let std = bind_transparent_std(addr)?;
    std.set_nonblocking(true)?;
    TcpListener::from_std(std)
}

/// Like [`bind_transparent`] but returns a blocking `std` listener and needs no
/// tokio reactor. The supervisor's netns child uses this to create the
/// `IP_TRANSPARENT` TPROXY listener inside the VM netns (where it holds
/// CAP_NET_ADMIN), then passes its fd to the host-netns parent, which adopts it
/// with [`listener_from_raw_fd`]. IPv4.
pub fn bind_transparent_std(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    // The property that makes TPROXY delivery legal for this socket.
    sock.set_ip_transparent(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    Ok(sock.into())
}

/// Adopt an existing listening socket fd as a tokio [`TcpListener`]. Used by the
/// supervisor to run the proxy in the **host** netns on a TPROXY listener
/// socket that was created inside the VM netns and passed over via SCM_RIGHTS —
/// the socket stays bound to its origin netns, so it still receives the VM's
/// diverted connections while the proxy's own dials go out the host netns.
///
/// # Safety
/// `fd` must be an owned, listening TCP socket fd not used elsewhere; ownership
/// transfers to the returned listener.
pub unsafe fn listener_from_raw_fd(fd: std::os::fd::RawFd) -> io::Result<TcpListener> {
    use std::os::fd::FromRawFd;
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

/// Boxed future alias so [`Dialer`] is object-safe (usable as `dyn Dialer`).
pub type DialFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;

/// How the proxy reaches a connection's original destination. The policy dialer
/// is an implementation that dials from the host netns (sidestepping the netns
/// interception loop) and consults the allowlist first.
pub trait Dialer: Send + Sync + 'static {
    fn dial(&self, dst: SocketAddr) -> DialFuture;
}

/// Connects straight to the destination in the current netns. Simple and used
/// in tests; the real deployment injects the host-netns dialer.
pub struct DirectDialer;

impl Dialer for DirectDialer {
    fn dial(&self, dst: SocketAddr) -> DialFuture {
        Box::pin(async move { TcpStream::connect(dst).await })
    }
}

/// The transparent TCP proxy: accept TPROXY-diverted connections, recover each
/// original destination, and hand off to the [`Dialer`] + splice.
pub struct TransparentProxy<D: Dialer> {
    listener: TcpListener,
    dialer: Arc<D>,
}

impl<D: Dialer> TransparentProxy<D> {
    /// Wrap an already-bound listener (use [`bind_transparent`] in production;
    /// tests may pass an ordinary listener).
    pub fn new(listener: TcpListener, dialer: Arc<D>) -> Self {
        Self { listener, dialer }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept loop. Each connection is handled on its own task so one slow peer
    /// cannot stall others. Returns only on a fatal accept error — which the
    /// supervisor treats as a **fail-closed** signal: the egress
    /// filter is the guest's only path out, so if this loop terminates the
    /// supervisor powers the guest off rather than let it run unfiltered. A
    /// per-connection failure never reaches here: an unmatched destination or a
    /// failed upstream dial denies that one connection (see [`crate::policy`]) and
    /// the loop continues.
    pub async fn serve(self) -> io::Result<()> {
        loop {
            let (client, peer) = self.listener.accept().await?;
            // TPROXY preserves the original destination as the local address.
            let dst = match client.local_addr() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("proxy: no original dst for {peer}: {e}");
                    continue;
                }
            };
            let dialer = self.dialer.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(client, dst, dialer).await {
                    eprintln!("proxy: {peer} -> {dst} closed: {e}");
                }
            });
        }
    }
}

async fn handle<D: Dialer>(
    mut client: TcpStream,
    dst: SocketAddr,
    dialer: Arc<D>,
) -> io::Result<()> {
    let mut upstream = dialer.dial(dst).await?;
    // Bidirectional copy until either side closes.
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A dialer that ignores `dst` and always connects to a fixed echo server,
    /// recording the original dst it was asked for (to assert recovery wiring).
    struct FixedDialer {
        target: SocketAddr,
        seen: Arc<Mutex<Vec<SocketAddr>>>,
    }
    impl Dialer for FixedDialer {
        fn dial(&self, dst: SocketAddr) -> DialFuture {
            self.seen.lock().unwrap().push(dst);
            let target = self.target;
            Box::pin(async move { TcpStream::connect(target).await })
        }
    }

    async fn spawn_echo() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match l.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn accepts_recovers_dst_and_splices() {
        let echo = spawn_echo().await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let dialer = Arc::new(FixedDialer {
            target: echo,
            seen: seen.clone(),
        });

        // Ordinary listener (IP_TRANSPARENT needs CAP_NET_ADMIN; the recovery
        // *wiring* is what we test here — the real transparent path is validated
        // live in a netns). local_addr of accepted conns is the proxy addr.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TransparentProxy::new(listener, dialer);
        let paddr = proxy.local_addr().unwrap();
        tokio::spawn(proxy.serve());

        let mut c = TcpStream::connect(paddr).await.unwrap();
        c.write_all(b"ping/pong").await.unwrap();
        let mut buf = [0u8; 9];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping/pong");

        // The proxy passed the recovered original dst (here, its own addr) to
        // the dialer — proving local_addr() feeds the dial step.
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0], paddr);
    }

    #[tokio::test]
    async fn transparent_bind_works_or_skips_without_cap() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        match bind_transparent(addr) {
            Ok(l) => {
                assert!(l.local_addr().is_ok());
            }
            Err(e) if e.raw_os_error() == Some(nix_eperm()) => {
                eprintln!("skipping: IP_TRANSPARENT needs CAP_NET_ADMIN");
            }
            Err(e) => panic!("unexpected bind_transparent error: {e}"),
        }
    }

    fn nix_eperm() -> i32 {
        1 // EPERM
    }

    /// End-to-end proof that TPROXY + `local_addr()` recovers the *original*
    /// destination (not the proxy's own addr). Requires CAP_NET_ADMIN and
    /// nft/ip; ignored in normal runs. Invoke inside a fresh netns:
    ///   unshare -Un --map-root-user \
    ///     cargo test -p sodabox-proxy -- --ignored tproxy_recovers_original_dst
    #[tokio::test]
    #[ignore = "needs netns + CAP_NET_ADMIN + nft/ip"]
    async fn tproxy_recovers_original_dst() {
        use std::process::Command;
        fn sh(cmd: &str) {
            let s = Command::new("sh").arg("-c").arg(cmd).status().unwrap();
            assert!(s.success(), "setup command failed: {cmd}");
        }

        // We are already in a fresh netns (the unshare wrapper). Prepare it.
        sh("ip link set lo up");
        sh("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter");
        sh("echo 0 > /proc/sys/net/ipv4/conf/lo/rp_filter");
        sh("echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet");
        sh("ip rule add fwmark 0x111 lookup 100");
        sh("ip route add local default dev lo table 100");
        // A main-table route so the initial lookup succeeds and the packet is
        // built; the OUTPUT mark + fwmark rule then bounce it via table 100.
        sh("ip route add default dev lo");
        // Mark only traffic to the fake dst so the proxy's own dial to the echo
        // (127.0.0.1) is not re-intercepted; TPROXY it to our listener.
        sh("nft add table ip sodabox");
        sh("nft add chain ip sodabox out '{ type route hook output priority mangle; policy accept; }'");
        sh("nft add rule ip sodabox out ip daddr 192.0.2.7 meta l4proto tcp meta mark set 0x111");
        sh("nft add chain ip sodabox pre '{ type filter hook prerouting priority mangle; policy accept; }'");
        sh("nft add rule ip sodabox pre meta l4proto tcp meta mark 0x111 tproxy to :18443 accept");

        let echo = spawn_echo().await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let dialer = Arc::new(FixedDialer {
            target: echo,
            seen: seen.clone(),
        });

        let listener = bind_transparent("0.0.0.0:18443".parse().unwrap()).unwrap();
        let proxy = TransparentProxy::new(listener, dialer);
        tokio::spawn(proxy.serve());

        // The guest aims at 192.0.2.7:443; TPROXY diverts it to our listener.
        let mut c = TcpStream::connect("192.0.2.7:443").await.unwrap();
        c.write_all(b"orig-dst!").await.unwrap();
        let mut buf = [0u8; 9];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"orig-dst!");

        // The decisive assertion: the recovered original dst is 192.0.2.7:443,
        // *not* the proxy's listen addr (0.0.0.0:18443).
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0], "192.0.2.7:443".parse().unwrap());
    }
}
