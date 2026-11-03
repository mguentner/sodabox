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
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::io::Interest;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// How long to wait before accepting again after a temporary accept error. The
/// failed connection stays queued, so retrying at once would spin.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// How long a dial runs before a client close can cancel it. A client may
/// half-close right after sending (`printf … | nc -N`) and still want the reply,
/// which a socket can't tell apart from leaving, so an ordinary dial must finish
/// undisturbed. A dial still running after this is almost always a held request
/// (ADR-0021), where a client that closed has given up.
const CLIENT_GONE_GRACE: Duration = Duration::from_secs(2);
/// How often to re-check a client that has sent data (readable from then on, so
/// waiting for readiness alone would spin).
const CLIENT_GONE_POLL: Duration = Duration::from_secs(1);

/// Keepalive on the guest side while a dial is outstanding: keeps an idle held
/// connection alive, and with these timings notices a dead peer (10 + 3 × 5 s)
/// within [`sodabox_common::request::REQUEST_TTL`].
fn hold_keepalive() -> TcpKeepalive {
    TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5))
        .with_retries(3)
}

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
    local: Option<(SocketAddr, Arc<dyn LocalService>)>,
    /// One permit per open connection; `None` means no cap.
    permits: Option<Arc<Semaphore>>,
}

/// Boxed future alias for [`LocalService::serve`].
pub type ServeFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A service sodabox itself offers the guest at a reserved address, e.g. the
/// inference gateway (ADR-0020). Connections to that address are handed to it
/// instead of being dialed out; it decides whether the guest may use it.
pub trait LocalService: Send + Sync + 'static {
    fn serve(&self, client: TcpStream, peer: SocketAddr) -> ServeFuture;
}

impl<D: Dialer> TransparentProxy<D> {
    /// Wrap an already-bound listener (use [`bind_transparent`] in production;
    /// tests may pass an ordinary listener).
    pub fn new(listener: TcpListener, dialer: Arc<D>) -> Self {
        Self {
            listener,
            dialer,
            local: None,
            permits: None,
        }
    }

    /// Allow at most `max` open connections, closing new ones past that. Each
    /// holds file descriptors the VM's DNS, UDP and control paths share, so a
    /// guest opening too many must not starve those.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.permits = Some(Arc::new(Semaphore::new(max)));
        self
    }

    /// Hand connections whose original destination is `addr` to `service`.
    pub fn with_local(mut self, addr: SocketAddr, service: Arc<dyn LocalService>) -> Self {
        self.local = Some((addr, service));
        self
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
    /// the loop continues. Neither does a temporary accept error such as running
    /// out of file descriptors: the filter still works, and nothing is dialed
    /// while it waits (see [`is_transient_accept_error`]).
    pub async fn serve(self) -> io::Result<()> {
        // Each logs once per episode: a guest can keep these going for a while.
        let mut accept_failing = false;
        let mut at_cap = false;
        loop {
            let (client, peer) = match self.listener.accept().await {
                Ok(accepted) => {
                    accept_failing = false;
                    accepted
                }
                Err(e) if is_transient_accept_error(&e) => {
                    if !accept_failing {
                        eprintln!("proxy: can't accept connections for now, retrying: {e}");
                        accept_failing = true;
                    }
                    tokio::time::sleep(ACCEPT_RETRY).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let permit = match &self.permits {
                Some(permits) => match permits.clone().try_acquire_owned() {
                    Ok(permit) => {
                        at_cap = false;
                        Some(permit)
                    }
                    // Dropping `client` closes it: the guest gets a fast failure
                    // it can retry, not a hang.
                    Err(_) => {
                        if !at_cap {
                            eprintln!("proxy: connection limit reached, closing new connections");
                            at_cap = true;
                        }
                        continue;
                    }
                },
                None => None,
            };
            // TPROXY preserves the original destination as the local address.
            let dst = match client.local_addr() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("proxy: no original dst for {peer}: {e}");
                    continue;
                }
            };
            if let Some((addr, service)) = &self.local {
                if dst == *addr {
                    let serving = service.serve(client, peer);
                    tokio::spawn(async move {
                        let _permit = permit;
                        serving.await;
                    });
                    continue;
                }
            }
            let dialer = self.dialer.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle(client, dst, dialer).await {
                    eprintln!("proxy: {peer} -> {dst} closed: {e}");
                }
            });
        }
    }
}

/// Whether a failed `accept` says nothing about the listener itself: the process
/// or host is out of a resource, or the connection failed before it was accepted
/// (accept(2) says to treat those network errors like `EAGAIN`). Anything else
/// means the listener is broken, which stays fatal.
fn is_transient_accept_error(e: &io::Error) -> bool {
    use nix::libc;
    matches!(
        e.raw_os_error(),
        Some(
            libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::ECONNABORTED
                | libc::EINTR
                | libc::EPROTO
                | libc::ENETDOWN
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::ENONET
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH
        )
    )
}

async fn handle<D: Dialer>(
    mut client: TcpStream,
    dst: SocketAddr,
    dialer: Arc<D>,
) -> io::Result<()> {
    SockRef::from(&client).set_tcp_keepalive(&hold_keepalive())?;
    // Dropping a held dial drops its waiter, so a request whose clients have
    // all gone leaves the table (see `PendingRequests::expire_due`).
    let mut upstream = tokio::select! {
        dialed = dialer.dial(dst) => dialed?,
        () = client_gone(&client, CLIENT_GONE_GRACE) => return Ok(()),
    };
    // Only the hold needs it; an established flow is the two peers' business.
    SockRef::from(&client).set_keepalive(false)?;
    // Bidirectional copy until either side closes.
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Resolves once `client` has closed, reset or failed keepalive, checking only
/// after `grace`. Looks at readiness rather than reading, so data the guest sent
/// meanwhile is still there for the splice.
async fn client_gone(client: &TcpStream, grace: Duration) {
    tokio::time::sleep(grace).await;
    loop {
        match client.ready(Interest::READABLE).await {
            Ok(ready) if !ready.is_read_closed() => {
                tokio::time::sleep(CLIENT_GONE_POLL).await;
            }
            _ => return,
        }
    }
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

    #[test]
    fn only_a_broken_listener_is_a_fatal_accept_error() {
        use nix::libc;
        let transient = |code| is_transient_accept_error(&io::Error::from_raw_os_error(code));
        assert!(transient(libc::EMFILE));
        assert!(transient(libc::ENFILE));
        assert!(transient(libc::ECONNABORTED));
        assert!(!transient(libc::EBADF));
        assert!(!transient(libc::EINVAL));
        assert!(!is_transient_accept_error(&io::Error::other("boom")));
    }

    #[tokio::test]
    async fn connections_past_the_cap_are_closed_until_one_ends() {
        let dialer = Arc::new(FixedDialer {
            target: spawn_echo().await,
            seen: Arc::new(Mutex::new(Vec::new())),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TransparentProxy::new(listener, dialer).with_max_connections(1);
        let paddr = proxy.local_addr().unwrap();
        tokio::spawn(proxy.serve());
        let echoes = |mut c: TcpStream| async move {
            c.write_all(b"hi").await.unwrap();
            let mut buf = [0u8; 2];
            c.read_exact(&mut buf).await.unwrap();
            c
        };

        let first = echoes(TcpStream::connect(paddr).await.unwrap()).await;

        // At the cap: closed straight away, while the first keeps working.
        let mut second = TcpStream::connect(paddr).await.unwrap();
        let mut buf = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf)).await;
        assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "{closed:?}");
        let first = echoes(first).await;

        // Its permit comes back once it ends.
        drop(first);
        for _ in 0..100 {
            let mut c = TcpStream::connect(paddr).await.unwrap();
            let served = c.write_all(b"hi").await.is_ok()
                && tokio::time::timeout(Duration::from_millis(100), c.read_exact(&mut [0u8; 2]))
                    .await
                    .is_ok_and(|r| r.is_ok());
            if served {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the cap never freed up");
    }

    /// A connected (client, accepted server side) pair.
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        (c, l.accept().await.unwrap().0)
    }

    #[tokio::test]
    async fn hold_keepalive_reports_a_dead_peer_within_the_request_ttl() {
        let (_c, s) = tcp_pair().await;
        let sock = SockRef::from(&s);
        sock.set_tcp_keepalive(&hold_keepalive()).unwrap();
        assert!(sock.keepalive().unwrap());
        let time = sock.keepalive_time().unwrap();
        let interval = sock.keepalive_interval().unwrap();
        let retries = sock.keepalive_retries().unwrap();
        assert!(time + interval * retries < sodabox_common::request::REQUEST_TTL);
    }

    #[tokio::test]
    async fn client_gone_waits_for_a_close_and_sees_past_unread_data() {
        let (mut c, s) = tcp_pair().await;
        let gone = |grace| tokio::time::timeout(Duration::from_millis(200), client_gone(&s, grace));

        // Open and quiet: not gone.
        assert!(gone(Duration::ZERO).await.is_err());
        // Open with unread data: still not gone, and the data stays readable.
        c.write_all(b"early").await.unwrap();
        assert!(gone(Duration::ZERO).await.is_err());

        // Closed: gone, even with that data still unread.
        drop(c);
        tokio::time::timeout(CLIENT_GONE_POLL * 3, client_gone(&s, Duration::ZERO))
            .await
            .expect("a closed client must be noticed");
        let mut buf = [0u8; 5];
        s.try_read(&mut buf).unwrap();
        assert_eq!(&buf, b"early");
    }

    /// Connects to `target` after `delay`, like a dial with a real round trip.
    struct SlowDialer {
        target: SocketAddr,
        delay: Duration,
    }
    impl Dialer for SlowDialer {
        fn dial(&self, _dst: SocketAddr) -> DialFuture {
            let (target, delay) = (self.target, self.delay);
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                TcpStream::connect(target).await
            })
        }
    }

    #[tokio::test]
    async fn half_close_during_an_ordinary_dial_still_gets_the_reply() {
        let dialer = Arc::new(SlowDialer {
            target: spawn_echo().await,
            delay: Duration::from_millis(200),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TransparentProxy::new(listener, dialer);
        let paddr = proxy.local_addr().unwrap();
        tokio::spawn(proxy.serve());

        let mut c = TcpStream::connect(paddr).await.unwrap();
        c.write_all(b"query").await.unwrap();
        c.shutdown().await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"query");
    }

    /// A local service that answers every connection with a fixed greeting.
    struct Greeter;
    impl LocalService for Greeter {
        fn serve(&self, mut client: TcpStream, _peer: SocketAddr) -> ServeFuture {
            Box::pin(async move {
                let _ = client.write_all(b"local").await;
            })
        }
    }

    #[tokio::test]
    async fn local_service_address_never_reaches_the_dialer() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let dialer = Arc::new(FixedDialer {
            target: spawn_echo().await,
            seen: seen.clone(),
        });
        // With an ordinary listener the "original dst" is the proxy's own
        // address, so registering the service there routes every connection.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let paddr = listener.local_addr().unwrap();
        let proxy = TransparentProxy::new(listener, dialer).with_local(paddr, Arc::new(Greeter));
        tokio::spawn(proxy.serve());

        let mut c = TcpStream::connect(paddr).await.unwrap();
        let mut buf = [0u8; 5];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"local");
        assert!(seen.lock().unwrap().is_empty());
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
