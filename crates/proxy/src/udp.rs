//! Transparent UDP proxy for TPROXY-diverted guest egress
//! (mechanism from spike 0003, ADR-0004).
//!
//! Like the TCP proxy ([`crate::tcp`]) the nft rules TPROXY every guest
//! UDP datagram to this proxy's listener. UDP has no accepted socket, so the
//! **original destination** is recovered per-datagram from the `IP_ORIGDSTADDR`
//! (a.k.a. `IP_RECVORIGDSTADDR`) control message — `getsockname()` would only
//! give the wildcard listen address. The listener is bound `IP_TRANSPARENT` so
//! the kernel delivers diverted datagrams to it.
//!
//! # Pseudo-flows and the reply path
//! UDP is connectionless, so we track a **pseudo-flow** per `(guest_src, dst)`
//! pair: the first datagram to an *allowed* `dst` opens an upstream socket
//! (dialed from the host netns via [`UdpConnector`]) and a reader task that
//! relays replies. Replies cannot simply be sent back on the listener: the guest
//! (passt's connected outbound socket) only accepts datagrams whose source is the
//! original `dst:port`, and forging that source requires an `IP_TRANSPARENT`
//! socket bound to `dst` **inside the VM netns** — which this host-netns proxy
//! cannot create (it is not in that netns). So replies are handed to a
//! [`ReplySink`]; the supervisor implements it by shipping each reply to a
//! netns-child injector that owns the transparent send (ADR-0004).
//!
//! Flows are evicted after [`FLOW_TTL`] idle or when [`MAX_FLOWS`] is exceeded
//! (oldest first), bounding fd/memory use against a chatty or hostile guest. A
//! flow awaiting a verdict is exempt: its hold task owns the entry until the
//! verdict lands, and the request table's waiter cap bounds how many there are.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;

use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrIn};

use sodabox_common::allowlist::{Decision, Proto, SharedAllowlist};
use sodabox_common::event::{Event, RefusalReason, Verdict};
use sodabox_common::request::{refusal_reason, PendingRequests, RequestVerdict, REQUEST_TTL};

use crate::events::{now_ts, null_sink, EgressEvents};

/// Largest UDP payload we relay (a full datagram). Guest QUIC/NTP/etc. fit well
/// under this; oversize is truncated by the kernel to the buffer anyway.
const MAX_UDP: usize = 65_535;
/// Idle lifetime of a pseudo-flow before it is evicted.
pub const FLOW_TTL: Duration = Duration::from_secs(60);
/// Hard cap on concurrent pseudo-flows (oldest evicted past this).
pub const MAX_FLOWS: usize = 1024;

/// Where a relayed UDP reply is sent so it re-enters the guest with the correct
/// spoofed source. Implemented by the supervisor's netns-child injector; tests
/// use an in-memory recorder.
pub trait ReplySink: Send + Sync + 'static {
    /// Deliver `payload` to `guest` making it appear to originate from `src`
    /// (the original destination the guest dialed).
    fn inject(&self, guest: SocketAddrV4, src: SocketAddrV4, payload: &[u8]);
}

/// How the proxy reaches an allowed UDP destination. The real deployment dials
/// from the host netns so the allow-path is not re-intercepted; tests redirect
/// to a local echo.
pub trait UdpConnector: Send + Sync + 'static {
    /// A datagram socket connected to `dst` (so `recv`/`send` need no addr).
    fn connect(&self, dst: SocketAddr) -> io::Result<UdpSocket>;
}

/// Connects straight to the destination in the current netns.
pub struct DirectUdpConnector;

impl UdpConnector for DirectUdpConnector {
    fn connect(&self, dst: SocketAddr) -> io::Result<UdpSocket> {
        let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        sock.connect(dst)?;
        sock.set_nonblocking(true)?;
        UdpSocket::from_std(sock)
    }
}

/// Enable `IP_ORIGDSTADDR` on `fd` so `recvmsg` reports each datagram's original
/// destination. Separated out so tests can build a non-transparent socket.
pub fn enable_recv_origdst(fd: RawFd) -> io::Result<()> {
    // SAFETY: BorrowedFd over an fd the caller owns for the call's duration.
    let bfd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    nix::sys::socket::setsockopt(&bfd, nix::sys::socket::sockopt::Ipv4OrigDstAddr, &true)
        .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Bind a UDP listener with `IP_TRANSPARENT` + `IP_ORIGDSTADDR` for TPROXY
/// delivery, returning a blocking `std` socket (the netns child creates it inside
/// the VM netns and passes the fd to the host parent, mirroring
/// [`crate::tcp::bind_transparent_std`]). IPv4. Needs CAP_NET_ADMIN.
pub fn bind_transparent_udp_std(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_ip_transparent(true)?;
    sock.bind(&addr.into())?;
    enable_recv_origdst(sock.as_raw_fd())?;
    Ok(sock.into())
}

/// Recover one datagram plus its peer and original destination via `recvmsg`
/// with `MSG_DONTWAIT`. `WouldBlock` is surfaced for the async readiness loop.
fn recv_origdst(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4, SocketAddrV4)> {
    let mut iov = [io::IoSliceMut::new(buf)];
    let mut cmsg = nix::cmsg_space!(nix::libc::sockaddr_in);
    let msg = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg), MsgFlags::MSG_DONTWAIT)
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

    let peer = msg
        .address
        .map(|a| SocketAddrV4::new(a.ip(), a.port()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "recvmsg: no peer address"))?;

    let mut orig = None;
    for c in msg
        .cmsgs()
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?
    {
        if let ControlMessageOwned::Ipv4OrigDstAddr(sin) = c {
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            orig = Some(SocketAddrV4::new(ip, u16::from_be(sin.sin_port)));
        }
    }
    let orig = orig.ok_or_else(|| {
        // No IP_ORIGDSTADDR cmsg means the socket lacks the sockopt or the packet
        // was not TPROXY-diverted — fail-closed: we cannot police an unknown dst.
        io::Error::new(
            io::ErrorKind::InvalidData,
            "recvmsg: no original destination",
        )
    })?;
    Ok((msg.bytes, peer, orig))
}

/// One tracked pseudo-flow.
struct Flow {
    last: Instant,
    /// `Some` for an allowed flow (with its upstream + reply-relay task); `None`
    /// caches a denied `(guest, dst)` so repeats are dropped without re-emitting.
    forward: Option<Forward>,
    /// A hold task is awaiting this flow's verdict (ADR-0021) and will replace
    /// the entry; repeats are dropped until then.
    held: bool,
}

struct Forward {
    upstream: Arc<UdpSocket>,
    reader: tokio::task::JoinHandle<()>,
}

impl Flow {
    /// Abort the reply-relay task (if any) so its upstream socket is released.
    fn shutdown(self) {
        if let Some(f) = self.forward {
            f.reader.abort();
        }
    }
}

/// The transparent UDP proxy: recover each datagram's original destination,
/// enforce the allowlist, and relay allowed flows (with replies via [`ReplySink`]).
pub struct TransparentUdpProxy {
    socket: UdpSocket,
    allowlist: SharedAllowlist,
    connector: Arc<dyn UdpConnector>,
    sink: Arc<dyn ReplySink>,
    events: Arc<dyn EgressEvents>,
    /// Where an undecided destination is parked for interactive approval
    /// (ADR-0021); `None` keeps the plain drop-on-deny behavior (tests).
    pending: Option<PendingRequests>,
}

impl TransparentUdpProxy {
    pub fn new(
        socket: UdpSocket,
        allowlist: SharedAllowlist,
        connector: Arc<dyn UdpConnector>,
        sink: Arc<dyn ReplySink>,
    ) -> Self {
        Self {
            socket,
            allowlist,
            connector,
            sink,
            events: null_sink(),
            pending: None,
        }
    }

    /// Park undecided destinations in this table instead of dropping them
    /// (ADR-0021).
    pub fn with_pending(mut self, pending: PendingRequests) -> Self {
        self.pending = Some(pending);
        self
    }

    pub fn with_events(mut self, events: Arc<dyn EgressEvents>) -> Self {
        self.events = events;
        self
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Receive loop. Returns only on a fatal socket error (a fail-closed signal
    /// the supervisor acts on, like the TCP proxy).
    pub async fn serve(self) -> io::Result<()> {
        let fd = self.socket.as_raw_fd();
        let mut buf = vec![0u8; MAX_UDP];
        // Shared with the hold tasks (an approved request inserts its relay
        // once the verdict lands, ADR-0021); the receive loop stays the sole
        // decider for *new* flows.
        let flows: Arc<Mutex<HashMap<(SocketAddrV4, SocketAddrV4), Flow>>> =
            Arc::new(Mutex::new(HashMap::new()));

        loop {
            let (n, guest, dst) = self
                .socket
                .async_io(Interest::READABLE, || recv_origdst(fd, &mut buf))
                .await?;
            let datagram = &buf[..n];
            let key = (guest, dst);

            let evaluate = || match self.allowlist.read() {
                Ok(al) => al.evaluate(SocketAddr::V4(dst), Proto::Udp, Instant::now()),
                Err(_) => Decision::Deny, // poisoned lock -> fail closed
            };

            // Known flow: refresh and forward without re-deciding. A held flow's
            // repeats are dropped (the first datagram is what's held). A denial
            // stands for FLOW_TTL from when it was made, so retransmits neither
            // extend it nor re-ask, but a rule added since applies right away.
            {
                let mut map = flows.lock().unwrap();
                if let Some(flow) = map.get_mut(&key) {
                    if let Some(f) = &flow.forward {
                        flow.last = Instant::now();
                        let up = f.upstream.clone();
                        let bytes = datagram.to_vec();
                        tokio::spawn(async move {
                            let _ = up.send(&bytes).await;
                        });
                        continue;
                    }
                    if flow.held || (flow.last.elapsed() <= FLOW_TTL && !evaluate().is_allow()) {
                        continue;
                    }
                    map.remove(&key);
                }
            }

            // New flow: decide once, emit one event, and open a relay if allowed.
            let decision = evaluate();

            self.prune(&flows);

            let forward = match decision {
                Decision::Deny => {
                    // Undecided, not dropped (ADR-0021): hold the first datagram
                    // and let the user admit the flow from the TUI. The entry
                    // goes in first, so the hold task's replacement is the last
                    // write however quickly the verdict lands.
                    if let Some(pending) = self.pending.clone() {
                        flows.lock().unwrap().insert(
                            key,
                            Flow {
                                last: Instant::now(),
                                forward: None,
                                held: true,
                            },
                        );
                        let holder = HoldArgs {
                            pending,
                            allowlist: self.allowlist.clone(),
                            connector: self.connector.clone(),
                            sink: self.sink.clone(),
                            events: self.events.clone(),
                            flows: flows.clone(),
                        };
                        tokio::spawn(hold_udp_flow(holder, guest, dst, datagram.to_vec()));
                        continue;
                    }
                    emit(&self.events, dst, Verdict::Blocked, None, None);
                    None
                }
                allow => {
                    let rule = match allow {
                        Decision::AllowStatic => "static".to_string(),
                        Decision::AllowEphemeral { domain } => domain,
                        Decision::Deny => unreachable!(),
                    };
                    emit(&self.events, dst, Verdict::Allowed, Some(rule), None);
                    open_flow(&self.connector, &self.sink, guest, dst, datagram)
                }
            };
            flows.lock().unwrap().insert(
                key,
                Flow {
                    last: Instant::now(),
                    forward,
                    held: false,
                },
            );
        }
    }

    /// Drop flows idle past [`FLOW_TTL`]; if still over [`MAX_FLOWS`], evict the
    /// oldest. Called before inserting a new flow. Held flows stay: dropping one
    /// would let a repeat start a second hold for the same flow.
    fn prune(&self, flows: &Arc<Mutex<HashMap<(SocketAddrV4, SocketAddrV4), Flow>>>) {
        let mut flows = flows.lock().unwrap();
        let now = Instant::now();
        let expired: Vec<_> = flows
            .iter()
            .filter(|(_, f)| !f.held && now.duration_since(f.last) > FLOW_TTL)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            if let Some(f) = flows.remove(&k) {
                f.shutdown();
            }
        }
        while flows.len() >= MAX_FLOWS {
            let Some(oldest) = flows
                .iter()
                .filter(|(_, f)| !f.held)
                .min_by_key(|(_, f)| f.last)
                .map(|(k, _)| *k)
            else {
                break;
            };
            if let Some(f) = flows.remove(&oldest) {
                f.shutdown();
            }
        }
    }
}

/// Everything a spawned hold task needs to finish a parked UDP flow once its
/// verdict lands (ADR-0021): re-decide, open the relay, and patch the flow map.
struct HoldArgs {
    pending: PendingRequests,
    allowlist: SharedAllowlist,
    connector: Arc<dyn UdpConnector>,
    sink: Arc<dyn ReplySink>,
    events: Arc<dyn EgressEvents>,
    flows: Arc<Mutex<HashMap<(SocketAddrV4, SocketAddrV4), Flow>>>,
}

/// Park a denied-but-undecided UDP flow's first datagram. On approval the rule
/// is already in the allowlist (approve *is* a persistent rule), so re-decide:
/// allowed → open the relay and fire the held datagram; anything else → the
/// datagram is dropped (best-effort, UDP) and the denial is cached. Either way
/// this replaces the flow's held entry, which only this task can remove.
async fn hold_udp_flow(args: HoldArgs, guest: SocketAddrV4, dst: SocketAddrV4, first: Vec<u8>) {
    let (_, rx) = args
        .pending
        .hold("udp", &dst.ip().to_string(), Some(dst.port()));
    let verdict = tokio::time::timeout(REQUEST_TTL, rx)
        .await
        .ok()
        .and_then(Result::ok);
    let approved = verdict == Some(RequestVerdict::Approved);
    let decision = match args.allowlist.read() {
        Ok(al) if approved => al.evaluate(SocketAddr::V4(dst), Proto::Udp, Instant::now()),
        _ => Decision::Deny,
    };
    let forward = match decision {
        Decision::AllowStatic | Decision::AllowEphemeral { .. } => {
            emit(
                &args.events,
                dst,
                Verdict::Allowed,
                Some("granted".to_string()),
                None,
            );
            open_flow(&args.connector, &args.sink, guest, dst, &first)
        }
        Decision::Deny => {
            emit(
                &args.events,
                dst,
                Verdict::Blocked,
                None,
                Some(refusal_reason(verdict)),
            );
            None
        }
    };
    args.flows.lock().unwrap().insert(
        (guest, dst),
        Flow {
            last: Instant::now(),
            forward,
            held: false,
        },
    );
}

/// Emit one egress verdict event (free-standing so spawned hold tasks share
/// the receive loop's emission shape).
fn emit(
    events: &Arc<dyn EgressEvents>,
    dst: SocketAddrV4,
    verdict: Verdict,
    rule: Option<String>,
    reason: Option<RefusalReason>,
) {
    events.emit(Event::Egress {
        ts: now_ts(),
        verdict,
        proto: "udp".to_string(),
        daddr: dst.ip().to_string(),
        dport: dst.port(),
        rule,
        reason,
    });
}

/// Dial `dst` from the proxy's netns, send the first datagram, and spawn the
/// reply-relay task. Returns `None` (drops the datagram) if the dial fails.
fn open_flow(
    connector: &Arc<dyn UdpConnector>,
    sink: &Arc<dyn ReplySink>,
    guest: SocketAddrV4,
    dst: SocketAddrV4,
    first: &[u8],
) -> Option<Forward> {
    let upstream = match connector.connect(SocketAddr::V4(dst)) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("udp proxy: dial {dst} failed: {e}");
            return None;
        }
    };
    // Fire the first datagram.
    {
        let up = upstream.clone();
        let bytes = first.to_vec();
        tokio::spawn(async move {
            let _ = up.send(&bytes).await;
        });
    }
    // Relay replies until the flow is evicted (task aborted) or upstream dies.
    let reader = tokio::spawn(relay_replies(upstream.clone(), sink.clone(), guest, dst));
    Some(Forward { upstream, reader })
}

/// Relay every reply from `upstream` back to `guest`, forging source `dst`.
async fn relay_replies(
    upstream: Arc<UdpSocket>,
    sink: Arc<dyn ReplySink>,
    guest: SocketAddrV4,
    dst: SocketAddrV4,
) {
    let mut buf = vec![0u8; MAX_UDP];
    loop {
        match upstream.recv(&mut buf).await {
            Ok(0) => continue,
            Ok(n) => sink.inject(guest, dst, &buf[..n]),
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::ChannelEvents;
    use sodabox_common::allowlist::{shared, Allowlist};
    use sodabox_common::policy::{Rule, VmPolicy};
    use std::sync::Mutex;

    /// Records injected replies for assertions.
    #[derive(Default)]
    struct RecordSink {
        got: Mutex<Vec<(SocketAddrV4, SocketAddrV4, Vec<u8>)>>,
    }
    impl ReplySink for RecordSink {
        fn inject(&self, guest: SocketAddrV4, src: SocketAddrV4, payload: &[u8]) {
            self.got
                .lock()
                .unwrap()
                .push((guest, src, payload.to_vec()));
        }
    }

    /// Connector that ignores `dst` and dials a fixed echo server.
    struct FixedConnector {
        target: SocketAddr,
    }
    impl UdpConnector for FixedConnector {
        fn connect(&self, _dst: SocketAddr) -> io::Result<UdpSocket> {
            let s = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            s.connect(self.target)?;
            s.set_nonblocking(true)?;
            UdpSocket::from_std(s)
        }
    }

    async fn spawn_echo() -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut b).await {
                let _ = s.send_to(&b[..n], from).await;
            }
        });
        addr
    }

    fn allowlist_allowing(dst: SocketAddrV4) -> SharedAllowlist {
        let pol = VmPolicy {
            rules: vec![Rule::Ip {
                cidr: dst.ip().to_string(),
                ports: Some(dst.port().to_string()),
                proto: Some("udp".into()),
            }],
            ..VmPolicy::default()
        };
        shared(Allowlist::from_policy(&pol).unwrap())
    }

    /// Build a plain (non-transparent) listener with IP_ORIGDSTADDR — its
    /// original-dst is its own bound address, enough to exercise the flow wiring
    /// without CAP_NET_ADMIN (mirrors the TCP proxy's recovery test).
    async fn origdst_listener() -> UdpSocket {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        enable_recv_origdst(s.as_raw_fd()).unwrap();
        s.set_nonblocking(true).unwrap();
        UdpSocket::from_std(s).unwrap()
    }

    #[tokio::test]
    async fn allowed_datagram_forwards_and_relays_reply() {
        let echo = spawn_echo().await;
        let listener = origdst_listener().await;
        let dst = match listener.local_addr().unwrap() {
            SocketAddr::V4(v4) => v4, // the recovered orig-dst equals this addr
            _ => unreachable!(),
        };
        let sink = Arc::new(RecordSink::default());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let proxy = TransparentUdpProxy::new(
            listener,
            allowlist_allowing(dst),
            Arc::new(FixedConnector { target: echo }),
            sink.clone(),
        )
        .with_events(Arc::new(ChannelEvents::new(tx)));
        let paddr = proxy.local_addr().unwrap();
        tokio::spawn(proxy.serve());

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caddr = match client.local_addr().unwrap() {
            SocketAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        client.send_to(b"ping", paddr).await.unwrap();

        // The echo reply is relayed to the sink as (guest=client, src=dst, bytes).
        for _ in 0..50 {
            if !sink.got.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let got = sink.got.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "expected one relayed reply, got {got:?}");
        assert_eq!(got[0].0, caddr); // reply targets the guest
        assert_eq!(got[0].1, dst); // forged source is the original dst
        assert_eq!(&got[0].2, b"ping"); // echoed payload

        // And an Allowed event was emitted for the flow.
        match rx.try_recv().unwrap() {
            Event::Egress {
                verdict,
                proto,
                dport,
                ..
            } => {
                assert_eq!(verdict, Verdict::Allowed);
                assert_eq!(proto, "udp");
                assert_eq!(dport, dst.port());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn denied_datagram_is_dropped_and_logged() {
        let echo = spawn_echo().await;
        let listener = origdst_listener().await;
        // Allowlist permits some *other* address, so the datagram to `dst` denies.
        let other = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9999);
        let sink = Arc::new(RecordSink::default());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let proxy = TransparentUdpProxy::new(
            listener,
            allowlist_allowing(other),
            Arc::new(FixedConnector { target: echo }),
            sink.clone(),
        )
        .with_events(Arc::new(ChannelEvents::new(tx)));
        let paddr = proxy.local_addr().unwrap();
        tokio::spawn(proxy.serve());

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"nope", paddr).await.unwrap();

        // Give the loop time; nothing should be relayed.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            sink.got.lock().unwrap().is_empty(),
            "denied UDP must not relay"
        );
        match rx.try_recv().unwrap() {
            Event::Egress { verdict, .. } => assert_eq!(verdict, Verdict::Blocked),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn undecided_datagram_is_held_then_relays_on_approval() {
        // ADR-2021: a denied-but-undecided first datagram is held (its flow
        // entry caches "no relay"), and the *held* datagram is fired once the
        // request is approved and the rule is in the allowlist.
        let echo = spawn_echo().await;
        let listener = origdst_listener().await;
        let dst = match listener.local_addr().unwrap() {
            SocketAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        let other = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9999);
        let al = allowlist_allowing(other);
        let sink = Arc::new(RecordSink::default());
        let pending = sodabox_common::request::shared();
        let proxy = TransparentUdpProxy::new(
            listener,
            al.clone(),
            Arc::new(FixedConnector { target: echo }),
            sink.clone(),
        )
        .with_pending(pending.clone());
        let paddr = proxy.local_addr().unwrap();
        tokio::spawn(proxy.serve());

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caddr = match client.local_addr().unwrap() {
            SocketAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        client.send_to(b"held", paddr).await.unwrap();

        // The request is parked; nothing relayed yet.
        let id = loop {
            if let Some(r) = pending.list().first() {
                break r.id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            sink.got.lock().unwrap().is_empty(),
            "held datagram must not relay"
        );

        // Approve = rule first, then resolve.
        let allow_dst = VmPolicy {
            rules: vec![Rule::Ip {
                cidr: dst.ip().to_string(),
                ports: Some(dst.port().to_string()),
                proto: Some("udp".into()),
            }],
            ..VmPolicy::default()
        };
        al.write().unwrap().swap_policy(&allow_dst).unwrap();
        assert!(pending.resolve(id, true));

        // The held datagram goes out, the echo replies, and the relay injects
        // it back as (guest, src=dst, b"held").
        for _ in 0..100 {
            let done = sink
                .got
                .lock()
                .unwrap()
                .iter()
                .any(|(g, s, b)| *g == caddr && *s == dst && b == b"held");
            if done {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("approved flow never relayed");
    }

    /// A proxy that holds undecided datagrams, with its pending table and sink.
    async fn holding_proxy() -> (
        SocketAddrV4,
        SharedAllowlist,
        PendingRequests,
        Arc<RecordSink>,
        SocketAddr,
    ) {
        let echo = spawn_echo().await;
        let listener = origdst_listener().await;
        let dst = match listener.local_addr().unwrap() {
            SocketAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        let al = allowlist_allowing(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9999));
        let sink = Arc::new(RecordSink::default());
        let pending = sodabox_common::request::shared();
        let proxy = TransparentUdpProxy::new(
            listener,
            al.clone(),
            Arc::new(FixedConnector { target: echo }),
            sink.clone(),
        )
        .with_pending(pending.clone());
        let paddr = proxy.local_addr().unwrap();
        tokio::spawn(proxy.serve());
        (dst, al, pending, sink, paddr)
    }

    async fn first_request(pending: &PendingRequests) -> u64 {
        loop {
            if let Some(r) = pending.list().first() {
                return r.id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn allow(al: &SharedAllowlist, dst: SocketAddrV4) {
        let policy = VmPolicy {
            rules: vec![Rule::Ip {
                cidr: dst.ip().to_string(),
                ports: Some(dst.port().to_string()),
                proto: Some("udp".into()),
            }],
            ..VmPolicy::default()
        };
        al.write().unwrap().swap_policy(&policy).unwrap();
    }

    #[tokio::test]
    async fn denied_flow_stays_quiet_until_a_rule_allows_it() {
        let (dst, al, pending, sink, paddr) = holding_proxy().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"first", paddr).await.unwrap();
        assert!(pending.resolve(first_request(&pending).await, false));
        tokio::time::sleep(Duration::from_millis(30)).await;

        // Retransmits while the denial stands don't ask again.
        client.send_to(b"again", paddr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(pending.list().is_empty());
        assert!(sink.got.lock().unwrap().is_empty());

        // A rule added later applies to the very next datagram.
        allow(&al, dst);
        client.send_to(b"after", paddr).await.unwrap();
        for _ in 0..100 {
            if sink
                .got
                .lock()
                .unwrap()
                .iter()
                .any(|(_, _, b)| b == b"after")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("flow stayed blackholed after a rule allowed it");
    }

    #[tokio::test]
    async fn repeats_of_a_held_flow_relay_once_on_approval() {
        let (dst, al, pending, sink, paddr) = holding_proxy().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"held", paddr).await.unwrap();
        let id = first_request(&pending).await;
        client.send_to(b"repeat", paddr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;

        allow(&al, dst);
        assert!(pending.resolve(id, true));
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Only the held datagram went out, over one relay.
        let got = sink.got.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(&got[0].2, b"held");
    }

    #[tokio::test]
    async fn prune_never_evicts_a_held_flow() {
        let proxy = TransparentUdpProxy::new(
            origdst_listener().await,
            allowlist_allowing(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 9999)),
            Arc::new(DirectUdpConnector),
            Arc::new(RecordSink::default()),
        );
        let key = |port| {
            (
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
                SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 53),
            )
        };
        let flow = |held| Flow {
            last: Instant::now() - FLOW_TTL * 2,
            forward: None,
            held,
        };
        let flows = Arc::new(Mutex::new(HashMap::new()));
        flows.lock().unwrap().insert(key(1), flow(true));
        flows.lock().unwrap().insert(key(2), flow(false));

        // Past the idle TTL: the cached denial goes, the held flow stays.
        proxy.prune(&flows);
        let map = flows.lock().unwrap();
        assert!(map.contains_key(&key(1)));
        assert!(!map.contains_key(&key(2)));
        drop(map);

        // At the cap with nothing evictable, prune gives up instead of spinning.
        let fresh = |held| Flow {
            last: Instant::now(),
            forward: None,
            held,
        };
        for port in 0..MAX_FLOWS as u16 {
            flows.lock().unwrap().insert(key(port + 2), fresh(true));
        }
        proxy.prune(&flows);
        assert!(flows.lock().unwrap().len() > MAX_FLOWS);
    }

    #[tokio::test]
    async fn transparent_udp_bind_works_or_skips_without_cap() {
        match bind_transparent_udp_std("127.0.0.1:0".parse().unwrap()) {
            Ok(s) => assert!(s.local_addr().is_ok()),
            Err(e) if e.raw_os_error() == Some(1) => {
                eprintln!("skipping: IP_TRANSPARENT needs CAP_NET_ADMIN");
            }
            Err(e) => panic!("unexpected bind error: {e}"),
        }
    }
}
