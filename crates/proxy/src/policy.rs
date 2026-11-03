//! Allowlist enforcement on the recovered original destination.
//!
//! [`PolicyDialer`] wraps an inner [`Dialer`] and consults the VM's effective
//! allowlist (static ∪ DNS-ephemeral, ADR-0006) before every connection: an
//! allowed destination is dialed through; a denied one fails with
//! `PermissionDenied`, so the proxy drops the connection (deny-by-default). The
//! allowlist is shared behind an `RwLock` so the DNS filter can add
//! ephemeral entries and the CLI can swap policy live.
//!
//! Allowed/blocked *events* and the loop-avoiding host-netns inner dialer
//! live here too.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use sodabox_common::allowlist::{Decision, Proto};
use sodabox_common::event::{Event, Verdict};
use sodabox_common::request::{RequestVerdict, REQUEST_TTL};
// Re-exported so proxy callers keep a single import site.
pub use sodabox_common::allowlist::{shared, SharedAllowlist};

use crate::events::{now_ts, null_sink, EgressEvents};
use crate::tcp::{DialFuture, Dialer};

/// A [`Dialer`] that enforces the allowlist before delegating to `inner`, and
/// emits an [`Event::Egress`] for every verdict. The `inner` dialer runs
/// wherever the proxy process runs — the host netns per ADR-0004 — so the
/// allow-path connection reaches the real internet without traversing the netns
/// interception rules again.
pub struct PolicyDialer<D: Dialer> {
    allowlist: SharedAllowlist,
    inner: Arc<D>,
    /// Protocol of this proxy's connections (TCP for the transparent TCP proxy).
    proto: Proto,
    events: Arc<dyn EgressEvents>,
    /// Where an undecided destination is parked for interactive approval
    /// (ADR-0021); `None` keeps the plain refuse-on-deny behavior (tests).
    pending: Option<sodabox_common::request::PendingRequests>,
}

impl<D: Dialer> PolicyDialer<D> {
    pub fn new(allowlist: SharedAllowlist, inner: Arc<D>, proto: Proto) -> Self {
        Self {
            allowlist,
            inner,
            proto,
            events: null_sink(),
            pending: None,
        }
    }

    /// Park undecided destinations in this table instead of refusing them
    /// (ADR-0021).
    pub fn with_pending(mut self, pending: sodabox_common::request::PendingRequests) -> Self {
        self.pending = Some(pending);
        self
    }

    /// Attach an event sink so verdicts are reported (allowed/blocked).
    pub fn with_events(mut self, events: Arc<dyn EgressEvents>) -> Self {
        self.events = events;
        self
    }

    fn emit(&self, dst: SocketAddr, verdict: Verdict, rule: Option<String>) {
        self.events.emit(Event::Egress {
            ts: now_ts(),
            verdict,
            proto: match self.proto {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
            }
            .to_string(),
            daddr: dst.ip().to_string(),
            dport: dst.port(),
            rule,
        });
    }
}

impl<D: Dialer> Dialer for PolicyDialer<D> {
    fn dial(&self, dst: SocketAddr) -> DialFuture {
        // A poisoned lock means a writer panicked mid-update; fail closed rather
        // than trust a possibly-inconsistent allowlist.
        let decision = match self.allowlist.read() {
            Ok(al) => al.evaluate(dst, self.proto, Instant::now()),
            Err(_) => Decision::Deny,
        };

        match decision {
            Decision::AllowStatic => {
                self.emit(dst, Verdict::Allowed, Some("static".to_string()));
                self.inner.dial(dst)
            }
            Decision::AllowEphemeral { domain } => {
                self.emit(dst, Verdict::Allowed, Some(domain));
                self.inner.dial(dst)
            }
            Decision::Deny => {
                // Undecided, not refused (ADR-0021): park the connection for up
                // to REQUEST_TTL and let the user admit it from the TUI. The
                // guest-side socket is already ours (TPROXY), so it just sees a
                // stalled connect. On approval the rule is already in the
                // allowlist (approve *is* a persistent rule), so re-evaluate —
                // fail closed on anything but a clean allow.
                if let Some(pending) = self.pending.clone() {
                    let allowlist = self.allowlist.clone();
                    let inner = self.inner.clone();
                    let events = self.events.clone();
                    let proto = self.proto;
                    let proto_s = match proto {
                        Proto::Tcp => "tcp",
                        Proto::Udp => "udp",
                    }
                    .to_string();
                    let (info, rx) = pending.hold("tcp", &dst.ip().to_string(), Some(dst.port()));
                    return Box::pin(async move {
                        let verdict = tokio::time::timeout(REQUEST_TTL, rx).await;
                        match verdict {
                            Ok(Ok(RequestVerdict::Approved)) => {}
                            _ => {
                                events.emit(Event::Egress {
                                    ts: now_ts(),
                                    verdict: Verdict::Blocked,
                                    proto: proto_s.clone(),
                                    daddr: dst.ip().to_string(),
                                    dport: dst.port(),
                                    rule: None,
                                });
                                return Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    format!("egress denied by policy: {dst}"),
                                ));
                            }
                        }
                        // Re-check the (just-updated) allowlist.
                        let decision = match allowlist.read() {
                            Ok(al) => al.evaluate(dst, proto, Instant::now()),
                            Err(_) => Decision::Deny,
                        };
                        match decision {
                            Decision::AllowStatic | Decision::AllowEphemeral { .. } => {
                                events.emit(Event::Egress {
                                    ts: now_ts(),
                                    verdict: Verdict::Allowed,
                                    proto: proto_s.clone(),
                                    daddr: dst.ip().to_string(),
                                    dport: dst.port(),
                                    rule: Some(format!("granted (request {})", info.id)),
                                });
                                inner.dial(dst).await
                            }
                            Decision::Deny => {
                                events.emit(Event::Egress {
                                    ts: now_ts(),
                                    verdict: Verdict::Blocked,
                                    proto: proto_s.clone(),
                                    daddr: dst.ip().to_string(),
                                    dport: dst.port(),
                                    rule: None,
                                });
                                Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    format!("egress denied by policy: {dst}"),
                                ))
                            }
                        }
                    });
                }
                self.emit(dst, Verdict::Blocked, None);
                Box::pin(async move {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("egress denied by policy: {dst}"),
                    ))
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::DirectDialer;
    use sodabox_common::allowlist::Allowlist;
    use sodabox_common::policy::{Rule, VmPolicy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_echo() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 64];
                    if let Ok(n) = s.read(&mut b).await {
                        let _ = s.write_all(&b[..n]).await;
                    }
                });
            }
        });
        addr
    }

    fn allowlist_allowing(addr: SocketAddr) -> SharedAllowlist {
        let pol = VmPolicy {
            rules: vec![Rule::Ip {
                cidr: addr.ip().to_string(),
                ports: Some(addr.port().to_string()),
                proto: Some("tcp".into()),
            }],
            ..VmPolicy::default()
        };
        shared(Allowlist::from_policy(&pol).unwrap())
    }

    #[tokio::test]
    async fn allowed_dst_is_dialed() {
        let echo = spawn_echo().await;
        let dialer =
            PolicyDialer::new(allowlist_allowing(echo), Arc::new(DirectDialer), Proto::Tcp);
        let mut up = dialer
            .dial(echo)
            .await
            .expect("allowed dial should connect");
        up.write_all(b"hi").await.unwrap();
        let mut b = [0u8; 2];
        up.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hi");
    }

    #[tokio::test]
    async fn denied_dst_is_blocked_without_connecting() {
        // Allowlist permits the echo addr, but we dial a *different* one.
        let echo = spawn_echo().await;
        let dialer =
            PolicyDialer::new(allowlist_allowing(echo), Arc::new(DirectDialer), Proto::Tcp);

        // A destination not in the allowlist.
        let denied: SocketAddr = "203.0.113.200:443".parse().unwrap();
        let err = dialer
            .dial(denied)
            .await
            .expect_err("denied dial must fail");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn denied_dst_is_held_and_dials_after_approval() {
        // ADR-0021: an undecided destination parks in the request table instead
        // of failing. Approve *is* a persistent rule: add it, resolve the
        // request, and the held dial goes through as if it had been allowed.
        let echo = spawn_echo().await;
        // Allowlist permits a different addr, so the echo is undecided.
        let al = allowlist_allowing("203.0.113.1:9".parse().unwrap());
        let pending = sodabox_common::request::shared();
        let dialer = PolicyDialer::new(al.clone(), Arc::new(DirectDialer), Proto::Tcp)
            .with_pending(pending.clone());

        let fut = dialer.dial(echo);
        // The request is parked (coalesced id 1); the dial has neither failed
        // nor connected yet.
        let id = loop {
            let list = pending.list();
            if let Some(r) = list.first() {
                break r.id;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        assert_eq!(pending.list()[0].destination, echo.ip().to_string());
        assert_eq!(pending.list()[0].port, Some(echo.port()));

        // The TUI's approve path: rule first, then the resolve.
        let allow_echo = VmPolicy {
            rules: vec![Rule::Ip {
                cidr: echo.ip().to_string(),
                ports: Some(echo.port().to_string()),
                proto: Some("tcp".into()),
            }],
            ..VmPolicy::default()
        };
        al.write().unwrap().swap_policy(&allow_echo).unwrap();
        assert!(pending.resolve(id, true));

        let mut up = fut.await.expect("approved dial should connect");
        up.write_all(b"hi").await.unwrap();
        let mut b = [0u8; 2];
        up.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hi");
        assert!(pending.list().is_empty());
    }

    #[tokio::test]
    async fn request_leaves_the_table_when_its_client_gives_up() {
        use crate::tcp::TransparentProxy;
        use std::time::Duration;
        use tokio::net::TcpStream;

        // Allowlist permits a different addr, so the proxy's own addr is undecided.
        let al = allowlist_allowing("203.0.113.1:9".parse().unwrap());
        let pending = sodabox_common::request::shared();
        let dialer =
            PolicyDialer::new(al, Arc::new(DirectDialer), Proto::Tcp).with_pending(pending.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TransparentProxy::new(listener, Arc::new(dialer));
        let paddr = proxy.local_addr().unwrap();
        tokio::spawn(proxy.serve());

        let client = TcpStream::connect(paddr).await.unwrap();
        while pending.list().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(client);

        // The supervisor's sweep removes the row once the hold has noticed.
        for _ in 0..100 {
            pending.expire_due();
            if pending.list().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("request outlived its only client");
    }

    #[tokio::test]
    async fn held_dst_fails_when_denied() {
        let echo = spawn_echo().await;
        let al = allowlist_allowing("203.0.113.1:9".parse().unwrap());
        let pending = sodabox_common::request::shared();
        let dialer = PolicyDialer::new(al.clone(), Arc::new(DirectDialer), Proto::Tcp)
            .with_pending(pending.clone());

        let fut = dialer.dial(echo);
        let id = loop {
            if let Some(r) = pending.list().first() {
                break r.id;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        assert!(pending.resolve(id, false));
        let err = fut.await.expect_err("denied hold must fail");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn emits_allowed_and_blocked_events() {
        use crate::events::ChannelEvents;
        let echo = spawn_echo().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let dialer =
            PolicyDialer::new(allowlist_allowing(echo), Arc::new(DirectDialer), Proto::Tcp)
                .with_events(Arc::new(ChannelEvents::new(tx)));

        // Allowed dst -> allowed event with 5-tuple + rule.
        let _ = dialer.dial(echo).await.unwrap();
        match rx.recv().await.unwrap() {
            Event::Egress {
                verdict,
                proto,
                daddr,
                dport,
                rule,
                ..
            } => {
                assert_eq!(verdict, Verdict::Allowed);
                assert_eq!(proto, "tcp");
                assert_eq!(daddr, echo.ip().to_string());
                assert_eq!(dport, echo.port());
                assert_eq!(rule.as_deref(), Some("static"));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        // Denied dst -> blocked event.
        let denied: SocketAddr = "203.0.113.201:8443".parse().unwrap();
        let _ = dialer.dial(denied).await.unwrap_err();
        match rx.recv().await.unwrap() {
            Event::Egress {
                verdict,
                daddr,
                dport,
                rule,
                ..
            } => {
                assert_eq!(verdict, Verdict::Blocked);
                assert_eq!(daddr, "203.0.113.201");
                assert_eq!(dport, 8443);
                assert_eq!(rule, None);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    /// Fail-closed on the *allow* path too: when policy permits a
    /// destination but the inner dial fails (upstream unreachable, host netns
    /// error), the proxy must surface the error so the connection is dropped —
    /// never silently fall through to an unfiltered/half-open state.
    #[tokio::test]
    async fn allowed_but_inner_dial_failure_is_not_fallthrough() {
        struct FailingDialer;
        impl Dialer for FailingDialer {
            fn dial(&self, _dst: SocketAddr) -> DialFuture {
                Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "upstream down",
                    ))
                })
            }
        }
        let allowed: SocketAddr = "198.51.100.10:443".parse().unwrap();
        let dialer = PolicyDialer::new(
            allowlist_allowing(allowed),
            Arc::new(FailingDialer),
            Proto::Tcp,
        );
        let err = dialer
            .dial(allowed)
            .await
            .expect_err("failed inner dial must propagate");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn poisoned_lock_fails_closed() {
        let al = allowlist_allowing("127.0.0.1:1".parse().unwrap());
        // Poison the lock.
        let al2 = al.clone();
        let _ = std::thread::spawn(move || {
            let _g = al2.write().unwrap();
            panic!("poison");
        })
        .join();
        let dialer = PolicyDialer::new(al, Arc::new(DirectDialer), Proto::Tcp);
        let err = dialer
            .dial("127.0.0.1:1".parse().unwrap())
            .await
            .expect_err("must fail closed");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
