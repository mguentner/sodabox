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
}

impl<D: Dialer> PolicyDialer<D> {
    pub fn new(allowlist: SharedAllowlist, inner: Arc<D>, proto: Proto) -> Self {
        Self {
            allowlist,
            inner,
            proto,
            events: null_sink(),
        }
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
