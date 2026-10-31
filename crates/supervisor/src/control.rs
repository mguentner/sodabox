//! Per-VM control + event unix socket (ADR-0007).
//!
//! Each supervisor exposes a user-only (`0600`) unix socket at
//! `$XDG_RUNTIME_DIR/sodabox/<vm>/control.sock` speaking **newline-delimited
//! JSON**: one [`Request`] object per line in, one [`Response`] object per line
//! out (`serde_json` never emits an embedded newline, so `\n` is a safe frame
//! delimiter). [`Request::Subscribe`] is the exception — the server acks with
//! [`Response::Ok`] then streams bare [`Event`] JSON lines until the client
//! disconnects or the VM stops.
//!
//! This module owns the socket, framing and dispatch only. The actual VM state
//! (policy lock, live event source, teardown signal) is supplied by whatever
//! wires it up — the orchestrator implements [`ControlHandler`]
//! for the real supervisor; tests use an in-memory mock. That trait seam mirrors
//! the rest of the codebase (`Dialer`, `QueryHandler`, `EgressEvents`) and keeps
//! this module self-contained and testable before the orchestrator exists.
//!
//! [`ControlClient`] is the thin client the CLI/TUI use.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use sodabox_common::event::{now_ts, Event};
use sodabox_common::paths;
use sodabox_common::policy::VmPolicy;
use sodabox_common::protocol::{Request, Response};
use sodabox_common::quota::Balances;

/// The VM-runtime operations the control socket dispatches to. Methods are
/// synchronous: they only touch in-memory state (behind the supervisor's own
/// locks) or fire a signal, so they must not block — the [`ControlServer`] owns
/// all the async socket I/O.
pub trait ControlHandler: Send + Sync + 'static {
    /// `(state, policy_version)` for `status`.
    fn status(&self) -> (String, u32);
    /// The live effective policy for `policy.get`.
    fn policy_get(&self) -> VmPolicy;
    /// Replace the live policy (`policy.set`). `Err(msg)` → `Response::Error`.
    fn policy_set(&self, policy: VmPolicy) -> Result<(), String>;
    /// Add an allow rule. The raw rule string is parsed by the handler (the
    /// policy layer), not here.
    fn allow(&self, rule: &str) -> Result<(), String>;
    /// Remove/deny a rule (raw string, as [`ControlHandler::allow`]).
    fn deny(&self, rule: &str) -> Result<(), String>;
    /// Request VM teardown (`stop`). Fire-and-return; the supervisor's run loop
    /// observes the signal and tears down (fail-closed).
    fn stop(&self);
    /// A fresh subscription to the live event feed for `subscribe`.
    fn subscribe(&self) -> broadcast::Receiver<Event>;
    /// The inference gateway's live token balances (ADR-0020).
    fn quota_get(&self) -> Result<Balances, String> {
        Err("this supervisor has no inference gateway".to_string())
    }
    /// Re-read the quota ledger after a grant was appended.
    fn quota_reload(&self) -> Result<(), String> {
        Err("this supervisor has no inference gateway".to_string())
    }
}

/// The control socket server. Generic over the [`ControlHandler`] so the real
/// supervisor state and test mocks share one code path.
pub struct ControlServer<H: ControlHandler> {
    listener: UnixListener,
    handler: Arc<H>,
    path: PathBuf,
}

impl<H: ControlHandler> ControlServer<H> {
    /// Bind the control socket for `vm` under `$XDG_RUNTIME_DIR/sodabox/<vm>/`.
    pub fn bind(vm: &str, handler: Arc<H>) -> io::Result<Self> {
        Self::bind_at(paths::runtime_dir(vm).join("control.sock"), handler)
    }

    /// Bind at an explicit path (used by tests). Creates the parent dir `0700`,
    /// removes any stale socket, binds, and tightens the socket to `0600`.
    pub fn bind_at(path: impl Into<PathBuf>, handler: Arc<H>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        // A leftover socket from an unclean shutdown would make bind() fail.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            handler,
            path,
        })
    }

    /// The bound socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept loop. Each connection runs on its own task so a subscribed (long-
    /// lived) client cannot stall control requests from others. Returns only on
    /// a fatal accept error.
    pub async fn serve(self) -> io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let handler = self.handler.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_conn(stream, handler).await {
                    // A client hanging up is normal; only surface real errors.
                    if !is_disconnect(&e) {
                        eprintln!("control: connection error: {e}");
                    }
                }
            });
        }
    }
}

impl<H: ControlHandler> Drop for ControlServer<H> {
    fn drop(&mut self) {
        // Leave the runtime dir clean; ignore if already gone.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Handle one client connection: dispatch requests until it closes, `stop`s, or
/// `subscribe`s (which consumes the connection for the event stream).
async fn serve_conn<H: ControlHandler>(stream: UnixStream, handler: Arc<H>) -> io::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    while let Some(line) = read_line_opt(&mut rd).await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                // Deny-by-default posture: reject and drop on malformed input.
                write_line(
                    &mut wr,
                    &Response::Error {
                        msg: format!("bad request: {e}"),
                    },
                )
                .await?;
                return Ok(());
            }
        };

        match req {
            Request::Status => {
                let (state, policy_version) = handler.status();
                write_line(
                    &mut wr,
                    &Response::Status {
                        state,
                        policy_version,
                    },
                )
                .await?;
            }
            Request::PolicyGet => {
                write_line(
                    &mut wr,
                    &Response::Policy {
                        policy: handler.policy_get(),
                    },
                )
                .await?;
            }
            Request::PolicySet { policy } => {
                write_line(&mut wr, &to_response(handler.policy_set(policy))).await?;
            }
            Request::Allow { rule } => {
                write_line(&mut wr, &to_response(handler.allow(&rule))).await?;
            }
            Request::Deny { rule } => {
                write_line(&mut wr, &to_response(handler.deny(&rule))).await?;
            }
            Request::Stop => {
                handler.stop();
                write_line(&mut wr, &Response::Ok).await?;
                return Ok(());
            }
            Request::Subscribe => {
                write_line(&mut wr, &Response::Ok).await?;
                stream_events(&mut wr, handler.subscribe()).await?;
                return Ok(());
            }
            Request::QuotaGet => {
                let resp = match handler.quota_get() {
                    Ok(balances) => Response::Quota { balances },
                    Err(msg) => Response::Error { msg },
                };
                write_line(&mut wr, &resp).await?;
            }
            Request::QuotaReload => {
                write_line(&mut wr, &to_response(handler.quota_reload())).await?;
            }
        }
    }
    Ok(())
}

/// Forward broadcast events to the client as newline-delimited JSON until the
/// client disconnects (write error) or the feed closes (VM stopped).
async fn stream_events<W: AsyncWriteExt + Unpin>(
    wr: &mut W,
    mut rx: broadcast::Receiver<Event>,
) -> io::Result<()> {
    loop {
        match rx.recv().await {
            Ok(event) => write_line(wr, &event).await?,
            // The subscriber fell behind and the bounded ring dropped the oldest
            // `n` events (backpressure under a chatty guest; ADR-0009). Rather
            // than silently lose them, tell the client how many went missing so
            // the TUI can render an explicit gap; then resume from the current
            // position (`recv` has already advanced past the dropped range).
            Err(broadcast::error::RecvError::Lagged(n)) => {
                write_line(
                    wr,
                    &Event::Dropped {
                        ts: now_ts(),
                        count: n,
                    },
                )
                .await?;
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

fn to_response(r: Result<(), String>) -> Response {
    match r {
        Ok(()) => Response::Ok,
        Err(msg) => Response::Error { msg },
    }
}

/// The thin client the CLI/TUI use to drive a running VM's supervisor.
pub struct ControlClient {
    io: BufReader<UnixStream>,
}

impl ControlClient {
    /// Connect to `vm`'s control socket under `$XDG_RUNTIME_DIR`.
    pub async fn connect(vm: &str) -> io::Result<Self> {
        Self::connect_at(paths::runtime_dir(vm).join("control.sock")).await
    }

    /// Connect to an explicit socket path (used by tests).
    pub async fn connect_at(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            io: BufReader::new(UnixStream::connect(path).await?),
        })
    }

    /// Send one request and read its single response.
    pub async fn request(&mut self, req: &Request) -> io::Result<Response> {
        write_line(&mut self.io, req).await?;
        let line = read_line(&mut self.io).await?;
        serde_json::from_str(&line).map_err(io::Error::other)
    }

    /// Begin the live event stream. Returns the server's ack ([`Response::Ok`],
    /// or an error response) and, on Ok, an [`EventStream`] to pull events from.
    pub async fn subscribe(mut self) -> io::Result<(Response, EventStream)> {
        write_line(&mut self.io, &Request::Subscribe).await?;
        let line = read_line(&mut self.io).await?;
        let ack: Response = serde_json::from_str(&line).map_err(io::Error::other)?;
        Ok((ack, EventStream { io: self.io }))
    }
}

/// A live event feed from `subscribe`. Pull events with [`EventStream::recv`];
/// `Ok(None)` means the server closed the stream (VM stopped).
pub struct EventStream {
    io: BufReader<UnixStream>,
}

impl EventStream {
    pub async fn recv(&mut self) -> io::Result<Option<Event>> {
        match read_line_opt(&mut self.io).await? {
            Some(line) => Ok(Some(serde_json::from_str(&line).map_err(io::Error::other)?)),
            None => Ok(None),
        }
    }
}

/// Serialize `msg` as one JSON line (`\n`-terminated) and write it.
async fn write_line<W: AsyncWriteExt + Unpin, T: Serialize>(wr: &mut W, msg: &T) -> io::Result<()> {
    let mut buf = serde_json::to_vec(msg).map_err(io::Error::other)?;
    buf.push(b'\n');
    wr.write_all(&buf).await
}

/// Read one line, erroring with `UnexpectedEof` if the peer closed first.
async fn read_line<R: AsyncBufReadExt + Unpin>(rd: &mut R) -> io::Result<String> {
    read_line_opt(rd)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "control: connection closed"))
}

/// Read one line, or `None` at clean EOF. Strips the trailing `\n`/`\r\n`.
async fn read_line_opt<R: AsyncBufReadExt + Unpin>(rd: &mut R) -> io::Result<Option<String>> {
    let mut line = String::new();
    if rd.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(Some(line))
}

fn is_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Mutex;

    use sodabox_common::event::{Event, Verdict};

    /// In-memory stand-in for the supervisor's runtime state.
    struct MockHandler {
        policy: Mutex<VmPolicy>,
        events: broadcast::Sender<Event>,
        stopped: AtomicBool,
        allow_calls: Mutex<Vec<String>>,
        deny_ok: bool,
    }

    impl MockHandler {
        fn new(deny_ok: bool) -> Arc<Self> {
            let (events, _) = broadcast::channel(16);
            Arc::new(Self {
                policy: Mutex::new(VmPolicy {
                    version: 1,
                    ..VmPolicy::default()
                }),
                events,
                stopped: AtomicBool::new(false),
                allow_calls: Mutex::new(Vec::new()),
                deny_ok,
            })
        }
    }

    impl ControlHandler for MockHandler {
        fn status(&self) -> (String, u32) {
            ("running".into(), self.policy.lock().unwrap().version)
        }
        fn policy_get(&self) -> VmPolicy {
            self.policy.lock().unwrap().clone()
        }
        fn policy_set(&self, policy: VmPolicy) -> Result<(), String> {
            *self.policy.lock().unwrap() = policy;
            Ok(())
        }
        fn allow(&self, rule: &str) -> Result<(), String> {
            self.allow_calls.lock().unwrap().push(rule.to_string());
            Ok(())
        }
        fn deny(&self, rule: &str) -> Result<(), String> {
            if self.deny_ok {
                Ok(())
            } else {
                Err(format!("no such rule: {rule}"))
            }
        }
        fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }
        fn subscribe(&self) -> broadcast::Receiver<Event> {
            self.events.subscribe()
        }
    }

    /// A short, unique socket path in `/tmp` (kept well under the 108-byte
    /// `sun_path` limit — the scratchpad path would overflow it).
    fn unique_sock() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sodabox-control-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("control.sock")
    }

    /// Bind a server on `handler`, spawn its accept loop, return the socket path.
    fn serve(handler: Arc<MockHandler>) -> PathBuf {
        let sock = unique_sock();
        let srv = ControlServer::bind_at(&sock, handler).unwrap();
        tokio::spawn(srv.serve());
        sock
    }

    #[tokio::test]
    async fn status_roundtrips() {
        let sock = serve(MockHandler::new(true));
        let mut c = ControlClient::connect_at(&sock).await.unwrap();
        match c.request(&Request::Status).await.unwrap() {
            Response::Status {
                state,
                policy_version,
            } => {
                assert_eq!(state, "running");
                assert_eq!(policy_version, 1);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn policy_get_set() {
        let sock = serve(MockHandler::new(true));
        let mut c = ControlClient::connect_at(&sock).await.unwrap();

        let new_policy = VmPolicy {
            version: 7,
            ..VmPolicy::default()
        };
        assert!(matches!(
            c.request(&Request::PolicySet { policy: new_policy })
                .await
                .unwrap(),
            Response::Ok
        ));
        match c.request(&Request::PolicyGet).await.unwrap() {
            Response::Policy { policy } => assert_eq!(policy.version, 7),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn allow_deny_plumb_raw_rule() {
        let handler = MockHandler::new(false); // deny returns Err
        let sock = serve(handler.clone());
        let mut c = ControlClient::connect_at(&sock).await.unwrap();

        assert!(matches!(
            c.request(&Request::Allow {
                rule: "ip 1.2.3.0/24:443".into()
            })
            .await
            .unwrap(),
            Response::Ok
        ));
        // The exact raw string reached the handler unparsed.
        assert_eq!(
            handler.allow_calls.lock().unwrap().as_slice(),
            &["ip 1.2.3.0/24:443"]
        );

        match c
            .request(&Request::Deny {
                rule: "nope".into(),
            })
            .await
            .unwrap()
        {
            Response::Error { msg } => assert!(msg.contains("nope")),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_streams_events() {
        let handler = MockHandler::new(true);
        let sock = serve(handler.clone());
        let c = ControlClient::connect_at(&sock).await.unwrap();

        let (ack, mut stream) = c.subscribe().await.unwrap();
        assert!(matches!(ack, Response::Ok));

        // Give the server task a moment to register the subscriber before we
        // publish, so the event isn't sent before recv() is wired up.
        let sent = Event::Egress {
            ts: 42,
            verdict: Verdict::Blocked,
            proto: "tcp".into(),
            daddr: "203.0.113.9".into(),
            dport: 443,
            rule: None,
        };
        loop {
            if handler.events.receiver_count() > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        handler.events.send(sent.clone()).unwrap();

        let got = stream.recv().await.unwrap().expect("one event");
        assert_eq!(
            serde_json::to_string(&got).unwrap(),
            serde_json::to_string(&sent).unwrap()
        );
    }

    /// Backpressure: when a subscriber falls behind and the
    /// bounded ring drops the oldest events, the stream must emit a single
    /// `Event::Dropped { count }` gap marker in their place, then resume with
    /// the retained (newest) events — not silently swallow the loss.
    #[tokio::test]
    async fn lagging_subscriber_gets_a_dropped_marker() {
        // Capacity 4; publish 6 before anyone reads => the 2 oldest are dropped.
        let (tx, rx) = broadcast::channel::<Event>(4);
        for version in 0..6u32 {
            tx.send(Event::Policy { ts: 0, version }).unwrap();
        }
        // Close the channel so stream_events drains the retained events and returns.
        drop(tx);

        let mut buf: Vec<u8> = Vec::new();
        stream_events(&mut buf, rx).await.unwrap();

        let events: Vec<Event> = String::from_utf8(buf)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        // First line: the gap marker for the 2 dropped events.
        assert!(
            matches!(events[0], Event::Dropped { count: 2, .. }),
            "expected Dropped {{ count: 2 }}, got {:?}",
            events[0]
        );
        // Then the 4 retained (newest) events, in order, nothing silently lost.
        let versions: Vec<u32> = events[1..]
            .iter()
            .map(|e| match e {
                Event::Policy { version, .. } => *version,
                other => panic!("unexpected event: {other:?}"),
            })
            .collect();
        assert_eq!(versions, vec![2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn stop_fires_signal() {
        let handler = MockHandler::new(true);
        let sock = serve(handler.clone());
        let mut c = ControlClient::connect_at(&sock).await.unwrap();

        assert!(matches!(
            c.request(&Request::Stop).await.unwrap(),
            Response::Ok
        ));
        assert!(handler.stopped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn socket_and_dir_are_user_only() {
        let sock = unique_sock();
        let _srv = ControlServer::bind_at(&sock, MockHandler::new(true)).unwrap();

        let sock_mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(sock_mode, 0o600, "control socket must be 0600");

        let dir_mode = std::fs::metadata(sock.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "runtime dir must be 0700");
    }

    #[tokio::test]
    async fn malformed_request_errors_and_closes() {
        let sock = serve(MockHandler::new(true));
        let stream = UnixStream::connect(&sock).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        wr.write_all(b"{not json}\n").await.unwrap();

        let mut rd = BufReader::new(rd);
        let line = read_line(&mut rd).await.unwrap();
        let resp: Response = serde_json::from_str(&line).unwrap();
        assert!(matches!(resp, Response::Error { .. }));
        // Server closes the connection after a bad request.
        assert!(read_line_opt(&mut rd).await.unwrap().is_none());
    }
}
