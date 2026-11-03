//! Pending egress requests (ADR-0021).
//!
//! A deny-by-default verdict for a destination no rule matched is *undecided*,
//! not refused: the enforcement component (TCP proxy, UDP proxy, DNS filter)
//! parks it in a per-VM [`PendingRequests`] table with a fixed 30 s TTL and
//! awaits the verdict. The supervisor surfaces the request as a
//! [`crate::event::Event::RequestPending`] (the TUI's Egress Requests panel) and
//! resolves it over the control socket with [`Request::RequestResolve`]
//! ([`crate::protocol::Request`]); on TTL expiry the entry is denied by
//! [`PendingRequests::expire_due`]. Approval *is* an allowlist rule: the CLI/TUI
//! adds one (ADR-0006) before resolving, so the held flow proceeds through the
//! normal allow path — the guest only ever observed latency.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::event::{now_ts, Event};

/// How long a request is held before it is denied by expiry. Fixed (ADR-0021).
pub const REQUEST_TTL: Duration = Duration::from_secs(30);
/// Concurrent pending entries per VM. Overflow denies the oldest first (FIFO),
/// so a chatty or hostile guest cannot grow memory/fds without bound.
pub const MAX_PENDING: usize = 64;
/// Enforcement calls held across all entries of a VM. Each can pin a socket and
/// a task, and coalescing means [`MAX_PENDING`] alone does not bound them: at
/// the cap, a further call for a held destination is denied on the spot, and a
/// new destination makes room by denying the oldest entries.
pub const MAX_WAITERS: usize = 256;

/// The outcome of a held request. `Expired` and `Abandoned` only ever originate
/// from the sweep; a resolved request is `Approved` or `Denied`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestVerdict {
    Approved,
    Denied,
    Expired,
    /// Every enforcement call waiting on it went away (the client gave up).
    Abandoned,
}

impl RequestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestVerdict::Approved => "approved",
            RequestVerdict::Denied => "denied",
            RequestVerdict::Expired => "expired",
            RequestVerdict::Abandoned => "abandoned",
        }
    }
}

/// One held request, as surfaced on the event stream, `RequestList` and the
/// Egress Requests panel: what is being asked for and when it dies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequest {
    pub id: u64,
    /// `dns`, `tcp` or `udp`.
    pub proto: String,
    /// The qname (dns) or destination IP (tcp/udp).
    pub destination: String,
    /// The destination port (tcp/udp); `None` for dns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Unix seconds at which the request is denied if still unresolved.
    pub expires_ts: u64,
}

/// An entry in the table: its wire shape, its deadline, and the enforcement
/// calls waiting on it (retransmissions/parallel attempts coalesce into one
/// entry but each holds its own completion channel).
struct Entry {
    info: PendingRequest,
    deadline: Instant,
    waiters: Vec<oneshot::Sender<RequestVerdict>>,
}

/// The registry's event sink shape (the supervisor passes a closure that sends
/// onto its broadcast ring).
pub type EventSink = Arc<dyn Fn(Event) + Send + Sync>;

/// The per-VM pending-request table. Cloning the `Shared` handle is how the
/// supervisor, the proxies and the resolver all reach the same table (they run
/// as tasks in one process, ADR-0007).
#[derive(Clone, Default)]
pub struct PendingRequests {
    inner: Arc<Inner>,
}

struct Inner {
    entries: Mutex<Vec<Entry>>,
    next_id: Mutex<u64>,
    /// Where [`Event::RequestPending`]/[`Event::RequestResolved`] go. The sink
    /// must not call back into this table (it would deadlock on the entry lock).
    events: Mutex<Option<EventSink>>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            next_id: Mutex::new(0),
            events: Mutex::new(None),
        }
    }
}

/// The shared handle type used across crates.
pub fn shared() -> PendingRequests {
    PendingRequests::default()
}

impl PendingRequests {
    /// Route the table's events onto `sink` (e.g. the supervisor's broadcast
    /// ring, which fans them out to the CLI/TUI and the per-VM log).
    pub fn with_events(self, sink: EventSink) -> Self {
        *self.inner.events.lock().unwrap() = Some(sink);
        self
    }

    fn emit(&self, event: Event) {
        let sink = self.inner.events.lock().unwrap().clone();
        if let Some(sink) = sink {
            sink(event);
        }
    }

    /// Park a request. A matching entry (same proto/destination/port) is reused,
    /// so retransmissions and parallel attempts coalesce instead of minting rows;
    /// a new one is announced with a [`Event::RequestPending`]. Returns the
    /// request (with its id) and the channel the verdict arrives on — the caller
    /// should also bound its wait by [`REQUEST_TTL`] (see [`Self::resolve`] and
    /// [`Self::expire_due`], which drive this side) so a missing sweep cannot
    /// wedge a flow forever. On table overflow the oldest entry is denied early.
    pub fn hold(
        &self,
        proto: &str,
        destination: &str,
        port: Option<u16>,
    ) -> (PendingRequest, oneshot::Receiver<RequestVerdict>) {
        let (tx, rx) = oneshot::channel();
        let mut entries = self.inner.entries.lock().unwrap();

        let held = |entries: &[Entry]| entries.iter().map(|e| e.waiters.len()).sum::<usize>();

        // Coalesce into a live matching entry.
        if let Some(idx) = entries.iter().position(|e| {
            e.info.proto == proto && e.info.destination == destination && e.info.port == port
        }) {
            if held(&entries) >= MAX_WAITERS {
                let _ = tx.send(RequestVerdict::Denied);
            } else {
                entries[idx].waiters.push(tx);
            }
            return (entries[idx].info.clone(), rx);
        }

        // Cap: deny the oldest first, so an uncooperative guest cannot push the
        // table (and the held sockets/fds behind it) past its limits.
        while entries.len() >= MAX_PENDING || held(&entries) >= MAX_WAITERS {
            if let Some(oldest) = entries.first() {
                let id = oldest.info.id;
                self.finish_locked(&mut entries, id, RequestVerdict::Denied);
            } else {
                break;
            }
        }

        let id = {
            let mut next = self.inner.next_id.lock().unwrap();
            *next += 1;
            *next
        };
        let info = PendingRequest {
            id,
            proto: proto.to_string(),
            destination: destination.to_string(),
            port,
            expires_ts: now_ts() + REQUEST_TTL.as_secs(),
        };
        entries.push(Entry {
            info: info.clone(),
            deadline: Instant::now() + REQUEST_TTL,
            waiters: vec![tx],
        });
        self.emit(Event::RequestPending {
            ts: now_ts(),
            id: info.id,
            proto: info.proto.clone(),
            destination: info.destination.clone(),
            port: info.port,
            expires_ts: info.expires_ts,
        });
        (info, rx)
    }

    /// Resolve a request by id (approve or deny). Idempotent: an unknown or
    /// already-resolved id is a no-op that returns `false` (the TUI may act on
    /// a row that just expired). Every waiter is completed with the verdict and
    /// a [`Event::RequestResolved`] is emitted.
    pub fn resolve(&self, id: u64, allow: bool) -> bool {
        let mut entries = self.inner.entries.lock().unwrap();
        if !entries.iter().any(|e| e.info.id == id) {
            return false;
        }
        let verdict = if allow {
            RequestVerdict::Approved
        } else {
            RequestVerdict::Denied
        };
        self.finish_locked(&mut entries, id, verdict);
        true
    }

    /// Deny every entry whose TTL has passed, completing its waiters with
    /// [`RequestVerdict::Expired`] and emitting one
    /// [`Event::RequestResolved`] each. Driven by the supervisor's 1 s sweep.
    /// Returns how many expired. The sweep also forgets waiters that went away
    /// and removes a request left with none as
    /// [`RequestVerdict::Abandoned`]: there is nothing left to approve.
    pub fn expire_due(&self) -> usize {
        let now = Instant::now();
        let mut entries = self.inner.entries.lock().unwrap();
        let due: Vec<u64> = entries
            .iter()
            .filter(|e| e.deadline <= now)
            .map(|e| e.info.id)
            .collect();
        for id in &due {
            self.finish_locked(&mut entries, *id, RequestVerdict::Expired);
        }
        for entry in entries.iter_mut() {
            entry.waiters.retain(|w| !w.is_closed());
        }
        let abandoned: Vec<u64> = entries
            .iter()
            .filter(|e| e.waiters.is_empty())
            .map(|e| e.info.id)
            .collect();
        for id in abandoned {
            self.finish_locked(&mut entries, id, RequestVerdict::Abandoned);
        }
        due.len()
    }

    /// The live requests (for `RequestList`): a freshly started TUI shows held
    /// requests without waiting for new ones.
    pub fn list(&self) -> Vec<PendingRequest> {
        self.inner
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.info.clone())
            .collect()
    }

    /// Complete every waiter of `id`, drop the entry, and report the outcome.
    /// Callers hold the entry lock; `emit` only touches the (separate) sink slot.
    fn finish_locked(&self, entries: &mut Vec<Entry>, id: u64, verdict: RequestVerdict) {
        if let Some(idx) = entries.iter().position(|e| e.info.id == id) {
            let entry = entries.remove(idx);
            for waiter in entry.waiters {
                // A closed channel just means the holder gave up (its own
                // timeout fired first) — the verdict is dropped with it.
                let _ = waiter.send(verdict);
            }
            self.emit(Event::RequestResolved {
                ts: now_ts(),
                id,
                verdict: verdict.as_str().to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hold_emits_pending_and_resolve_completes_waiters() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let table = shared().with_events(Arc::new(move |e: Event| {
            sink_events.lock().unwrap().push(e);
        }));

        let (info, mut rx) = table.hold("tcp", "203.0.113.5", Some(443));
        assert_eq!(info.id, 1);
        assert_eq!(info.expires_ts, now_ts() + 30);

        let sink = events.lock().unwrap();
        assert!(matches!(
            sink.first(),
            Some(Event::RequestPending { id: 1, proto, destination, .. })
                if proto == "tcp" && destination == "203.0.113.5"
        ));
        drop(sink);

        assert!(table.resolve(info.id, true));
        assert_eq!(rx.try_recv(), Ok(RequestVerdict::Approved));

        // Resolving again is a no-op (the TUI may race an expiry).
        assert!(!table.resolve(info.id, true));
        assert!(table.list().is_empty());
    }

    #[tokio::test]
    async fn matching_requests_coalesce_into_one_entry() {
        let table = shared();
        let (a, mut rx1) = table.hold("dns", "example.com", None);
        let (b, mut rx2) = table.hold("dns", "example.com", None);
        assert_eq!(a.id, b.id);
        assert_eq!(table.list().len(), 1);

        // Both waiters see the same verdict.
        table.resolve(a.id, false);
        assert_eq!(rx1.try_recv(), Ok(RequestVerdict::Denied));
        assert_eq!(rx2.try_recv(), Ok(RequestVerdict::Denied));

        // A different port (or proto, or name) is a separate entry.
        let (_, _) = table.hold("dns", "example.com", Some(53));
        assert_eq!(table.list().len(), 1);
        let _ = table.hold("tcp", "203.0.113.5", Some(443));
        assert_eq!(table.list().len(), 2);
    }

    #[tokio::test]
    async fn expiry_denies_due_entries() {
        let table = shared();
        let (info, mut rx) = table.hold("udp", "203.0.113.9", Some(53));
        assert_eq!(info.proto, "udp");
        // Nothing due yet.
        assert_eq!(table.expire_due(), 0);
        assert_eq!(table.list().len(), 1);

        // Fake the passage of time by rewinding the deadline through the
        // private slot — the sweep only looks at `deadline`.
        {
            let mut entries = table.inner.entries.lock().unwrap();
            entries[0].deadline = Instant::now() - Duration::from_secs(1);
        }
        assert_eq!(table.expire_due(), 1);
        assert_eq!(rx.try_recv(), Ok(RequestVerdict::Expired));
        assert!(table.list().is_empty());
    }

    #[tokio::test]
    async fn sweep_removes_a_request_once_every_waiter_is_gone() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let table = shared().with_events(Arc::new(move |e: Event| {
            sink_events.lock().unwrap().push(e);
        }));
        let (info, rx1) = table.hold("tcp", "203.0.113.5", Some(443));
        let (_, rx2) = table.hold("tcp", "203.0.113.5", Some(443));

        // One client left: the request stays, for the other.
        drop(rx1);
        assert_eq!(table.expire_due(), 0);
        assert_eq!(table.list().len(), 1);

        drop(rx2);
        assert_eq!(table.expire_due(), 0);
        assert!(table.list().is_empty());
        assert!(matches!(
            events.lock().unwrap().last(),
            Some(Event::RequestResolved { id, verdict, .. })
                if *id == info.id && verdict == "abandoned"
        ));
    }

    #[tokio::test]
    async fn overflow_denies_the_oldest_entry() {
        let table = shared();
        let mut first = None;
        for i in 0..MAX_PENDING {
            let (info, _rx) = table.hold("tcp", &format!("198.51.100.{i}"), Some(80));
            if first.is_none() {
                first = Some((info, _rx));
            }
        }
        assert_eq!(table.list().len(), MAX_PENDING);

        // One more: the oldest is denied early (FIFO).
        let (_newest, _nrx) = table.hold("tcp", "198.51.100.200", Some(80));
        let (info, mut rx) = first.unwrap();
        assert_eq!(rx.try_recv(), Ok(RequestVerdict::Denied));
        assert_eq!(table.list().len(), MAX_PENDING);
        assert!(table.list().iter().all(|r| r.id != info.id));
    }

    #[tokio::test]
    async fn waiter_cap_denies_excess_calls_and_new_destinations_make_room() {
        let table = shared();
        let mut held: Vec<_> = (0..MAX_WAITERS)
            .map(|_| table.hold("tcp", "203.0.113.5", Some(443)).1)
            .collect();
        assert_eq!(table.list().len(), 1);
        assert!(held.iter_mut().all(|rx| rx.try_recv().is_err()));

        // One call too many for the held destination: denied now, row kept.
        let (info, mut extra) = table.hold("tcp", "203.0.113.5", Some(443));
        assert_eq!(extra.try_recv(), Ok(RequestVerdict::Denied));
        assert_eq!(table.list().len(), 1);
        assert_eq!(table.list()[0].id, info.id);

        // The flood can't hide a new destination: its row evicts the oldest.
        let (new, mut new_rx) = table.hold("tcp", "198.51.100.1", Some(80));
        assert!(new_rx.try_recv().is_err());
        assert_eq!(table.list(), vec![new]);
        assert!(held
            .iter_mut()
            .all(|rx| rx.try_recv() == Ok(RequestVerdict::Denied)));
    }
}
