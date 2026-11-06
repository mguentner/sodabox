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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::allowlist::Proto;
use crate::blocklist::Blocklist;
use crate::event::{now_ts, Event, RefusalReason};

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
/// How long a lookup's answer is remembered for [`PendingRequest::via`]. Longer
/// than DNS TTLs, which floor as low as seconds: applications cache answers past
/// them, and a row must not claim no lookup happened because of that.
const ORIGIN_RETENTION: Duration = Duration::from_secs(3600);
/// Remembered answers per VM (oldest dropped past this). The guest can make these
/// churn through a wildcard-ish approved name, so they need a bound.
const MAX_ORIGINS: usize = 4096;

/// The outcome of a held request. `Expired` and `Abandoned` only ever originate
/// from the sweep; a resolved request is `Approved` or `Denied`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestVerdict {
    Approved,
    Denied,
    Expired,
    /// Every enforcement call waiting on it went away (the client gave up).
    Abandoned,
    /// The table was at a cap, so it was refused to make room or on the spot.
    /// Nobody decided this, which is why it isn't `Denied`.
    QueueFull,
    /// A blocklist entry covers it.
    Blocklisted,
}

impl RequestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestVerdict::Approved => "approved",
            RequestVerdict::Denied => "denied",
            RequestVerdict::Expired => "expired",
            RequestVerdict::Abandoned => "abandoned",
            RequestVerdict::QueueFull => "queue-full",
            RequestVerdict::Blocklisted => "blocklisted",
        }
    }
}

/// Why a held call ended up refused, from the verdict it received (`None` if its
/// own wait ran out first). `Approved` here means the re-check that follows an
/// approval found no rule.
pub fn refusal_reason(verdict: Option<RequestVerdict>) -> RefusalReason {
    match verdict {
        Some(RequestVerdict::Approved) => RefusalReason::NotCovered,
        Some(RequestVerdict::Denied) => RefusalReason::Denied,
        Some(RequestVerdict::QueueFull) => RefusalReason::QueueFull,
        Some(RequestVerdict::Blocklisted) => RefusalReason::Blocklist,
        Some(RequestVerdict::Expired | RequestVerdict::Abandoned) | None => RefusalReason::TimedOut,
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
    /// For tcp/udp, the name whose lookup most recently returned this IP. A hint,
    /// not proof: it says what the guest looked up, not who owns the address,
    /// since a guest can point a name of its own at anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// Unix seconds at which the request is denied if still unresolved.
    pub expires_ts: u64,
}

/// How a row describes where its address came from: `via <name>`, or that the
/// guest reached it without a recent lookup, which is worth noticing. `None` for
/// a dns request (no `port`), which is a name already.
pub fn origin_label(port: Option<u16>, via: Option<&str>) -> Option<String> {
    port?;
    Some(match via {
        Some(name) => format!("via {name}"),
        None => "no recent lookup".to_string(),
    })
}

/// A remembered lookup answer: which name returned an address, and when.
struct Origin {
    name: String,
    noted: Instant,
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

/// Restores the permit for an address a name returned earlier, if a rule on that
/// name covers the connection: `(name, destination, proto)` → restored. Set by
/// the supervisor, which holds the domain rules. Must not call back into this
/// table.
pub type Readmit = Arc<dyn Fn(&str, SocketAddr, Proto) -> bool + Send + Sync>;

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
    /// What the resolver answered, for [`PendingRequest::via`].
    origins: Mutex<HashMap<IpAddr, Origin>>,
    /// See [`Readmit`].
    readmit: Mutex<Option<Readmit>>,
    /// What is refused instead of held.
    blocklist: Mutex<Blocklist>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            next_id: Mutex::new(0),
            events: Mutex::new(None),
            origins: Mutex::new(HashMap::new()),
            readmit: Mutex::new(None),
            blocklist: Mutex::new(Blocklist::default()),
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

    /// Set how remembered lookups restore permits (see [`Readmit`]). Separate from
    /// construction because the rules it reads belong to the resolver, which is
    /// built around this table.
    pub fn set_readmit(&self, readmit: Readmit) {
        *self.inner.readmit.lock().unwrap() = Some(readmit);
    }

    /// Replace what is refused instead of held. Rows it now covers go on the next
    /// [`Self::refuse_blocklisted`].
    pub fn set_blocklist(&self, blocklist: Blocklist) {
        *self.inner.blocklist.lock().unwrap() = blocklist;
    }

    /// Whether a blocklist entry covers this request.
    fn blocklisted(&self, proto: &str, destination: &str, port: Option<u16>) -> bool {
        let blocklist = self.inner.blocklist.lock().unwrap();
        let Some(port) = port else {
            return blocklist.blocks_name(destination);
        };
        let (Ok(ip), Ok(proto)) = (destination.parse::<IpAddr>(), Proto::parse(proto)) else {
            return false;
        };
        let via = self.origin_of(destination);
        blocklist.blocks_address(SocketAddr::new(ip, port), proto, via.as_deref())
    }

    /// Refuse every held request a blocklist entry now covers. The sweep runs this
    /// after releasing what a rule covers, since an allow rule wins.
    pub fn refuse_blocklisted(&self) {
        let mut entries = self.inner.entries.lock().unwrap();
        let covered: Vec<u64> = entries
            .iter()
            .filter(|e| self.blocklisted(&e.info.proto, &e.info.destination, e.info.port))
            .map(|e| e.info.id)
            .collect();
        for id in covered {
            self.finish_locked(&mut entries, id, RequestVerdict::Blocklisted);
        }
    }

    /// Try to restore the permit for an address request from the name remembered
    /// for it. Returns whether one was restored.
    pub fn readmit(&self, proto: &str, destination: &str, port: u16) -> bool {
        let Some(readmit) = self.inner.readmit.lock().unwrap().clone() else {
            return false;
        };
        let (Ok(ip), Ok(proto)) = (destination.parse::<IpAddr>(), Proto::parse(proto)) else {
            return false;
        };
        let Some(name) = self.origin_of(destination) else {
            return false;
        };
        readmit(&name, SocketAddr::new(ip, port), proto)
    }

    fn emit(&self, event: Event) {
        let sink = self.inner.events.lock().unwrap().clone();
        if let Some(sink) = sink {
            sink(event);
        }
    }

    /// Remember that looking up `name` returned `ip`, so a request to that address
    /// can say so. The latest name wins when several share an address.
    pub fn note_resolved(&self, ip: IpAddr, name: &str) {
        let mut origins = self.inner.origins.lock().unwrap();
        if !origins.contains_key(&ip) && origins.len() >= MAX_ORIGINS {
            let oldest = origins
                .iter()
                .min_by_key(|(_, o)| o.noted)
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest {
                origins.remove(&oldest);
            }
        }
        origins.insert(
            ip,
            Origin {
                name: name.trim_end_matches('.').to_string(),
                noted: Instant::now(),
            },
        );
    }

    /// The remembered name for `destination`, if it's an address with a recent one.
    fn origin_of(&self, destination: &str) -> Option<String> {
        let ip: IpAddr = destination.parse().ok()?;
        let origins = self.inner.origins.lock().unwrap();
        let origin = origins.get(&ip)?;
        (origin.noted.elapsed() <= ORIGIN_RETENTION).then(|| origin.name.clone())
    }

    /// Park a request. A matching entry (same proto/destination/port) is reused,
    /// so retransmissions and parallel attempts coalesce instead of minting rows;
    /// a new one is announced with a [`Event::RequestPending`]. Returns the
    /// request (with its id) and the channel the verdict arrives on — the caller
    /// should also bound its wait by [`REQUEST_TTL`] (see [`Self::resolve`] and
    /// [`Self::expire_due`], which drive this side) so a missing sweep cannot
    /// wedge a flow forever. On table overflow the oldest entry is denied early.
    ///
    /// An address a rule already covers through its remembered name is approved
    /// right here: there is no decision to ask for, so no row and no notification.
    /// The same goes for a request a blocklist entry covers, which is refused.
    pub fn hold(
        &self,
        proto: &str,
        destination: &str,
        port: Option<u16>,
    ) -> (PendingRequest, oneshot::Receiver<RequestVerdict>) {
        let (tx, rx) = oneshot::channel();
        let decided = if port.is_some_and(|p| self.readmit(proto, destination, p)) {
            Some(RequestVerdict::Approved)
        } else if self.blocklisted(proto, destination, port) {
            Some(RequestVerdict::Blocklisted)
        } else {
            None
        };
        if let Some(verdict) = decided {
            let _ = tx.send(verdict);
            let info = PendingRequest {
                id: self.next_id(),
                proto: proto.to_string(),
                destination: destination.to_string(),
                port,
                via: self.origin_of(destination),
                expires_ts: now_ts(),
            };
            return (info, rx);
        }
        let mut entries = self.inner.entries.lock().unwrap();

        let held = |entries: &[Entry]| entries.iter().map(|e| e.waiters.len()).sum::<usize>();

        // Coalesce into a live matching entry.
        if let Some(idx) = entries.iter().position(|e| {
            e.info.proto == proto && e.info.destination == destination && e.info.port == port
        }) {
            if held(&entries) >= MAX_WAITERS {
                let _ = tx.send(RequestVerdict::QueueFull);
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
                self.finish_locked(&mut entries, id, RequestVerdict::QueueFull);
            } else {
                break;
            }
        }

        let info = PendingRequest {
            id: self.next_id(),
            proto: proto.to_string(),
            destination: destination.to_string(),
            port,
            via: self.origin_of(destination),
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
            via: info.via.clone(),
            expires_ts: info.expires_ts,
        });
        (info, rx)
    }

    fn next_id(&self) -> u64 {
        let mut next = self.inner.next_id.lock().unwrap();
        *next += 1;
        *next
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

    /// An address covered through its remembered name is approved without a row
    /// or an event; a name the hook turns down, or no lookup at all, is held.
    #[tokio::test]
    async fn a_covered_remembered_address_never_becomes_a_request() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let table = shared().with_events(Arc::new(move |e: Event| {
            sink_events.lock().unwrap().push(e);
        }));
        table.set_readmit(Arc::new(|name, dst, proto| {
            name == "covered.test" && dst.port() == 443 && proto == Proto::Tcp
        }));
        table.note_resolved("203.0.113.5".parse().unwrap(), "covered.test");

        let (_, mut rx) = table.hold("tcp", "203.0.113.5", Some(443));
        assert_eq!(rx.try_recv(), Ok(RequestVerdict::Approved));
        assert!(table.list().is_empty());
        assert!(events.lock().unwrap().is_empty());

        let (_, mut other_port) = table.hold("tcp", "203.0.113.5", Some(22));
        let (_, mut no_lookup) = table.hold("tcp", "198.51.100.1", Some(443));
        assert!(other_port.try_recv().is_err());
        assert!(no_lookup.try_recv().is_err());
        assert_eq!(table.list().len(), 2);
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
    async fn requests_name_the_lookup_that_returned_their_address() {
        let table = shared();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();

        // No lookup yet.
        let (before, _rx1) = table.hold("tcp", "203.0.113.5", Some(443));
        assert_eq!(before.via, None);

        table.note_resolved(ip, "www.example.com.");
        let (tcp, _rx2) = table.hold("tcp", "203.0.113.5", Some(80));
        assert_eq!(tcp.via.as_deref(), Some("www.example.com"));
        let (udp, _rx3) = table.hold("udp", "203.0.113.5", Some(53));
        assert_eq!(udp.via.as_deref(), Some("www.example.com"));

        // A dns request is a name already.
        let (dns, _rx4) = table.hold("dns", "maybe.test", None);
        assert_eq!(dns.via, None);

        // The latest name wins on a shared address.
        table.note_resolved(ip, "other.test");
        let (latest, _rx5) = table.hold("tcp", "203.0.113.5", Some(22));
        assert_eq!(latest.via.as_deref(), Some("other.test"));

        // Past the retention it's no longer a recent lookup.
        table
            .inner
            .origins
            .lock()
            .unwrap()
            .get_mut(&ip)
            .unwrap()
            .noted = Instant::now() - ORIGIN_RETENTION - Duration::from_secs(1);
        let (stale, _rx6) = table.hold("tcp", "203.0.113.5", Some(23));
        assert_eq!(stale.via, None);
    }

    #[test]
    fn remembered_lookups_are_bounded_dropping_the_oldest() {
        let table = shared();
        let ip = |n: u32| IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + n));
        for n in 0..=MAX_ORIGINS as u32 {
            table.note_resolved(ip(n), "example.com");
        }
        let origins = table.inner.origins.lock().unwrap();
        assert_eq!(origins.len(), MAX_ORIGINS);
        assert!(origins.contains_key(&ip(MAX_ORIGINS as u32)));
    }

    #[test]
    fn origin_label_flags_an_address_with_no_lookup() {
        assert_eq!(
            origin_label(Some(443), Some("example.com")).as_deref(),
            Some("via example.com")
        );
        assert_eq!(
            origin_label(Some(443), None).as_deref(),
            Some("no recent lookup")
        );
        assert_eq!(origin_label(None, None), None);
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
        assert_eq!(rx.try_recv(), Ok(RequestVerdict::QueueFull));
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
        assert_eq!(extra.try_recv(), Ok(RequestVerdict::QueueFull));
        assert_eq!(table.list().len(), 1);
        assert_eq!(table.list()[0].id, info.id);

        // The flood can't hide a new destination: its row evicts the oldest.
        let (new, mut new_rx) = table.hold("tcp", "198.51.100.1", Some(80));
        assert!(new_rx.try_recv().is_err());
        assert_eq!(table.list(), vec![new]);
        assert!(held
            .iter_mut()
            .all(|rx| rx.try_recv() == Ok(RequestVerdict::QueueFull)));
    }

    fn table_blocking(blocklist: Vec<crate::policy::BlocklistEntry>) -> PendingRequests {
        let table = shared();
        table.set_blocklist(
            Blocklist::from_policy(&crate::policy::VmPolicy {
                blocklist,
                ..Default::default()
            })
            .unwrap(),
        );
        table
    }

    fn blocked_name(ports: Option<&str>, proto: Option<&str>) -> crate::policy::BlocklistEntry {
        crate::policy::BlocklistEntry::Domain {
            name: "example.com".into(),
            scope: crate::policy::DomainScope::Exact,
            ports: ports.map(Into::into),
            proto: proto.map(Into::into),
        }
    }

    /// No row and no notification: that is the point of the blocklist.
    #[tokio::test]
    async fn a_blocklisted_request_is_refused_without_a_row_or_an_event() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let table = shared().with_events(Arc::new(move |e: Event| {
            sink_events.lock().unwrap().push(e);
        }));
        table.set_blocklist(
            Blocklist::from_policy(&crate::policy::VmPolicy {
                blocklist: vec![blocked_name(None, None)],
                ..Default::default()
            })
            .unwrap(),
        );

        let (_, mut dns) = table.hold("dns", "example.com.", None);
        assert_eq!(dns.try_recv(), Ok(RequestVerdict::Blocklisted));
        assert!(table.list().is_empty());
        assert!(events.lock().unwrap().is_empty());

        // Its neighbour is still a question.
        let (_, mut other) = table.hold("dns", "www.example.com", None);
        assert!(other.try_recv().is_err());
        assert_eq!(table.list().len(), 1);
    }

    #[tokio::test]
    async fn a_name_entry_refuses_addresses_through_their_remembered_lookup() {
        let table = table_blocking(vec![blocked_name(Some("443"), Some("udp"))]);
        table.note_resolved("203.0.113.5".parse().unwrap(), "example.com.");

        let (_, mut quic) = table.hold("udp", "203.0.113.5", Some(443));
        assert_eq!(quic.try_recv(), Ok(RequestVerdict::Blocklisted));
        // The rest of that address, and an address with no lookup, still ask.
        let (_, mut tcp) = table.hold("tcp", "203.0.113.5", Some(443));
        let (_, mut unknown) = table.hold("udp", "198.51.100.1", Some(443));
        assert!(tcp.try_recv().is_err());
        assert!(unknown.try_recv().is_err());
    }

    /// An allow wins: a request a rule covers through its name is approved, not
    /// refused, whatever the blocklist says.
    #[tokio::test]
    async fn a_covering_rule_beats_a_blocklist_entry() {
        let table = table_blocking(vec![blocked_name(None, None)]);
        table.note_resolved("203.0.113.5".parse().unwrap(), "example.com");
        table.set_readmit(Arc::new(|_, _, _| true));

        let (_, mut rx) = table.hold("tcp", "203.0.113.5", Some(443));
        assert_eq!(rx.try_recv(), Ok(RequestVerdict::Approved));
    }

    #[tokio::test]
    async fn a_new_entry_clears_the_rows_it_covers_on_the_next_sweep() {
        let table = shared();
        table.note_resolved("203.0.113.5".parse().unwrap(), "example.com");
        table.note_resolved("203.0.113.6".parse().unwrap(), "example.com");
        let (_, mut a) = table.hold("udp", "203.0.113.5", Some(443));
        let (_, mut b) = table.hold("udp", "203.0.113.6", Some(443));
        let (_, mut c) = table.hold("tcp", "203.0.113.6", Some(443));
        table.refuse_blocklisted();
        assert_eq!(table.list().len(), 3);

        table.set_blocklist(
            Blocklist::from_policy(&crate::policy::VmPolicy {
                blocklist: vec![blocked_name(Some("443"), Some("udp"))],
                ..Default::default()
            })
            .unwrap(),
        );
        table.refuse_blocklisted();
        assert_eq!(a.try_recv(), Ok(RequestVerdict::Blocklisted));
        assert_eq!(b.try_recv(), Ok(RequestVerdict::Blocklisted));
        assert!(c.try_recv().is_err());
        assert_eq!(table.list().len(), 1);
    }

    #[test]
    fn every_verdict_explains_a_refusal() {
        use RefusalReason as R;
        for (verdict, reason) in [
            (Some(RequestVerdict::Approved), R::NotCovered),
            (Some(RequestVerdict::Denied), R::Denied),
            (Some(RequestVerdict::Expired), R::TimedOut),
            (Some(RequestVerdict::QueueFull), R::QueueFull),
            (Some(RequestVerdict::Blocklisted), R::Blocklist),
            (None, R::TimedOut),
        ] {
            assert_eq!(refusal_reason(verdict), reason);
        }
    }
}
