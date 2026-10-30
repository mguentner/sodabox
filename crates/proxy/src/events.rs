//! Egress event emission from the filter proxy (ADR-0009).
//!
//! On every verdict the proxy emits an [`Event::Egress`] (allowed or blocked,
//! with the 5-tuple and the matched rule) onto a sink. The supervisor owns the
//! receiving end and fans it out to the CLI/TUI and the per-VM log;
//! tests use an in-memory sink.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sodabox_common::event::Event;

/// Where the proxy sends its events.
pub trait EgressEvents: Send + Sync + 'static {
    fn emit(&self, event: Event);
}

/// Discards events (used when no observer is attached).
pub struct NullEvents;
impl EgressEvents for NullEvents {
    fn emit(&self, _event: Event) {}
}

/// Forwards events onto a Tokio mpsc channel for the supervisor to consume.
pub struct ChannelEvents {
    tx: tokio::sync::mpsc::UnboundedSender<Event>,
}

impl ChannelEvents {
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<Event>) -> Self {
        Self { tx }
    }
}

impl EgressEvents for ChannelEvents {
    fn emit(&self, event: Event) {
        // A closed receiver just means nobody is listening; drop the event.
        let _ = self.tx.send(event);
    }
}

/// Convenience: an `Arc<dyn EgressEvents>` that discards.
pub fn null_sink() -> Arc<dyn EgressEvents> {
    Arc::new(NullEvents)
}

/// Seconds since the Unix epoch, for event timestamps.
pub(crate) fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
