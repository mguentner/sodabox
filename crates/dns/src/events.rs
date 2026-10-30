//! DNS decision event emission from the filtering resolver
//! (ADR-0005/ADR-0009).
//!
//! On every query the resolver reaches a filter verdict — `Refused` (the name
//! is not on the domain allowlist; a blocked/exfil attempt) or `Allowed` (the
//! name passed the filter and resolved, authorizing its A/AAAA IPs into the
//! ephemeral egress set). It emits an [`Event::Dns`] onto a sink; the supervisor
//! owns the receiving end and fans it out to the CLI/TUI and per-VM log.
//! Mirrors the proxy's `EgressEvents` seam; tests use a channel.

use std::sync::Arc;

use sodabox_common::event::Event;

/// Where the resolver sends its DNS-decision events.
pub trait DnsEvents: Send + Sync + 'static {
    fn emit(&self, event: Event);
}

/// Discards events (used when no observer is attached — the default).
pub struct NullEvents;
impl DnsEvents for NullEvents {
    fn emit(&self, _event: Event) {}
}

/// Forwards events onto a Tokio mpsc channel for the supervisor (or a test) to
/// consume.
pub struct ChannelEvents {
    tx: tokio::sync::mpsc::UnboundedSender<Event>,
}

impl ChannelEvents {
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<Event>) -> Self {
        Self { tx }
    }
}

impl DnsEvents for ChannelEvents {
    fn emit(&self, event: Event) {
        // A closed receiver just means nobody is listening; drop the event.
        let _ = self.tx.send(event);
    }
}

/// Convenience: an `Arc<dyn DnsEvents>` that discards.
pub fn null_sink() -> Arc<dyn DnsEvents> {
    Arc::new(NullEvents)
}
