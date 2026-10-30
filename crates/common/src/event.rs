//! Monitoring event schema streamed from a supervisor to the CLI/TUI (ADR-0009).
//! Skeleton — fields will grow as the proxy/DNS emit real events.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// One event on a VM's live stream (also written to a per-VM log).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Event {
    /// An egress flow verdict from the filter proxy (ADR-0004).
    Egress {
        ts: u64,
        verdict: Verdict,
        proto: String,
        daddr: String,
        dport: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
    },
    /// A DNS decision from the filtering resolver (ADR-0005).
    Dns {
        ts: u64,
        verdict: DnsVerdict,
        qname: String,
        #[serde(default)]
        answers: Vec<String>,
        ttl: u32,
    },
    /// A live policy change.
    Policy { ts: u64, version: u32 },
    /// VM lifecycle transition.
    Lifecycle { ts: u64, state: String },
    /// A backpressure gap: a subscriber fell behind and the
    /// bounded event ring dropped `count` events before the next one it will
    /// receive. Surfaced so the TUI can show an explicit gap marker instead of
    /// silently losing events under a chatty (or hostile) guest.
    Dropped { ts: u64, count: u64 },
}

/// Seconds since the Unix epoch, for stamping an [`Event`]. Clamps a
/// pre-epoch clock to 0 rather than erroring — a monitoring timestamp is not
/// worth failing a stream over.
pub fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allowed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsVerdict {
    Allowed,
    Refused,
}
