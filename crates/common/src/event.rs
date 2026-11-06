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
        /// Why a blocked flow was refused.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<RefusalReason>,
    },
    /// A DNS decision from the filtering resolver (ADR-0005).
    Dns {
        ts: u64,
        verdict: DnsVerdict,
        qname: String,
        #[serde(default)]
        answers: Vec<String>,
        ttl: u32,
        /// Why a refused query was refused.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<RefusalReason>,
    },
    /// One request through the inference gateway (ADR-0020). Metadata only:
    /// prompts and completions are never part of an event.
    Inference {
        ts: u64,
        verdict: Verdict,
        /// The route's API format: `openai` or `ollama`.
        api: String,
        alias: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        /// HTTP status returned to the guest.
        status: u16,
        #[serde(default)]
        tokens: Tokens,
        /// False if the response ended early (client gone, upstream cut off),
        /// so the usage may be partial.
        complete: bool,
        latency_ms: u64,
    },
    /// A request was refused because the alias's token quota is used up.
    QuotaExhausted { ts: u64, alias: String },
    /// A live policy change.
    Policy { ts: u64, version: u32 },
    /// A request was parked for interactive approval (ADR-0021): no rule
    /// matched, so instead of refusing, the enforcement component holds it for
    /// `REQUEST_TTL` and waits for a `RequestResolve` over the control socket.
    RequestPending {
        ts: u64,
        id: u64,
        /// `dns`, `tcp` or `udp`.
        proto: String,
        /// The qname (dns) or destination IP (tcp/udp).
        destination: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// A name whose lookup recently returned this IP (tcp/udp). A hint, not
        /// proof; see [`crate::request::PendingRequest::via`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<String>,
        /// Unix seconds when the request dies if unresolved.
        expires_ts: u64,
    },
    /// A parked request left the table: `approved` / `denied` / `expired` /
    /// `abandoned`.
    RequestResolved { ts: u64, id: u64, verdict: String },
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

/// Token usage of one inference request: as the provider reported it, or
/// the gateway's estimate when the response ended without a report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    /// Prompt tokens, including `cache_read`.
    pub input: u64,
    /// Completion tokens, including `reasoning`.
    pub output: u64,
    #[serde(default)]
    pub reasoning: u64,
    #[serde(default)]
    pub cache_read: u64,
    /// The provider reported no usage (e.g. the stream was cut off before its
    /// end): `input` is estimated from the request size, `output` from the
    /// content chunks streamed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub estimated: bool,
}

impl Tokens {
    /// What a request costs against a quota: input and output, but not cache
    /// reads (ADR-0020).
    pub fn metered(&self) -> u64 {
        self.input.saturating_sub(self.cache_read) + self.output
    }

    pub fn total(&self) -> u64 {
        self.input + self.output
    }
}

/// Why a request ended in a refusal (ADR-0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalReason {
    /// Refused over the control socket, with nothing recorded.
    Denied,
    /// Nobody answered within the hold.
    TimedOut,
    /// The request table was full, so nobody was asked.
    QueueFull,
    /// Approved, but no rule covered it when it was re-checked.
    NotCovered,
    /// The gateway is off or the guest has no `service` rule for it.
    NoAccess,
}

impl RefusalReason {
    /// The label on TUI rows and in `soda logs`.
    pub fn label(self) -> &'static str {
        match self {
            RefusalReason::Denied => "denied",
            RefusalReason::TimedOut => "timed out",
            RefusalReason::QueueFull => "queue full",
            RefusalReason::NotCovered => "not covered",
            RefusalReason::NoAccess => "no access",
        }
    }
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
