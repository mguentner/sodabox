//! Per-VM host-side filtering DNS resolver (ADR-0005). Receives guest queries
//! forwarded by passt into the netns (spike 0002:
//! docs/spikes/0002-passt-in-netns.md — `--dns-forward` guest-facing address
//! plus `-D` upstream = this resolver). Refuses names not on the domain
//! allowlist (anti-QNAME-exfil), resolves allowed names upstream via the
//! host `resolv.conf`, and authorizes the resolved A/AAAA IPs into the
//! VM's ephemeral egress set (TTL-bounded).
//!
//! - [`wire`] — bounds-checked DNS codec.
//! - [`frontend`] — UDP listener + [`frontend::QueryHandler`].
//! - [`domain`] — domain allowlist matching.
//! - [`resolver::FilteringResolver`] — the handler composing filter + upstream +
//!   ephemeral admission.
//! - [`events`] — DNS-decision event emission onto the monitoring stream.

pub mod domain;
pub mod events;
pub mod frontend;
pub mod resolver;
pub mod wire;

pub use resolver::FilteringResolver;
