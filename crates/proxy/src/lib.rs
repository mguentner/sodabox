//! Egress filter proxy (ADR-0004). Runs host-side, receives all VM egress via
//! **TPROXY** in the per-VM netns (decided by spike 0003:
//! docs/spikes/0003-egress-interception.md), recovers the original destination
//! (TCP `getsockname()`, UDP `IP_RECVORIGDSTADDR` — both on `IP_TRANSPARENT`
//! sockets), checks it against the VM allowlist, then splices or drops+logs.
//!
//! Implemented across the modules below: `tcp` (transparent TCP + splice),
//! `udp` (transparent UDP + forged-source reply relay), `policy` (allowlist
//! eval and allow-path/events), and `events`. Fail-closed
//! is enforced by the supervisor supervising these `serve()` loops. The
//! supervisor composes the pieces (`sodabox_supervisor::supervise`); there is no
//! monolithic entry point in this crate.

pub mod events;
pub mod policy;
pub mod tcp;
pub mod udp;
