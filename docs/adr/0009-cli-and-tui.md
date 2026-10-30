# ADR-0009: CLI and TUI (Rust)

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

Everything is driven by a **CLI**, which must also provide a **TUI** to monitor
a running VM live — showing **blocked IPs** and **DNS requests/decisions**. It
talks to per-VM supervisors over their control sockets
([ADR-0007](0007-control-plane.md)).

## Decision

Implement the CLI, supervisor, filter proxy, and DNS filter in **Rust**
(async via **tokio**), with the TUI built on **ratatui**. The TUI is a client
that `subscribe`s to a VM's event stream and renders it live.

## Details

### Why Rust

- Aligns with cloud-hypervisor and the security posture (memory safety in
  components exposed to hostile traffic); strong async (tokio) and TUI
  (ratatui + crossterm) ecosystems; single static-ish binary is easy to ship
  via the flake ([ADR-0010](0010-packaging-and-rootless.md)).

### CLI surface (initial)

```
soda create <vm> [--cpus N --mem M --disk SIZE]
soda start <vm> [--foreground]
soda stop <vm>
soda ls
soda allow ip <cidr> [--ports …] [--vm <vm>]
soda allow domain <name> [--exact|--wildcard] [--vm <vm>]
soda deny <rule>
soda policy show|edit
soda tui <vm>          # live monitor
soda logs <vm>
soda rm <vm> [--keep-disk]
```

### TUI (ratatui)

- Connects to `$XDG_RUNTIME_DIR/sodabox/<vm>/control.sock`, sends `subscribe`,
  renders a live view:
  - **Egress panel:** recent flows with verdict (allowed/blocked), 5-tuple,
    matched rule / reason, counts. Blocked entries highlighted.
  - **DNS panel:** queries with name, verdict (allowed/refused), resolved IPs,
    TTL, and which egress entries they authorized.
  - **Policy panel:** current effective policy version + a quick view of rules;
    hotkeys to allow/deny a highlighted blocked destination on the spot.
  - **VM status:** state, cpu/mem, uptime.
- Read-primary but supports quick actions (e.g. press to allow a just-blocked
  IP/domain), which issue control-socket commands (ADR-0006 live update).

### Event schema (shared with the supervisor)

```
Event =
  | Egress   { ts, verdict: Allowed|Blocked, proto, saddr, daddr, dport, rule? }
  | Dns      { ts, verdict: Allowed|Refused, qname, qtype, answers[], ttl }
  | Policy   { ts, version, change }
  | Lifecycle{ ts, state }
```

- Events are also written to a per-VM log for `soda logs` and post-hoc audit.

## Consequences

- **Positive:** One language across the stack; safe by construction where it
  matters; good interactive monitoring out of the box; the "allow the thing I
  just saw blocked" workflow is natural.
- **Negative / costs:** TUI work is non-trivial; must handle backpressure/volume
  on busy VMs (bounded ring buffers, sampling).
- **Risks & open questions:**
  - Cross-VM overview (a top-level `soda tui` with no VM arg) fans out over
    all sockets — define layout later.
  - Event volume/rate limiting under a chatty or hostile guest.

## Alternatives considered

- **Zig (reuse/lift from cogbox)** — cogbox is Zig, so staying Zig would let us
  lift its rule parser and socket plumbing without a port. Rejected: we chose a
  fresh Rust tool (cogbox is reference only), and Rust gives a far more mature
  TUI stack (ratatui) plus memory safety in components exposed to hostile
  traffic; no TUI library in Zig is as mature.
- **Go (bubbletea)** — faster to write and trivial static binaries, but off the
  cloud-hypervisor/Rust path and mixes toolchains. Rejected for stack cohesion.
- **Web UI instead of TUI** — heavier, needs a server surface; the requirement
  is specifically a terminal TUI.
