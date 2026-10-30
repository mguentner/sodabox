# ADR-0007: Control plane — per-VM supervisor, no daemon

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

We need to start/stop multiple VMs, apply live policy updates
([ADR-0006](0006-allowlist-model.md)), and stream monitoring events to a TUI
([ADR-0009](0009-cli-and-tui.md)) — all rootless, per invoking user. A central
long-running daemon is one option; a per-VM supervisor process spawned by the
CLI is another.

## Decision

**No central daemon.** `soda start <vm>` spawns a **per-VM supervisor
process** that owns that VM's entire runtime — the network namespace,
cloud-hypervisor, passt, the filter proxy, and the DNS filter — and exposes a
**per-VM control + event unix socket**. The CLI and TUI are thin clients that
connect to that socket. Multiple VMs = multiple independent supervisors.

## Details

### Process tree (per VM)

```
soda start vm1
   └─ supervisor(vm1)                      # long-lived, owns the userns+netns
        ├─ cloud-hypervisor(vm1)
        ├─ passt(vm1)          (in netns)
        ├─ filter proxy(vm1)   (Rust, in-process or child)
        └─ dns filter(vm1)     (Rust, in-process or child)
      exposes: $XDG_RUNTIME_DIR/sodabox/vm1/control.sock
```

- The supervisor creates the user+network namespace and holds it for the VM's
  lifetime; children run inside as needed (ADR-0004).
- Filter proxy and DNS filter may be threads/tasks in the supervisor process
  (simplest, shared policy state) rather than separate processes — decided at
  implementation time; the boundary the ADRs rely on is only that they run
  host-side and outside the guest.

### Discovery & layout

- Runtime state under `$XDG_RUNTIME_DIR/sodabox/<vm>/`: `control.sock`, `pid`,
  console socket, passt/chv sockets.
- Persistent state under `$XDG_DATA_HOME/sodabox/<vm>/`: disk image, policy,
  metadata ([ADR-0008](0008-persistent-storage.md)).
- `soda ls` enumerates VMs by scanning these dirs and probing sockets.

### Control protocol

- Line/length-delimited JSON (or similar) over the unix socket. Requests:
  `status`, `policy.get`, `policy.set`, `allow`, `deny`, `stop`, `subscribe`.
- `subscribe` returns a live event stream (blocked/allowed egress, DNS
  decisions, VM lifecycle) — the TUI's data source (ADR-0009).
- Socket permissions: user-only (0600, in the user's runtime dir); no
  cross-user access.

### Lifecycle & supervision

- The supervisor supervises its children; if cloud-hypervisor exits, it tears
  down the netns, proxy, and sockets cleanly (fail-closed: teardown removes all
  egress paths).
- Detached/background start by default; `--foreground` for debugging.
- Crash of the supervisor => VM's egress dies with it (fail-closed by
  construction, since the netns/proxy are its children).
- Optional: a `systemd --user` unit template for auto-restart, but not required
  and never a system-level service.

## Consequences

- **Positive:** No always-on privileged surface; each VM is self-contained and
  independently fails/upgrades; namespace ownership maps naturally to a process
  lifetime; simple mental model; strong isolation between VMs.
- **Negative / costs:** No single place for cross-VM concerns (global quotas,
  aggregate dashboards) — must aggregate by scanning per-VM sockets; each
  supervisor duplicates some machinery.
- **Risks & open questions:**
  - Cross-VM TUI/overview must fan out over sockets (acceptable; ADR-0009).
  - Define cleanup of stale runtime dirs after unclean shutdown.
  - Decide in-process vs. child-process for proxy/DNS (leaning in-process).

## Alternatives considered

- **Central daemon** owning all VMs — nicer for aggregate views and a single API,
  but an always-running component, a bigger blast radius, and more complex
  rootless namespace ownership. Rejected for v1; the per-VM socket API leaves the
  door open to add an optional aggregator later without changing enforcement.
