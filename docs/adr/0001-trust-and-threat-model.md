# ADR-0001: Trust and threat model

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

`sodabox` runs **arbitrary, untrusted** Linux applications. The security goal is
to give such an application a working environment while constraining what it can
reach on the network — deny-by-default egress with an explicit allowlist — and
to do so **rootless** and **without modifying the host** (no host firewall
rules, no setuid, no persistent host state outside a per-user data dir).

Before choosing enforcement mechanisms we must be explicit about *who is
trusted* and *where the untrusted boundary is*, because it determines whether a
control can be relied upon.

## Decision

The **untrusted boundary is the guest VM**. Everything the sandboxed app can
influence — including a full root shell inside the guest and the guest kernel —
is treated as hostile. All security-relevant enforcement (egress allowlist, DNS
filtering) runs **outside the guest**, in host-side components that the guest
cannot reach or reconfigure. All `sodabox` components run as the **invoking
unprivileged user**; privilege is obtained only via **unprivileged user +
network namespaces**, and only *inside* namespaces we own.

## Details

Trust tiers (highest to lowest):

1. **Host kernel + `sodabox` host components** (trusted) — the CLI, the per-VM
   supervisor, the filter proxy, and the DNS filter. Run as the unprivileged
   user. May hold `CAP_NET_ADMIN`/`CAP_NET_RAW` **only within a user namespace
   they created**, never on the host.
2. **cloud-hypervisor + passt** (trusted binaries, adversary-adjacent) — our
   stock binaries. passt is exposed to hostile guest packets, so it is a
   hardening surface but is not where policy is enforced.
3. **Guest kernel + guest userspace** (untrusted) — assume the app has root in
   the guest and can run arbitrary code, load modules, and rewrite any in-guest
   network config.

Consequences of the boundary:

- In-guest firewalling (nftables/agent inside the VM) is **explicitly not a
  security control** — a root app disables it. It may be used only for
  convenience/observability, never relied upon.
- The egress chokepoint must be a host-side component the guest cannot bypass
  (see [ADR-0004](0004-egress-enforcement.md)).
- "No host firewall rules" is honored by confining all packet-filtering rules to
  a **per-VM private network namespace** we create; the host's global
  `nftables`/`iptables` tables are never touched.

### Threats in scope

- Data exfiltration / C2 to non-allowlisted destinations.
- DNS-based exfiltration and resolution of non-allowlisted names.
- Guest attempts to reconfigure or bypass egress controls.

### Threats out of scope (initially)

- **VM escape** via a cloud-hypervisor/KVM 0-day (mitigated by microVM attack
  surface + seccomp, ADR-0002; not eliminated).
- **Covert/side channels** and timing exfiltration through *allowed*
  destinations.
- **Host compromise** by a user who already runs `sodabox` as themselves.
- Ingress/inbound exposure (the model is egress-focused; no listening ports are
  published to the host by default).

## Consequences

- **Positive:** A single, clear rule — "trust nothing in the guest" — makes it
  obvious which designs are acceptable and rules out whole classes of
  bypassable controls up front.
- **Negative / costs:** Enforcement cannot use the convenient in-guest path;
  host-side interception is more work (ADR-0004).
- **Risks & open questions:** VM-escape resilience depends on upstream
  cloud-hypervisor/KVM; we track CVEs and keep the guest kernel/config minimal.

## Alternatives considered

- **Trust an in-guest agent to self-restrict** — rejected: trivially bypassable
  by the very code we are sandboxing.
- **Root-based host firewalling per VM** — rejected: violates the rootless and
  host-non-invasive requirements.
