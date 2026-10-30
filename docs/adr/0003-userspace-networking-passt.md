# ADR-0003: User-space networking with stock passt

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

The guest needs network connectivity without a host tap/bridge and without
host `CAP_NET_ADMIN` (rootless, host-non-invasive). **passt** provides
user-mode networking for VMs: it terminates the guest's L2/L3 and translates
guest flows into ordinary host sockets, requiring no privileges on the host.

We reviewed passt's source (cloned into `sources/passt`) to confirm what it does
and does **not** do for our requirements:

- **DNS:** passt implements `--dns-forward`: it advertises a resolver address to
  the guest and, in `fwd_nat_from_tap()` (`fwd.c`), redirects the guest's DNS
  flow to a host resolver (`dns_host`, seeded from the host `resolv.conf`). It
  forwards DNS **packets verbatim** — it does *not* parse or filter query names.
- **Egress filtering:** `fwd_nat_from_tap()` is the single decision point for
  every guest-originated outbound flow. It returns the target `pif`
  (`PIF_HOST`) or `PIF_NONE` (drop) — but today it **always forwards**
  outbound. passt has **no built-in destination allowlist**. Its forwarding
  rules (`fwd_rule.c`) are about **inbound** port forwarding and NAT only.
- **Outbound binding:** passt supports `-o/--outbound`, `--outbound-if4/6`, and
  runs its outbound sockets in **whatever network namespace the passt process
  is in**.

## Decision

Use **stock passt** (no fork, no patch) as the vhost-user network backend for
cloud-hypervisor. Do **not** rely on passt for policy. Egress filtering and DNS
name filtering are layered *around* passt (see
[ADR-0004](0004-egress-enforcement.md), [ADR-0005](0005-dns-filtering.md)),
exploiting the fact that passt's outbound sockets live in a namespace we
control.

## Details

- Wiring: `cloud-hypervisor  ⇄  (vhost-user unix socket)  ⇄  passt`. Both are
  our processes; the socket is not exposed to the guest.
- passt runs **inside a per-VM private network namespace** created by the
  supervisor. Because passt's outbound sockets are created in that namespace,
  all guest egress is subject to the redirect rules we install there
  (ADR-0004) — without touching host firewall tables.
- DNS: configure passt so the guest's DNS is forwarded to **our** filtering
  resolver's address (reachable inside the netns), rather than straight to a
  host nameserver. Exact flag wiring (`--dns-forward` target vs. redirect) is an
  implementation task tracked in ADR-0005.
- Keep passt **stock** so we can track upstream (security fixes) without
  maintaining a fork. All `sodabox`-specific behavior lives in the surrounding
  netns + proxy.

## Consequences

- **Positive:** Rootless, no host tap/bridge; no fork to maintain; upstream
  security fixes flow in freely; the namespace trick gives us a clean
  interception point without modifying passt.
- **Negative / costs:** We depend on passt's process-namespace semantics staying
  as they are; policy logic must live outside passt (more moving parts).
- **Risks & open questions:**
  - Verify the exact passt invocation for vhost-user + running inside our netns,
    and that `--dns-forward` can target an arbitrary in-netns address.
  - passt is exposed to hostile guest packets — treat as a hardening surface;
    keep it updated and seccomp-confined as upstream ships it.

## Alternatives considered

- **Fork/patch passt** to add an allowlist in `fwd_nat_from_tap()` — rejected
  (for now): cleaner single chokepoint, but creates a maintained fork and puts
  security policy inside the packet-exposed process. The namespace + proxy
  approach keeps passt stock. Revisit if the proxy approach proves too costly.
- **slirp4netns / QEMU SLIRP** — weaker performance and features than passt.
- **Host tap + bridge** — requires host `CAP_NET_ADMIN` and host config;
  violates rootless/non-invasive rules.
