# ADR-0002: Virtualization stack — cloud-hypervisor + NixOS guests

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

We need strong isolation between the untrusted guest ([ADR-0001](0001-trust-and-threat-model.md))
and the host, while running **rootless** and starting quickly enough to be used
interactively for arbitrary apps. Container-only isolation shares the host
kernel and is a weaker boundary for hostile code; a VM boundary is preferred.

## Decision

Use **cloud-hypervisor** as the VMM, running **microVMs** that boot
**NixOS**-based guest images. cloud-hypervisor runs as the unprivileged user
against `/dev/kvm`.

## Details

- **VMM:** cloud-hypervisor — Rust, minimal device model (virtio-blk,
  virtio-net via vhost-user, virtio-console), seccomp sandboxing per worker
  thread, designed for rootless operation with only `/dev/kvm` access.
- **Guest image:** built from NixOS — reproducible, declarative, minimal closure
  (only what the target app needs). The guest definition is **user-owned,
  npins-pinned sources in the config dir** ([ADR-0012](0012-guest-definition-user-owned.md)),
  built with plain `nix-build` (not sodabox's flake); `microvm.nix` is a candidate
  builder to evaluate.
- **Boot:** direct kernel boot (`--kernel`/`--cmdline`) with a NixOS kernel +
  initrd/rootfs, avoiding a full firmware/bootloader path for fast start and
  smaller surface.
- **Devices:**
  - Disk: virtio-blk backed by a per-VM image ([ADR-0008](0008-persistent-storage.md)).
  - Network: **virtio-net via vhost-user**, with **passt** as the backend
    ([ADR-0003](0003-userspace-networking-passt.md)). No tap device on the host,
    no bridge, no host `CAP_NET_ADMIN`.
  - Console: virtio-console to the supervisor for logs/attach.
- **Resources:** vCPU/memory configured per VM via the CLI; memory not shared
  with host (no ballooning that leaks) unless explicitly enabled.

## Consequences

- **Positive:** Hardware-virtualization boundary; Rust VMM aligned with the rest
  of the stack; rootless via `/dev/kvm`; reproducible minimal guests via Nix.
- **Negative / costs:** Requires KVM (`/dev/kvm` access) on the host; guest
  images must be built/maintained; microVM device model may lack conveniences
  some apps expect (addressed per-app in the image).
- **Risks & open questions:**
  - Exact rootless launch recipe for cloud-hypervisor + vhost-user socket
    permissions to verify (implementation task).
  - Whether to standardize on `microvm.nix` or a bespoke image builder.
  - GPU/display and USB passthrough are out of scope initially.
  - The guest sees the host's CPU identity (vendor, model, brand string) via
    CPUID: cloud-hypervisor only has the `host` CPU profile. A static identity
    (some Intel i7) is to be pinned once
    [cloud-hypervisor#7068](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/7068)
    lands; no local VMM patch in the meantime.

## Alternatives considered

- **QEMU (microvm machine type)** — heavier, larger surface; viable fallback,
  but cloud-hypervisor is leaner and Rust-aligned.
- **Firecracker** — excellent minimalism but a more restrictive device model
  and weaker fit for interactive/desktop-ish apps and flexible disks.
- **Containers (runc/bwrap) only** — shared host kernel; rejected as the primary
  boundary for hostile code (ADR-0001).
