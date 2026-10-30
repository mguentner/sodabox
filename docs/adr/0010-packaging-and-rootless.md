# ADR-0010: Packaging, rootless operation, and host requirements

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

The system must run **rootless** and **without modifying the host**. It is
NixOS-based on the *guest* side, but the **host is any modern Linux** (not
required to be NixOS). We need a reproducible way to build and ship the CLI plus
the guest images and pinned versions of cloud-hypervisor and passt.

## Decision

Ship `sodabox` as a **Nix flake** that provides: the Rust CLI/supervisor package,
pinned **cloud-hypervisor** and **passt** binaries, and **NixOS guest image**
builds. The flake runs on **any Linux host with Nix installed**; the host does
**not** need to be NixOS. All operation is rootless.

## Details

### Host requirements

- Linux kernel with **KVM** and access to `/dev/kvm` for the invoking user
  (typically group `kvm`).
- **Unprivileged user namespaces enabled**
  (`kernel.unprivileged_userns_clone=1` / modern default). Required for the
  netns + transparent-proxy mechanism ([ADR-0004](0004-egress-enforcement.md)).
- **Nix** installed (multi- or single-user). Nothing else installed on the host;
  no system services, no host firewall changes, no setuid binaries.

### What the flake provides

- `packages.sodabox` — the Rust CLI/supervisor/proxy/DNS binary/binaries
  ([ADR-0009](0009-cli-and-tui.md)).
- Pinned `cloud-hypervisor` and `passt` (reproducible, security-tracked
  versions).
- ~~`packages.guestImage.*` — NixOS guest images~~ — **superseded by
  [ADR-0012](0012-guest-definition-user-owned.md):** the guest is **not** built
  inside sodabox's flake. Its definition is materialized as **user-owned,
  npins-pinned sources in the config dir** so users can audit it and update
  `nixpkgs` themselves. sodabox's flake builds only the CLI and the pinned
  host-side tools.
- `apps.sodabox` for `nix run`; optional `nix profile install`.
- Optional `homeManagerModules` / `systemd --user` unit template for convenience
  (never a system-level unit).

### Rootless posture (summary; enforced across ADRs)

- No root, no setuid, no sudo at any step, including setup.
- Privilege only inside user+network namespaces we create; never on the host.
- No host firewall rules; all packet rules confined to per-VM netns (ADR-0004).
- State lives under `$XDG_DATA_HOME` / `$XDG_RUNTIME_DIR` (ADR-0007/0008).

### Non-NixOS hosts

- Because everything is delivered through Nix and runs in user space, a Debian/
  Fedora/Arch/etc. host with Nix works identically. The only host-level
  prerequisites are KVM access and unprivileged userns — both configurable
  without `sodabox` touching the host.

## Consequences

- **Positive:** Reproducible builds; pinned, auditable dependency versions;
  portable across Linux distros; trivial to run (`nix run`); guest images are
  declarative and minimal.
- **Negative / costs:** Requires Nix on the host (a real dependency); users must
  ensure `/dev/kvm` access and unprivileged userns are enabled (documented
  preflight check in the CLI).
- **Risks & open questions:**
  - Some hardened distros disable unprivileged userns by default — provide a
    clear preflight diagnostic and docs (cannot silently work around it without
    host changes, which we refuse to make).
  - Decide packaging of guest images: baked rootfs vs. read-only host Nix store
    shared into the guest (size vs. rebuild trade-off; ties to ADR-0008).

## Alternatives considered

- **Distro packages (.deb/.rpm) / static binary only** — loses reproducible
  guest-image builds and pinned VMM/passt; more drift. Rejected as primary.
- **Require a NixOS host** — unnecessary; the userspace + Nix approach is
  host-agnostic and broader.
- **Container image distribution** — awkward for a tool that itself manages
  namespaces and `/dev/kvm`; rejected.
