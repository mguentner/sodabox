# Architecture Decision Records

This directory records the significant architecture decisions for **sodabox**
(provisional codename — see below), a rootless, security-focused sandbox that
runs arbitrary Linux applications inside microVMs with a whitelist-only network.

> **Codename.** `sodabox` is a placeholder used throughout these ADRs for the
> project and its CLI binary. Replace once a final name is chosen.

## Product summary

- Runs arbitrary Linux apps inside **cloud-hypervisor** microVMs with
  **NixOS**-based guest images.
- **Rootless and host-non-invasive**: no root, no setuid, and **no
  modifications to the host** — in particular *no host firewall rules*.
- **Deny-by-default egress**: traffic leaves a VM only to explicitly
  whitelisted IPv4/IPv6 destinations, or to IPs resolved for whitelisted DNS
  names.
- **DNS is filtered and resolved on the host** using the host `resolv.conf`.
- **Persistent, dedicated disk** per VM; **multiple VMs** run concurrently.
- Driven by a **CLI**, including a **TUI** to monitor a VM live (blocked IPs,
  DNS decisions).

## Index

| ADR | Title | Status |
| --- | ----- | ------ |
| [0001](0001-trust-and-threat-model.md) | Trust and threat model | Accepted |
| [0002](0002-virtualization-stack.md) | Virtualization stack: cloud-hypervisor + NixOS guests | Accepted |
| [0003](0003-userspace-networking-passt.md) | User-space networking with stock passt | Accepted |
| [0004](0004-egress-enforcement.md) | Egress enforcement: per-VM netns + transparent proxy | Accepted |
| [0005](0005-dns-filtering.md) | DNS filtering and host-side resolution | Accepted |
| [0006](0006-allowlist-model.md) | Allowlist model and runtime updates | Accepted |
| [0007](0007-control-plane.md) | Control plane: per-VM supervisor, no daemon | Accepted |
| [0008](0008-persistent-storage.md) | Persistent per-VM storage | Accepted |
| [0009](0009-cli-and-tui.md) | CLI and TUI (Rust) | Accepted |
| [0010](0010-packaging-and-rootless.md) | Packaging, rootless operation, host requirements | Accepted |
| [0011](0011-ssh-and-sync.md) | Host↔guest access: SSH and file sync | Accepted |
| [0012](0012-guest-definition-user-owned.md) | User-owned guest system definition (npins, in the config dir) | Accepted |
| [0013](0013-git-sync.md) | Git-native host↔guest sync | Accepted |
| [0014](0014-persistence-modes.md) | Persistence modes: full, home, none | Accepted |
| [0015](0015-policy-profiles.md) | Policy profiles | Accepted |
| [0016](0016-ssh-over-vsock.md) | SSH over vsock | Proposed |
| [0017](0017-optional-virtiofs-share.md) | Optional virtiofs share | Proposed |
| [0018](0018-caches-on-data-disk.md) | Tool caches on the data disk | Accepted |
| [0019](0019-dotfile-collections.md) | Dotfile collections | Accepted |
| [0020](0020-inference-gateway.md) | Inference gateway | Proposed |

## Conventions

- Format: lightweight [MADR](https://adr.github.io/madr/)-style, see
  [`0000-template.md`](0000-template.md).
- One decision per file; filenames are `NNNN-kebab-title.md`, numbers are
  never reused.
- Statuses: `Proposed` → `Accepted` → (`Deprecated` | `Superseded by NNNN`).
- Superseding: create a new ADR; do not rewrite an accepted one — amend its
  status line to point at the successor.
