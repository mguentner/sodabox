# ADR-0012: User-owned guest system definition (npins-pinned, in the config dir)

- **Status:** Accepted
- **Date:** 2026-09-03
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

The guest is a NixOS system (ADR-0002), built by Nix and shared into the VM as a
read-only store (ADR-0008). The implicit model so far had **sodabox's own flake**
build the guest images (`packages.guestImage.*`, ADR-0010). That couples the guest
build to sodabox's flake, which is wrong for this project for two reasons:

1. **Access.** A user who installs sodabox as a package/binary may not have its
   flake at all, yet still needs to build and modify their guest.
2. **Control & trust.** sodabox is a security tool; its value rests on the user
   being able to **audit and control exactly what runs inside the VM** and to
   **update `nixpkgs` themselves** (security fixes) without waiting on a sodabox
   release or understanding sodabox internals.

The guest's build definition should therefore be **owned by the user**, not buried
in sodabox's flake.

## Decision

Split the guest build into **inputs the user owns** and **logic sodabox owns**:

- **User inputs** (materialized in the config dir): the guest **`configuration.nix`**
  (*what* the guest contains) and an **[npins](https://github.com/andir/npins)**
  pin set for **`nixpkgs`** — and optionally overlays and other sources (the
  *which*). The user edits these and runs `npins update` to move `nixpkgs`
  themselves. That is the whole of what the user owns.
- **sodabox owns the *how*** — in the parent flake + Rust: a **guest build
  function** taking `{ nixpkgs, configuration, overlays?, sources? }` and
  producing a bootable guest (**kernel + read-only store image**), the **erofs**
  build, and the **cloud-hypervisor launch**. The config dir contains **no build
  logic**; *how* the guest is assembled and run is not user-editable boilerplate.

sodabox ships a **default `configuration.nix` + npins pin** so `create` works out
of the box; both are editable and user-owned. npins keeps this **flake-free** (no
experimental features, and no requirement that the user has sodabox's flake).

## Details

### Layout — user inputs only (materialized into the config dir)

```
$XDG_CONFIG_HOME/sodabox/guest/          # editable default; per-VM override may shadow it
  npins/
    sources.json     # pinned nixpkgs (+ optional overlays / other sources)
    default.nix      # `import ./npins` -> { nixpkgs = <path>; ... } (npins-generated)
  configuration.nix  # the guest NixOS config the user edits (packages, services)
# NO build logic here — sodabox owns *how* the guest is built (see below).
```

- A per-VM override may shadow the shared default (mirroring the
  `authorized_keys`/`policy.toml` per-instance pattern), so most users share one
  editable guest input while a VM can diverge.
- *Amended 2026-10-16.* `create` materializes that override for every new VM as
  a thin layer instead of leaving it opt-in. Its `configuration.nix` imports the
  shared one (`imports = [ ../../guest/configuration.nix ]`) and sets
  `networking.hostName`. Its `npins` is a symlink to the shared pins. That gives
  two editable layers for free, "all VMs" (shared) and "this VM" (per-VM), and
  `npins update` in the shared dir still moves every VM. The hostname comes from
  `create --hostname`: `name` (default) is the VM name sanitized to one
  RFC 1123 label, `static` is base.nix's `sodabox-guest`, and `random` is
  `s` + 8 random `[a-z0-9]`. It is written literally into the file, so it is
  plain config from then on. A VM created before this has no layer and keeps
  using the shared input and `sodabox-guest`.

```
$XDG_CONFIG_HOME/sodabox/<vm>/guest/      # written by create, never rewritten
  npins -> ../../guest/npins              # replace with a real dir to pin this VM alone
  configuration.nix                        # imports ../../guest/configuration.nix; sets networking.hostName
```
- **Why npins:** flake-free (no experimental features, no dependency on sodabox's
  flake) and user-updatable — `npins update` / `npins add github NixOS nixpkgs
  --branch …` moves `nixpkgs`; pins are reviewable JSON. A flake variant may also
  be offered, but npins is the minimal self-contained form.

### The build function (sodabox owns the *how*)

sodabox ships its guest-build expression (e.g. `mkGuest.nix`) as part of its
**package/flake — not in the user's dir**. Given a guest input dir it:

1. imports the user's `npins` for `nixpkgs` (and any overlays / extra sources);
2. evaluates a NixOS system from **sodabox's base module ∪ the user's
   `configuration.nix`**. The base module encodes the non-negotiable *how* —
   virtio/8250/devtmpfs **built-in** kernel (spike 0001), init/boot, the
   read-only store-share mount (ADR-0008), SSH bring-up (ADR-0011);
3. builds the **erofs image of the closure** via a sodabox-owned derivation
   (reproducible, cached — spike 0004, docs/spikes/0004-store-share.md);
4. yields `{ kernel, store }` (bzImage + erofs image).

The **Rust CLI/supervisor invokes this** — an impure `nix-build` of sodabox's
shipped expression with the user's guest dir as the argument — then launches
cloud-hypervisor with the resulting `kernel` + `store` (read-only) + the per-VM
`data.img`, inside the userns+netns with passt/proxy/DNS (spikes 0001 / 0002 /
0003). *All of config-file handling, the guest build invocation, the erofs, and
the launch live in sodabox's flake + Rust.*

### VM creation flow

- `soda create <vm>` — write the per-VM data dir (`data.img`, `policy.toml`,
  `meta.toml`, ADR-0008) and, if absent, materialize the **default guest input**
  (`configuration.nix` + `npins`) into the config dir. Never overwrites user edits.
- `soda start <vm>` — resolve the guest input dir (per-VM override else shared
  default) → run sodabox's build function → get `{ kernel, store }` → supervisor
  brings up the netns/chv/passt/proxy/DNS and boots the VM.

### Relationship to sodabox's own flake (ADR-0010)

- sodabox's flake still builds the **CLI/supervisor** and pins **cloud-hypervisor
  / passt / erofs-utils** (the host-side tools). It **no longer builds guest
  images**. The guest is pinned independently by the user via npins, decoupling
  guest and sodabox versions.

## Consequences

- **Positive:** the user can audit and change exactly what runs in the VM (fits
  ADR-0001's trust model); users update `nixpkgs`/packages themselves; no flake
  dependency for guest builds; guest and sodabox versions are decoupled; still
  reproducible via npins pins.
- **Negative / costs:** another moving part (`npins`) and a guest `nix-build` on
  the user's machine; sodabox must define and honor the guest build contract; must
  handle guest rebuilds and caching.
**Resolved (2026-09-03):**
- **Invocation:** the Rust side runs an **impure `nix-build` of sodabox's shipped
  `mkGuest.nix`** with the guest dir as an argument. Nix content-addresses the
  output, so repeat `start`s with unchanged inputs are instant — caching is free.
- **Builder:** **bespoke `eval-config`** with sodabox's own base module (not
  `microvm.nix`), matching the validated minimal direct-kernel path (spike 0001)
  and the minimal-closure goal (ADR-0008). Revisit `microvm.nix` later if wanted.
- **Location:** a **shared editable default** at `…/sodabox/guest/`, with an
  optional **per-VM override** at `…/sodabox/<vm>/guest/`.

**Still open:**
- Exact **argument interface** of `mkGuest` and the **base-module option surface**
  the user's `configuration.nix` may set.
- Whether to also ship a **flake variant** of the build function (deferred).

## Alternatives considered

- **Put the guest *configuration* and its `nixpkgs` pin inside sodabox's flake
  (`packages.guestImage.*`)** — the original implicit model; rejected: opaque to
  the user, not updatable without sodabox's flake, couples guest to sodabox
  versions. Note the build *logic* still lives in sodabox (this ADR) — only the
  *inputs* move out to the user.
- **A flake in the config dir** instead of npins — viable and may be offered, but
  requires flakes enabled and is heavier than npins for "just update nixpkgs";
  npins is the minimal form the requirement asks for.
- **Prebuilt guest images shipped by sodabox** — least transparent and not
  user-modifiable; rejected.
