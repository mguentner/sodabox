# Spike report: read-only /nix/store share — virtiofs vs erofs image

- **ADR:** ADR-0008
- **Date:** 2026-09-03
- **Result:** ✅ SUCCESS. **Both work rootless.** Original recommendation: erofs
  image as the default, virtiofsd as the option for live/whole-store sharing.

> **Post-spike security decision (supersedes the recommendation below).** The
> whole host `/nix/store` must **never** be shared into a guest — that would leak
> every host package, secret, and derivation into the sandbox. virtiofsd's only
> advantage here was the live *whole-store* share, which is now forbidden, so the
> **per-guest erofs closure image is the SOLE mechanism** and virtiofsd is **not**
> implemented. The rest of this report is retained as the
> as-tested record; treat every "virtiofsd as the option" phrasing as rejected.
> See ADR-0008 (§ Guest root / store sharing) for the authoritative rule.

## What was tested (rootless: `unshare -Un --map-root-user`, CH v52, guest 6.18.38)

A guest mounted the shared store read-only and **executed a binary from it**, for
each mechanism.

### A — erofs image over virtio-blk

- `mkfs.erofs img <store-path>` as an ordinary user → attach `--disk
  path=img,image_type=raw,readonly=on` → guest `insmod erofs.ko` (no deps) +
  `mount -t erofs -o ro /dev/vdX /mnt`.
- **Mount OK, exec-from-image OK.** Read-only by construction.
- **lz4 compression works with just `erofs.ko`** (no extra decompressor module):
  the 1.4 MB store path imaged to 1.47 MB uncompressed / **1.15 MB with `-zlz4`**,
  both mounted and executed.
- Read throughput ≈ **142 MB/s** (rough, see caveat).
- **Fully rootless, no daemon, no shared memory needed.**

### B — virtiofsd (virtio-fs)

- Build `virtiofsd`; run `virtiofsd --socket-path=S --shared-dir=D
  --sandbox=<none|namespace>` → CH `--fs tag=stor,socket=S` **plus `--memory
  shared=on`** (required) → guest `insmod fuse.ko virtiofs.ko` + `mount -t
  virtiofs stor /mnt`.
- **Mount OK, exec-from-share OK, writes denied (RO).**
- **Rootless works both ways:** `--sandbox=none` and `--sandbox=namespace` (the
  latter nests virtiofsd's own userns inside ours for extra isolation; benign
  `Failed to generate a file handle … disabling file handles` warning — normal
  rootless fallback to O_PATH fds).
- Read throughput ≈ **116 MB/s** (rough).
- Shares the **actual host store live** — zero duplication, no rebuild — at the
  cost of a per-VM daemon + shared memory.

> **Perf caveat:** single 64 MB cold read inside nested virt — indicative only,
> not a benchmark. Both are in the same ballpark; virtiofs has tuning knobs (DAX,
> multiqueue, cache modes) and scales better for large shared trees, erofs
> benefits from being a plain compressed block image. Not decision-deciding.

## Decision & rationale

**Default: erofs image.** For sodabox's model — guests are **declaratively-built,
fixed NixOS closures** (ADR-0002/0010) — erofs is the better fit:

- Trivially **rootless**, **no daemon**, **no shared memory**, **RO by
  construction** — the fewest moving parts and the smallest attack surface.
- Build the closure image **once per guest system** and attach it **read-only to
  every VM** of that system → per-VM disk overhead ≈ 0, satisfying ADR-0008's
  minimal-overhead requirement. (The image duplicates the *guest closure*, not
  the whole host store, and that one copy is shared across VMs — so it is *not* a
  per-VM cost.)
- lz4 keeps it compact.

**Option: virtiofsd.** Preferred when the guest must see the **whole host store
live** or arbitrary/varying host paths (e.g. ad-hoc `nix` use referencing host
store), where re-imaging is impractical. Rootless is fine (`--sandbox=namespace`);
budget a per-VM daemon + `--memory shared=on`.

> **Reverses ADR-0008's lean.** ADR-0008 proposed *virtio-fs as default, erofs as
> the rootless fallback*, on the assumption rootless virtiofsd was the riskier
> unknown. The spike shows rootless virtiofsd is feasible **but** carries more
> moving parts (daemon, shared mem, sandbox mode) than the ADR assumed, while
> erofs is trivially rootless and — via per-system image sharing — does not incur
> the per-VM duplication the ADR worried about. Net: swap the default. ADR-0008
> should get a pointer to this spike (like ADR-0004 ← spike 0003).

## Requirements / findings for implementation

1. Guest kernel needs `erofs` (standalone) **and** `fuse`+`virtiofs` modules (or
   built-in) — ties to the guest-image task; prefer building the
   chosen mechanism's fs support **built-in** to avoid initramfs juggling.
2. virtiofs requires CH **`--memory …,shared=on`** (same as vhost-user net,
   spike 0002).
3. erofs: use `-zlz4` for compression; images attach `readonly=on,image_type=raw`.
4. RO enforcement: erofs is inherently RO; for virtiofsd rely on the store being
   read-only (writes returned `EROFS`), and/or a read-only share option.

## Design inputs for downstream tasks

- **store share:** implement the **erofs closure image** as the
  **sole** mechanism (mkfs.erofs of the guest closure via
  `closureInfo{rootPaths=[toplevel]}`, attached RO virtio-blk, one image shared
  across a system's VMs). **virtiofsd is NOT implemented** — its whole-store live
  share violates the never-share-the-whole-store rule (post-spike decision above).
- **guest image:** build erofs (and/or virtiofs+fuse) fs support
  built-in.

## Artifacts

Pinned `<nixpkgs>`: `virtiofsd-1.13.3`, `erofs-utils` (`mkfs.erofs`),
`cloud-hypervisor-52.0`, `linux-6.18.38` (+ `erofs`/`fuse`/`virtiofs` modules).
Images, initramfs, run scripts in the scratch dir.
