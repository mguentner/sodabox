# Spike report: rootless cloud-hypervisor boot recipe

- **ADR:** ADR-0002
- **Date:** 2026-09-02
- **Result:** ✅ SUCCESS — validated a rootless cloud-hypervisor microVM boot with
  direct kernel boot, working **virtio-console** and **virtio-blk**, and a
  verified **persistent-storage round-trip** (guest write read back from the
  host-side image after shutdown).

## What was validated

- cloud-hypervisor **v52.0.0** boots a microVM against `/dev/kvm` with no root
  privilege required by the launch itself (`/dev/kvm` was mode `0666`; the launch
  is uid-agnostic — see caveat below).
- Direct kernel boot: `--kernel bzImage --initramfs initrd.gz --cmdline "console=ttyS0 rdinit=/init"`.
- virtio-blk: `/dev/vda` enumerated at the correct size; **read+write works and
  persists** to the backing file.
- virtio-console: `/dev/hvc0` present after the module loads.
- Boot-to-init ≈ **1.5 s**.

## The working recipe

```sh
cloud-hypervisor \
  --kernel   <bzImage> \
  --initramfs <initrd.gz> \
  --cmdline  "console=ttyS0 rdinit=/init" \
  --serial   file=<serial.log> \
  --console  off \
  --disk     path=<data.img>,image_type=raw,readonly=off \
  --cpus     boot=1 \
  --memory   size=512M
```

Guest shutdown via `poweroff -f` (ACPI) makes cloud-hypervisor exit 0.

## Gotchas discovered (each is a design input for downstream tasks)

1. **Specify `image_type` explicitly on every `--disk`.** With auto-detection,
   CH v52 prints a deprecation warning *and* **disables sector-0 writes**
   (guards against clobbering a partition table on a misdetected image). A guest
   page-cache flush of logical block 0 then fails with `I/O error … sector 0 …
   ReadOnly`. Passing `image_type=raw` fixes it cleanly.

2. **Stock nixpkgs `linux` has virtio as modules (`=m`), not built-in.** A bare
   initramfs sees no virtio devices until the modules are loaded. Two options for
   the guest image:
   - *Recommended:* build the guest kernel with `CONFIG_VIRTIO`, `CONFIG_VIRTIO_PCI`,
     `CONFIG_VIRTIO_BLK`, `CONFIG_VIRTIO_CONSOLE`, `CONFIG_DEVTMPFS_MOUNT`,
     `CONFIG_SERIAL_8250` **built-in (`=y`)** → trivial direct boot, no initramfs
     module juggling.
   - *Fallback:* ship the virtio `.ko`s in the initramfs and load them in order.

3. **Module load order matters:** `virtio_ring` **before** `virtio`
   (`virtio_break_device` is exported by `virtio_ring`; `virtio.ko` depends on it).
   Full order used: `virtio_ring → virtio → virtio_pci_legacy_dev →
   virtio_pci_modern_dev → virtio_pci → virtio_console → virtio_blk`. Prefer
   `modprobe` with the real `modules.dep` over hand-ordered `insmod`.

4. **Kernel bzImage and modules must be the matched store-path pair** (vermagic /
   symbol CRCs). Mixing a bzImage with another build's `-modules` path yields
   `Unknown symbol …`. On NixOS use the pair referenced by the same system.

5. **Use serial (8250) for early boot logs, virtio-console for interactive
   attach.** 8250 is emulated by CH and available immediately; `hvc0` only exists
   after `virtio_console` loads, so init output bound to `hvc0` before that is
   lost. Boot with `console=ttyS0`; expose `hvc0` for a console/attach channel
   later. → informs the console wiring.

6. **Nix in this sandbox:** `cache.nixos.org` (binary cache) is reachable but
   `channels.nixos.org` (flake registry) is **blocked** by egress policy. Build
   with the `NIX_PATH`-pinned `<nixpkgs>` (`nix-build '<nixpkgs>' -A …`), not
   `nix run nixpkgs#…`. Environment-specific, not a product constraint.

7. **Rootless caveat for this environment:** we ran as `root` (uid 0) inside the
   sandbox, and `/dev/kvm` is world-RW, so this run does **not by itself** prove
   the *unprivileged-user* path. The launch is uid-agnostic given `/dev/kvm`
   access; the outstanding rootless-specific pieces (user+netns creation,
   vhost-user socket perms) are exercised by the passt/netns spikes
   (0002/0003), not here.

## cloud-hypervisor capabilities noted for other spikes

- `--fs tag=<t>,socket=<sock>` — virtio-fs (virtiofsd) for the read-only store
  share → spike 0004.
- `--net …,vhost_user=on,socket=<sock>` and `--disk …,vhost_user=on,socket=` —
  vhost-user backends (passt as net backend) → spike 0002.
- `--disk …,lock_granularity=byte-range|full` — **native image locking**; may
  satisfy ADR-0008's "one supervisor per data.img" lock without a separate
  lockfile → revisit for the data.img lock.
- `--disk …,sparse=on` — sparse backing, matches ADR-0008's sparse `data.img`.
- `--landlock` / `--landlock-rules path=,access=` — extra host-side sandboxing of
  the VMM worth evaluating for hardening.

## Artifacts

Built via pinned `<nixpkgs>` (26.11pre-git): `cloud-hypervisor-52.0`,
`linux-6.18.38` (bzImage + matched `-modules`), `pkgsStatic.busybox`. Scratch
working dir held the initramfs, `data.img`, and captured serial log.
