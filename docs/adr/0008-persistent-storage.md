# ADR-0008: Persistent per-VM storage (minimal disk overhead)

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** — (disk layout amended by [ADR-0014](0014-persistence-modes.md): the home and sshd host key moved to a separate home disk at `/persistent/home`, and per-VM persistence modes were added)

## Context

Each VM needs a **persistent, dedicated disk** for the app's mutable state that
survives restarts, plus config. Everything is **rootless**. A hard requirement
is **minimal per-VM disk overhead**: running several VMs must not cost a full OS
image each.

The dominant source of disk overhead in a NixOS microVM is the guest's
**OS/Nix-store closure**. Baking a full rootfs image per VM duplicates gigabytes
per instance. cogbox avoids this by sharing the host store and using a tmpfs
overlay; we adopt the same principle, adapted to cloud-hypervisor.

## Decision

**Do not copy the OS per VM.** Share the host **`/nix/store` read-only** into
the guest, so per-VM persistent storage is only a **small, sparse, dedicated
persistent disk** (virtio-blk, mounted at `/persistent`) for the guest's home,
work tree and app state. Writable store space is a small overlay whose upper
lives on that same disk (persisted across reboots), falling back to
tmpfs when no persistent disk is attached. Net per-VM disk overhead ≈
the app's actual written data plus any cached guest-side store writes.

## Details

### Layout

```
$XDG_DATA_HOME/sodabox/<vm>/
  ├─ data.img      # dedicated persistent disk (virtio-blk, sparse)
  ├─ policy.toml   # egress/domain allowlist (ADR-0006)
  └─ meta.toml     # vCPU, mem, system ref, created-at, ...
# NO per-VM rootfs copy: the guest system references the SHARED host store.
```

Inside the guest, that disk is mounted at **`/persistent`** and holds one folder
per kind of persisted state; the root filesystem itself stays tmpfs:

```
/persistent/            ← /dev/vdc (ext4, x-systemd.makefs, nofail)
  ├─ root/              → bind → /root      (the whole home)
  ├─ nix-store/         → upper+work for the /nix/store overlay
  ├─ work/              → bind → /var/work  (sync work tree; login lands here)
  └─ sodabox/           sodabox's own state (sshd host key); not mounted
```

### Guest root / store sharing

> **Hard security rule: the whole host `/nix/store` is NEVER shared into a guest.**
> A guest sees **only its own system closure**, read-only. Exposing the entire
> host store would leak every host package, secret path, and derivation into the
> sandbox — an unacceptable information-disclosure and attack-surface expansion
> that defeats the point of the sandbox. This rule is non-negotiable and bounds
> the mechanism choice below.

- **Mechanism (sole): a per-guest erofs closure image.** The guest's Nix system
  closure — and *only* that closure — is imaged read-only and attached via
  virtio-blk. The image is built from `closureInfo { rootPaths = [ toplevel ]; }`
  (see `nix/guest/erofs-store.nix`), so it contains exactly the store paths
  reachable from *that guest's* toplevel and nothing else. It is:
  - **fully rootless** — an ordinary `mkfs.erofs` by the user, no daemon, no
    shared memory, no privileged block setup;
  - **read-only by construction** — the guest cannot write it (a tmpfs overlay,
    below, provides writable store space);
  - **lz4-compressed** and, built **once per guest system and shared read-only
    across all its VMs**, incurs ≈0 per-VM duplication.
- The guest boots a minimal NixOS whose `init=` references paths inside this
  image (mounted at `/nix/.ro-store`, overlaid to `/nix/store`) — no full
  writable rootfs image.

> **virtiofsd rejected on the security rule.** Spike 0004
> ([docs/spikes/0004-store-share.md](../spikes/0004-store-share.md)) confirmed
> both an erofs closure image and rootless virtiofsd work. virtiofsd's value was
> sharing the **whole host store live** — which the hard rule above forbids —
> and it adds a per-VM daemon + `--memory shared=on` + a sandbox-mode choice for
> no benefit the closure image lacks. It is therefore **not** implemented. This
> reverses the earlier lean (virtiofs default) recorded in prior drafts; the
> erofs closure image is the **sole** store-share mechanism.

### Persistent disk

- **raw, sparse** by default (overhead = blocks actually written); qcow2 optional
  where snapshots/backing files are wanted. cloud-hypervisor supports both.
- Created at `sodabox create` with a user-specified size; the file is sparse so a
  large logical size costs little until used. Resizable later.
- Rootless: a plain file owned by the user; no loop devices, LVM, or privileged
  block setup.
- Attached RW as `/dev/vdc` and mounted in the guest at `/persistent` (base
  module), **formatted on first boot** via `x-systemd.makefs` (ext4) since the
  raw file starts empty. It carries the guest's home, the writable-store upper,
  the host↔guest sync work tree ([ADR-0011](0011-ssh-and-sync.md)) and the
  persisted SSH host key — see the folder layout above.
- **The whole home is persistent, not a list of dotfiles.** `/persistent/root` is
  bind-mounted onto `/root`, so *all* per-tool state under `$HOME` survives a
  reboot. An earlier increment bind-mounted individual dotfile paths
  (`~/.config`, `~/.local`, `~/.cache`, `~/.claude`, …) instead; that was replaced
  because it has to enumerate every tool — each new tool with a non-XDG dotfile
  needs another mount — while one bind on `/root` is both simpler and complete.
- **The work tree lives outside `$HOME`**, at `/var/work` (bind of
  `/persistent/work`), which is also where an interactive login lands
  (`environment.loginShellInit`). Keeping the synced project separate from the
  home means a sync can never scribble over tool state, and tool state never ends
  up pulled back to the host.
- **Layout is created in stage-1.** The bind sources are `mkdir`'d by an initrd
  service (`persistent-layout`) rather than `systemd.tmpfiles.rules`: tmpfiles
  runs *after* `local-fs.target`, so a tmpfiles-provisioned bind source does not
  exist yet when its mount is attempted and persistence would silently start one
  boot late. In stage-1 the disk is already mounted (`neededForBoot`).
- **Durable on stop.** The supervisor stops the guest with a clean
  ACPI power-off (`ch-remote power-button` on cloud-hypervisor's API socket, then
  wait), so the guest unmounts/flushes this disk — recent writes survive a
  restart without a manual `sync`. A hung guest falls back to a hard stop after a
  grace period. cloud-hypervisor runs in its own process group so a terminal
  SIGINT/SIGTERM reaches only the supervisor, not the VMM (else it would tear down
  concurrently and race the power-off). *Verified live on KVM.*

### Writable store overlay

- **Disk-backed upper on the persistent disk.** The `/nix/store`
  overlay's writable upper/work dirs live on the persistent disk under
  `/persistent/nix-store`, so guest-side installs and GC roots **cache across
  reboots** and do **not** consume guest RAM. This resolves the open question
  below (persist the writable store) in favour of persistence, at the cost of a
  little disk space shared with the home and the sync work tree.
- **Stage-1 ordering.** The overlay is `neededForBoot`, so the persistent disk is
  mounted (and first-boot `makefs`'d) in the initrd before the overlay assembles.
  That requires **systemd in stage-1** (`boot.initrd.systemd.enable`), the only
  initrd style that can `systemd-makefs` a blank disk and order the overlay after
  the disk mount.
- **tmpfs fallback when diskless.** The disk mount is `nofail`; a VM launched
  without a persistent disk skips it, leaving `/persistent` a directory on the
  tmpfs root, so the overlay's upper — and the `/root` and `/var/work` binds —
  transparently fall back to RAM (volatile, as before). The "boots without a
  persistent disk" guarantee is preserved.
- Persistence of installed *system* packages is still via the declarative system
  (ADR-0010); the overlay only caches ad-hoc guest-side store writes.

### Lifecycle

- `sodabox rm <vm>` removes runtime + data (confirm); `--keep-disk` retains data.
- A running VM holds a lockfile on its `data.img` so two supervisors can't attach
  the same image.
- At-rest encryption of `data.img` deferred to a future ADR.

## Consequences

- **Positive:** Per-VM disk overhead is just the app's real data; many VMs are
  cheap; app state is a single backup-able artifact; the OS is rebuildable and
  not duplicated.
- **Negative / costs:** Store-sharing adds a moving part (virtiofsd or a closure
  image build); tmpfs writable store uses RAM and loses installs on reboot.
- **Risks & open questions:**
  - ~~Rootless virtiofsd feasibility/perf~~ — **resolved** (spike 0004): both
    work rootless, but virtiofsd's whole-store live share is forbidden by the
    hard security rule above, so the erofs closure image is the sole mechanism.
  - Default `data.img` size and thin-provisioning behavior.
  - ~~Whether any app genuinely needs a persistent writable store (would push the
    overlay from tmpfs to a small disk overlay).~~ — **resolved:**
    the writable store upper now lives on the persistent disk (see "Writable
    store overlay"), persisting guest-side installs across reboots and freeing
    guest RAM, with a tmpfs fallback when no persistent disk is attached.

## Alternatives considered

- **Full per-VM rootfs image** — simplest, but multi-GB overhead per VM;
  rejected against the minimal-overhead requirement.
- **cogbox-style 9p store share** — same principle, but 9p is QEMU-oriented and
  slower, and (like virtiofs) shares a live host directory rather than a bounded
  closure image; rejected in favour of the per-guest erofs closure image.
- **virtio-fs (virtiofsd) live store share** — cloud-hypervisor's native path,
  but its purpose is sharing the whole host store live, which the hard security
  rule forbids; rejected (see the store-sharing section).
- **Shared data disk across VMs** — breaks per-VM isolation; rejected.
