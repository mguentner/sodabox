# ADR-0014: Persistence modes — full, home, none

- **Status:** Accepted
- **Date:** 2026-10-21
- **Deciders:** Project team
- **Supersedes / Superseded by:** Amends [ADR-0008](0008-persistent-storage.md)
  (disk layout); guest layout amended by [ADR-0018](0018-caches-on-data-disk.md)
  (tool caches moved to the data disk)

## Context

Under ADR-0008 every VM is fully stateful: one sparse `data.img` holds the
home, the writable-store upper and the work tree, and it keeps everything the
guest ever wrote, even while the VM is stopped. That protects against sudden
terminations, but a stopped VM still takes up its whole written footprint. A
host with many VMs therefore needs room for all of their disks at once, even
when only a few ever run at the same time.

Most of that footprint isn't worth keeping. Store caches and build output can be
rebuilt, and the project in `/var/work` comes back over sync (ADR-0011/0013).
What is worth keeping is the tool configuration under `/root` (Claude config,
shell history, credentials), which is tiny. Some uses want nothing kept at all.

Constraints: the guest must keep running **on disk, not on a RAM disk**, so a
big build doesn't eat guest memory. Everything stays rootless, so the host can
only create and delete image files; it can't mount or edit filesystems inside
them.

## Decision

Every VM gets **two read-write disks with a fixed guest layout**: the data disk
and a small home disk. A per-VM `persist` mode (`full` | `home` | `none`, set
at `sodabox create --persist`) decides which of them are **kept** and which are
**scratch**. A scratch disk is a fresh sparse file made at every start and
deleted at stop.

| `persist` | `data.img` → `/persistent` (vdc) | `home.img` → `/persistent/home` (vdd) |
|---|---|---|
| `full` (default) | kept | kept |
| `home` | scratch | kept |
| `none` | scratch | scratch |

## Details

### Guest layout (static; the guest never knows the mode)

```
/persistent/            ← /dev/vdc  data.img  (ext4, x-systemd.makefs, nofail)
  ├─ nix-store/         upper+work for the /nix/store overlay
  └─ work/              → bind → /var/work
/persistent/home/       ← /dev/vdd  home.img  (ext4, x-systemd.makefs, nofail)
  ├─ root/              → bind → /root
  └─ sodabox/           sshd host key; not mounted
```

Both disks are `neededForBoot`, so stage-1 can create the folder layout on them
(`persistent-layout`). A blank disk, whether a new VM's or a fresh scratch disk,
gets formatted by `x-systemd.makefs`. Because every VM has both disks, device
names are fixed, and nothing has to be gated on the kernel cmdline or by
device-wait logic.

### Host lifecycle (`VmMeta::prepare_disks` / `discard_scratch`)

- `create` provisions only the **kept** disks. A `none` VM has no disk at all
  until it starts.
- On start, under the existing `data.img.lock` flock, kept disks are used as-is
  (created blank if missing) and scratch disks are **replaced** with blank ones.
  Replacing at start, not only deleting at stop, also reclaims scratch left
  behind by a crashed supervisor. A `full` VM whose `data.img` is gone boots
  diskless, as before, instead of silently starting over.
- The disks are prepared *after* the guest build, so a failed `nix-build`
  creates none.
- After the VM exits (clean stop, guest crash or failed launch), scratch disks
  are deleted while the lock is still held.
- The flock is now held whenever the VM exists, not only while `data.img`
  exists, because a scratch `data.img` doesn't exist between runs.
- `rm --keep-disk` keeps exactly the kept disks.
- `ls` shows a `PERSIST` column.

### SSH host key for `none`

A `none` guest can't keep its own sshd host key, so it would present a new one
every boot, and the TOFU pin (ADR-0011) would refuse it. Re-trusting a
new key every boot would quietly drop host-key verification. Instead, **the host
owns this identity**:

- `ssh::pinned_guest_host_key` generates an ed25519 key once into
  `<data-dir>/<vm>/ssh_host_ed25519_key` and writes its public half into the
  VM's `known_hosts`. The first connection is therefore already verified, not
  trust-on-first-use.
- The private key ships on the per-launch read-only config disk
  (`ssh/ssh_host_ed25519_key`, 0600). The config image itself is now 0600.
- The guest unit `sodabox-host-key` installs the key at the sshd path before
  `sshd-keygen` runs, so generation is skipped.

`full` and `home` keep generating and persisting their key on the home disk, as
before.

### Space accounting

A stopped VM costs only its kept disks: nothing for `none`, roughly the size of
`/root` for `home`. `--disk` is a logical size, and for scratch disks nothing is
reserved, so the configured sizes of all VMs may exceed free space. The real
limit is what the *running* VMs write; nothing checks for host-disk exhaustion
at start.

## Consequences

- **Positive:**
  - Many more VMs fit on a host, as long as only some of them run at once.
  - `home` keeps exactly the config people care about.
  - `none` gives a clean VM on every start while keeping a verified SSH
    identity.
  - The guest layout is mode-agnostic: one code path, no runtime branching.
- **Negative / costs:**
  - Every `full` VM now has two files (`data.img` + a 1G sparse `home.img`).
  - In `home`/`none`, guest-side work in `/var/work` that wasn't synced back is
    lost at stop, and a hard host crash loses it too (it would anyway).
  - The guest store-overlay cache is rebuilt after every restart.
  - **Not compatible with VMs created before this ADR.** Their home lives at
    `data.img:/root`, while the guest now binds `/root` from the home disk. Such
    VMs must be recreated; there is no migration.
- **Risks & open questions:**
  - Changing the mode of an existing VM isn't supported (recreate it).
  - Scratch disks left by a supervisor crash are only reclaimed at that VM's
    next start or by `sodabox rm`.

*Verified live on KVM (2026-10-21):*
- `home` keeps `/root` across a restart, drops `/var/work` and store-overlay
  writes, deletes `data.img` at stop, and keeps the host-key pin stable.
- `none` deletes both disks at stop, starts with an empty `/root`, and ssh
  verifies against the host-held, pre-pinned key.
- `full` keeps `/root` and `/var/work`.

This is covered automatically by the NixOS integration test
`nix/tests/persist-modes.nix` (`nix build .#checks.x86_64-linux.persist-modes`;
needs nested KVM). It runs real sodabox VMs of every mode inside the test VM,
with the guest prebuilt through the `SODABOX_NIX_BUILD` seam because the test VM
is offline.

## Alternatives considered

- **Mode-gated optional home disk** (vdd only in `home`, signalled via a
  `sodabox.keep` cmdline flag, with stage-1 waiting for the device and running
  mkfs and bind mounts). Rejected: it needs a custom initrd script and extra
  initrd tools to avoid stalling on an absent device. The static two-disk layout
  needs none of that.
- **systemd-repart: one disk with `home` and `scratch` partitions.** Rejected:
  repart can create partitions but can't free host space. Dropping the scratch
  partition would mean the host parsing the GPT and hole-punching its byte
  range, and the partition sizes would be fixed. Two files are simpler.
- **Wiping scratch directories from inside the guest at boot.** Rejected: the
  host file stays allocated (at best discard punches holes later), so stopped
  VMs would still take up space, which is the problem being solved.
- **tmpfs for the dropped state.** Rejected by requirement: the guest must run
  on disk.
- **Re-trust the host key every boot for `none`** (clear `known_hosts` each
  start). Rejected: it silently downgrades host-key verification to blind
  trust.
