# ADR-0017: Optional virtiofs share

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Project team
- **Supersedes / Superseded by:** — (would amend [ADR-0011](0011-ssh-and-sync.md))

## Context

The work tree moves between host and guest only through explicit transports:
rsync ([ADR-0011](0011-ssh-and-sync.md)) and git
([ADR-0013](0013-git-sync.md)). Both are deliberately asymmetric and
delete-free. ADR-0011 rejected a live shared directory because a hostile guest
could then overwrite host files whenever it wants.

That suits agent-driven work. It gets in the way of interactive work, where
someone edits on the host (in their own editor or IDE) while the guest builds
and runs, and every edit means another sync.

Spike [0004](../spikes/0004-store-share.md) showed that rootless virtiofsd works
(`--sandbox=namespace`). It also found that virtiofs needs cloud-hypervisor's
`--memory …,shared=on` and the guest's `fuse` and `virtiofs` modules. virtiofs
was rejected for the **store** ([ADR-0008](0008-persistent-storage.md)), and
that rule stays: the host's whole `/nix/store` is never shared.

## Decision

Add an **opt-in, per-VM virtiofs share** of a single host directory, for
interactive work. It's off by default, read-only unless read-write is asked for
explicitly, and never allowed on directories that would expose the host broadly.
rsync and git stay the default transports.

## Details

- **Configuration:** `sodabox create <vm> --share <hostdir>[:ro|:rw]`, stored in
  `meta.toml`. With no `--share`, nothing changes: no virtiofsd, no shared
  memory.
- **Host:** the supervisor runs one rootless virtiofsd per VM
  (`--sandbox=namespace`, `--shared-dir <hostdir>`, plus a read-only option for
  `:ro`), with its socket in the runtime dir. It's pinned through
  `SODABOX_VIRTIOFSD` in the flake wrapper, like the other host tools
  ([ADR-0010](0010-packaging-and-rootless.md)). cloud-hypervisor gets
  `--fs tag=share,socket=…` and `--memory …,shared=on`, but only for VMs with a
  share.
- **Guest:** the `fuse` and `virtiofs` modules go in `nix/guest/base.nix`, and the
  share mounts at a fixed path (such as `/var/work/share`). A mount unit skips it
  when the tag is missing, like the optional data disk.
- **Guardrails:**
  - `create` refuses `/`, `$HOME`, `/nix/store`, and any path that contains
    sodabox's config or data dirs or the SSH key, or sits inside them. Paths are
    canonicalised before they're checked.
  - The default is read-only, so the guest can't write to the host without an
    explicit `:rw`.
  - `sodabox ls` and `status` show when a share is active, and whether it's
    read-write.

## Consequences

- **Positive:** live editing without sync round trips. It's opt-in and doesn't
  change anything for VMs that don't use it.
- **Negative / costs:** one more daemon per VM, shared guest memory, more guest
  kernel modules, and another host tool to pin.
- **Risks & open questions:**
  - A read-write share lets the guest modify host files directly, which is
    exactly what ADR-0011's alternative rejected. The
    [ADR-0001](0001-trust-and-threat-model.md) threat model needs a note: a VM
    with a read-write share is trusted with that directory.
  - Should the default be read-only (safer) or read-write (what interactive
    editing usually wants)?
  - One share per VM, or several?
  - Can a share be added to an existing VM (like `profile add`), taking effect on
    the next start?
  - How does it interact with persistence modes
    ([ADR-0014](0014-persistence-modes.md))? The share is host-owned and outside
    the guest's persistence entirely.
  - virtiofsd's own attack surface: a guest-reachable FUSE server on the host,
    sandboxed but still running as the user.

## Alternatives considered

- **9p (virtio-9p)** — cloud-hypervisor doesn't support it, and it's slower.
- **sshfs/sftp over the SSH transport** — no extra daemon or shared memory, but
  the mount direction is reversed (the guest mounts the host), so the guest would
  need credentials for the host. Rejected.
- **Status quo (rsync/git only)** — still the default. This ADR only adds an
  option.
