# ADR-0011: Host↔guest access — SSH and file sync

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

Two host↔guest needs beyond the network egress model: (a) get an interactive or
one-off **shell** into a running VM, and (b) move a **working tree** between the
host's current directory and the VM. cogbox solves both over **SSH**: a `ssh`
verb, and `sync-vm`/`sync-host` implemented as **`rsync -e ssh`** reusing the
exact same hardened SSH identity. We adopt this proven design, adapted to
cloud-hypervisor, a Rust CLI, our dedicated data disk ([ADR-0008](0008-persistent-storage.md)),
and the rootless posture.

Sync is bundled into this ADR because it is defined entirely in terms of the SSH
transport (same endpoint, same identity flags — a single source of those flags).

## Decision

**SSH is the single host↔guest access transport.** The tool owns an ed25519
keypair whose public half is injected into every guest's `authorized_keys` at
launch; the CLI drives the system `ssh`/`rsync` with a hardened, pinned identity
posture over a **host-loopback port forward** (via passt). **File sync is
`rsync` over that same SSH transport**, deliberately asymmetric and
delete-free.

## Details

### SSH access

- **Tool-owned key.** An ed25519 keypair at `$XDG_DATA_HOME/sodabox/sodabox_ed25519`
  (private key host-only, never mounted into a VM), reused across instances. Its
  public key is the **only** entry in each guest's `authorized_keys`, so
  `soda ssh` works out of the box and no other identity can log in.
- **No user keys.** The user's own keys (`~/.ssh/*.pub`, agent identities) are
  never injected, and there is no per-instance override: access to a guest goes
  through `soda ssh`, i.e. the tool key.
- **Delivery — read-only config disk.** The `authorized_keys` file is
  written into a small **read-only erofs image built at launch** (the *config
  disk*) and attached as the guest's **second** virtio-blk disk (`/dev/vdb`,
  always second so its device name is deterministic), which the guest mounts
  read-only at `/run/sodabox` (so sshd reads `/run/sodabox/ssh/authorized_keys`).
  Rebuilt every launch, so key changes apply
  immediately **without** rebuilding the immutable store image, and the guest
  cannot tamper with the keys (RO by construction). This same disk carries other
  host→guest launch data as the feature grows. (Chosen over baking keys into the
  store closure — which would rebuild on every key change and can't hold the
  per-instance host key — and over the data disk, which is optional and
  user-owned.)
- **Endpoint (host-loopback ↔ netns relay).** passt runs *inside* the per-VM
  netns (so its outbound sockets are egress-filtered), which has no veth to the
  host — so passt's inbound forward (`-t 127.0.0.1/<port>:22`) listens on the
  *netns* loopback, unreachable from the host directly. The supervisor bridges
  the two loopbacks without adding any host↔netns IP path: the host-netns parent
  binds `127.0.0.1:<port>` (see **Port assignment** below), and hands each
  accepted connection's fd to the netns
  child over the existing fork `SCM_RIGHTS` channel; the child splices it into
  passt's in-netns forward → guest:22 (an established TCP fd is netns-agnostic
  for I/O). Single guest NIC, no egress-bypassing second interface, no privilege.
  The live `host:port` is written to the instance runtime dir
  (`ssh.endpoint`) for the CLI to read, and removed on teardown.
- **Port assignment — state, not a per-boot choice.** Each VM's host-loopback
  port is **allocated once at `soda create` and stored in its `meta.toml`**
  (`ssh_port`), from the range **`3522..3585`** (above the crowded 2000–3000
  band the old `2222` base sat in). The allocator is the lowest port in that
  range no *other* VM's `meta.toml` claims — DHCP-like, minus the lease: there
  is nothing to expire, so a VM keeps its port across restarts, across
  `stop`/`start`, and across a delete-and-recreate of the same name (it may get
  a different one then, since the port was genuinely released). Two VMs can
  therefore never be assigned the same port, which is the point: the earlier
  design bound a *base port that slid up on collision*, so an `ssh.endpoint`
  file left behind by a crashed supervisor could name a port a **different** VM
  had since taken, and a `sync-vm`/`git push` could land in the wrong guest
  (caught by the host-key pin only once that VM had been connected to before).
  With the assignment in state, the only way the port is unavailable at boot is
  a non-sodabox process holding it; the supervisor then takes the lowest port no
  other VM owns, **persists** the reassignment, and prints it. `bind()` remains
  the sole arbiter, so concurrent starts cannot agree on one port. A full range
  (64 VMs) is a clear error at `create`, not a silent overlap.
- **Hardened identity posture** (single source of these flags, shared verbatim
  with sync):
  ```
  -F /dev/null -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=<per-VM>
  -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias=sodabox-<vm>
  -o LogLevel=ERROR -o IdentitiesOnly=yes -o IdentityAgent=none -i <tool key>
  ```
  `-F /dev/null` skips the user's ssh config; `IdentitiesOnly=yes` +
  `IdentityAgent=none` pin auth to *only* the tool key and never contact an agent
  (a gpg-agent with ssh support can't stall/prompt; personal keys aren't
  offered) — one deterministic auth attempt.
- **Host-key verification (improvement over cogbox), implemented.** cogbox
  disables host-key checking because its guest root is ephemeral and host keys
  regenerate each boot. We have a **persistent data disk**, so the guest persists
  its ed25519 host key there (`/persistent/sodabox/…`, kept out of the persisted
  home so its generation depends on the disk mount alone; generated once by
  `sshd-keygen`) and the CLI pins it (TOFU) to a per-VM `known_hosts`
  (`<data-dir>/<vm>/known_hosts`) via `StrictHostKeyChecking=accept-new`: the key
  is recorded on first connect and **verified** thereafter — a changed key is
  refused. `HostKeyAlias=sodabox-<vm>` keys the pin by VM so the forward's
  host:port can't defeat it (it is stable per VM now, but a reassignment — or a
  port reused by an unrelated listener — must not invalidate the pin). Because the supervisor stops the guest with a hard
  power-off (no ACPI shutdown → no guest flush), `sshd-keygen` runs `sync` right
  after generating the key so that first-boot write is durable (else it would be
  lost and regenerate, and the pin would refuse the new key). *Verified live on
  KVM across a reboot, at the key's earlier `/root/work/.sodabox` path; moving it
  to `/persistent/sodabox` changes only the path, but note that the move makes
  every existing VM present a **new** host key — an existing per-VM `known_hosts`
  pin must be cleared once, or the connection is refused.* Residual risk is a
  local host compromise (the connection
  is host loopback over a local passt forward regardless).
  *Amended by [ADR-0014](0014-persistence-modes.md): the key now lives on the
  home disk (`/persistent/home/sodabox/…`); a `persist = "none"` VM, which keeps
  no disk, gets a host-held key that is pinned up front instead of TOFU.*

### Composition with the egress model

SSH is **inbound** (host → guest); it does **not** traverse the egress allowlist
or the per-VM filter proxy ([ADR-0004](0004-egress-enforcement.md)), which govern
**guest → outside**. passt delivers the forwarded connection to the guest and the
guest's replies ride back on that established flow. So `soda ssh` and sync work
**regardless of egress policy — including `network none`** — which is exactly how
a locked-down VM is still reachable/operable.

### File sync

- **Transport:** `rsync -e "ssh <the hardened opts above>"` — no extra setup,
  same identity as `soda ssh` (one builder, `ssh_rsh_command`). Requires
  `rsync` on both host and guest (pinned host-side, in the guest's base module).
- **Work dir.** The user-owned persistent disk (`/dev/vdc`) is a blank
  sparse raw file at `create`; the base guest module mounts it at `/persistent`
  with `x-systemd.makefs` (ext4) so it is **formatted on first boot** and merely
  mounted thereafter, then binds `/persistent/work` onto **`/var/work`** — the
  sync work tree (`/var/work/project`) therefore survives reboot. It sits
  **outside `$HOME`** on purpose (ADR-0008): `/root` is persistent too, but holds
  per-tool state, and a sync must not be able to overwrite that (nor drag it back
  to the host). An interactive login lands in `/var/work` for the same reason —
  it is the directory the user actually works in.
  *Verified live on KVM (makefs formats vdc, push/pull round-trip) at the earlier
  `/root/work` mount point; the `/persistent` + `/var/work` layout is unverified
  until the next guest rebuild and relaunch.*
- **Asymmetric by design:**
  - `soda sync-vm` — push host cwd → the guest work dir. **No confirmation**:
    the source is the user's own tree.
  - `soda sync-host` — pull guest work dir → host cwd. **Careful**: print a
    dry-run summary (rsync `--out-format=%n`), then offer sync-all / interactive
    (per-entry y/N/q, a declined dir suppressing its children) / no. This is the
    only direction that overwrites host files.
    *Amended 2026-11-01:* `--mode all|interactive|no` makes the choice up
    front, for scripts. Without a terminal on stdin, `sync-host` fails instead
    of asking (a stdin that never closes would otherwise wait forever), and
    `--mode interactive` needs a terminal too.
- **Never deletes** (`--delete` is not used): additive/overwrite only, so the
  destination never loses a file the other side lacks.
- **`.git` is asymmetric:** pushed by default (so an in-guest agent can diff,
  commit, branch) but **not pulled back** unless `--sync-git`, so a guest repo
  can't clobber host history. Extra excludes are given with `--exclude` (applied
  both ways); a config-file `sync.excludes` source is deferred until sodabox has
  a config file (no config infra yet — only per-VM policy/meta today).

### Implementation

- The Rust CLI **shells out** to the system `ssh`/`rsync` rather than embedding an
  SSH/rsync library — minimal, and matches user expectations. The hardened-opts
  builder is one function shared by the `ssh` and `sync` verbs.

## Consequences

- **Positive:** One battle-tested transport for both shell and file transfer;
  rootless (loopback forward); works even with egress fully denied; the careful
  pull + no-delete + `.git`-push-only rules protect the host from a hostile guest;
  nothing to reimplement.
- **Negative / costs:** Depends on `ssh`/`rsync` being present on host and guest;
  the guest image must run `sshd` (added surface, but only on a loopback
  forward); rsync's overwrite-without-delete can leave stale files.
- **Risks & open questions:**
  - Rootless passt **inbound** port-forward wiring under cloud-hypervisor —
    resolved by the host-loopback↔netns fd-relay above and **verified
    live end-to-end on KVM** (real `ssh` with the tool key through the relay +
    passt to a booted guest's sshd, running a command as root). One subtlety
    found and fixed: the relay's in-netns hop to passt's `127.0.0.1` listener is
    itself loopback traffic, which the egress `out` chain would mark and
    TPROXY-divert to the filter proxy (and deny); the nft ruleset now bypasses
    loopback↔loopback before marking (never guest egress, which always carries a
    real destination), so the relay reaches passt.
  - Confirm host-key persistence/pinning on the data disk (the cogbox
    divergence).
  - Port-collision handling when multiple instances pick the same loopback port
    (slide-to-next-free, like cogbox).

## Alternatives considered

- **virtiofs/9p live shared directory** instead of rsync — rejected: a live mount
  means the guest continuously writes into a host directory (a hostile guest
  clobbers host files at will), losing the explicit, confirmable, delete-free
  pull that is the safety property here. Store-sharing uses a read-only per-guest
  erofs closure image (ADR-0008; the whole host store is never shared); the
  *working tree* uses explicit sync.
- **scp/sftp** — rejected: rsync gives incremental transfer, excludes, and
  dry-run summaries the careful-pull UX depends on.
- **Console only (no SSH)** — insufficient: no file transfer and poor ergonomics
  for real work; console remains the fallback.
