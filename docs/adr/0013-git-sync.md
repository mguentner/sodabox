# ADR-0013: Git-native host↔guest sync

- **Status:** Accepted
- **Date:** 2026-10-06
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

[ADR-0011](0011-ssh-and-sync.md) moves files between the host and a running
VM with `rsync -a -e ssh` against a fixed guest work dir
(`/var/work/project`). That is a full-tree, file-level transfer: build
artifacts, ignored files, and scratch dirs all move along with whatever the
user actually wanted to carry over.

When the work being moved is already a git repository — the common case when
a coding agent runs *inside* the VM and commits its own work — the host's own
git is a better transport: it moves committed history, not raw files, so
build clutter and scratch state never cross the boundary at all. We adopt
this as a second, independent sync transport, alongside rsync, reusing the
exact SSH identity ADR-0011 established.

## Decision

The host's **git** can treat a VM as a plain remote. `sodabox git-remote
<vm>` configures a git remote named after the VM in the cwd's repo, routed
through git's `ext::` helper and sodabox's existing hardened SSH identity;
from then on the user runs **unwrapped** `git push <vm>` / `git pull <vm>` —
sodabox does not wrap push or pull itself. The guest's `/var/work/project`
(the same directory rsync already uses) is kept a normal, non-bare working
tree, made push-safe with `receive.denyCurrentBranch = updateInstead` (git
≥2.4).

## Details

### Why `ext::`, not a baked-in `ssh://` URL

The SSH endpoint ([`SshEndpoint`]) is a host-loopback `host:port` the
*supervisor* publishes, not something a remote URL can know up front. When this
ADR was written the port also changed on every restart, which made a baked-in
`ssh://user@127.0.0.1:<port>/…` remote outright broken; ADR-0011 has since made
the port **per-VM state** (`meta.toml: ssh_port`), so it is now stable — but
`ext::` remains the right choice:

- The endpoint file stays the client-facing source of truth, and the port *can*
  still be reassigned (a non-sodabox process holding it at boot), which would
  silently break a baked-in URL in exactly the case hardest to debug.
- Resolving per invocation gives a real error ("start it with networking first")
  when the VM is down, instead of a connection refused against a dead port.
- The remote needs no path component, no port, and no reconfiguration ever.

git's `ext::` helper
re-execs an arbitrary command **once per push/fetch**: `sodabox git-remote`
configures

```
ext::sodabox git-proxy <vm> --user <user> %S
```

once, ever — git-remote-ext(1) splits this on unescaped spaces (no shell
involved; `vm`/`user` are escaped per its own `%%`/`% ` grammar, not shell
quoting) and substitutes the trailing `%S` with the long service name
(`git-upload-pack`/`git-receive-pack`) itself — it does **not** append the
service as an extra argument on its own, so the placeholder has to be given
explicitly. `sodabox git-proxy` (hidden; never run by hand) resolves a **fresh**
`SshEndpoint` on every invocation and `exec()`s `ssh` with the exact
hardened, pinned-identity option set shared verbatim with `ssh`/sync
(`hardened_ssh_opts`), running `<service> /var/work/project` on the guest.
The repo path is not part of the URL at all — `ext::` has no path concept,
and it is the one constant work dir rsync already uses, resolved by the
proxy itself. Net effect: the remote is configured exactly once and survives
any number of VM restarts with zero reconfiguration.

### Guest-side repo

- `pkgs.git` joins `pkgs.rsync` in the non-negotiable base image
  (`nix/guest/base.nix`) — both are host↔guest sync transports.
- A stage-2 systemd oneshot (`sodabox-git-init`, after `var-work.mount`) runs
  every boot: `mkdir -p /var/work/project`, `git init` only if `.git` is
  absent, then unconditionally `git config receive.denyCurrentBranch
  updateInstead`. Idempotent and order-independent with rsync: a VM that has
  only ever used `sync-vm`/`sync-host` already has a `.git` there (rsync
  pushes `.git` by default) and simply gets `updateInstead` applied in place
  on next boot — no migration step, immediately `git push`-able.
- `updateInstead` makes a push to the guest's **currently checked-out**
  branch update the working tree to match, refusing cleanly if that would
  clobber an uncommitted or conflicting local change; pushes to any other
  branch ref behave exactly like a bare repo (unaffected). This was chosen
  over a bare repo + a `post-receive` hook doing the checkout: same end
  result, one fewer moving part (a single working directory, no custom hook
  script to maintain), and it is a stock git feature rather than custom code.

### Push lands in `host/*`, not the guest's branches

*Amended 2026-10-16.* Pushing straight into the guest's `refs/heads/*` does not
fit the intended workflow (sync or push in → an in-VM agent commits → pull
out): once the guest has its own commits on the checked-out branch, a host push
to that branch is non-fast-forward, and `updateInstead` can't help with that.
In practice it was also bypassed entirely: `sync-vm` rsyncs the host's
`.git/config` over the guest's, wiping the `updateInstead` that
`sodabox-git-init` applied at boot, so pushes failed with the stock
"refusing to update checked out branch".

`sodabox git-remote` therefore also pins

```
remote.<vm>.push = +refs/heads/*:refs/remotes/host/*
```

git uses this both for a bare `git push <vm>` and to map the destination of
`git push <vm> <branch>`, so both forms put the host's branches into the guest
as remote-tracking refs `host/<branch>`. They are never checked out, so a push
can't collide with in-VM work. Inside the VM the agent integrates with an
ordinary `git merge host/<branch>` (or rebase), exactly as if the guest had a
remote called `host`. It has no fetchable URL, though: the guest can't reach
the host, since this transport is inbound-only. The refspec is forced
because `host/*` only mirrors the host. It never holds guest work, so a rebased
host branch simply replaces it, the same way a fetch refspec behaves. Re-running
`git-remote` on an existing remote applies the refspec in place.

`updateInstead` stays in place for anyone who deliberately pushes to a guest
branch with an explicit `git push <vm> <src>:refs/heads/<dst>`.

### No added confirm/dry-run layer

Unlike rsync's asymmetric, careful-pull design (ADR-0011), git push/pull get
**no** sodabox-side wrapping. git's own non-fast-forward rejection and
`updateInstead`'s dirty-worktree refusal already provide a structural,
content-aware safety property that is strictly stronger than rsync's
dry-run-and-confirm UX (which exists only because a raw-file overwrite can
silently destroy data with no trace — commits can't be silently lost the same
way). `sodabox git-remote` itself still refuses to silently repoint an
existing differently-configured remote of the same name (needs `--force`).

### Composition with the egress model and rsync

Like SSH and sync, this is **inbound** (host → guest) and does not traverse
the egress allowlist — it works even under `network none`. It is an
independent transport from rsync, sharing only the guest work dir and the
hardened SSH identity; a VM can use either, both, or switch between them
freely (rsync for the full tree including untracked scratch files when
wanted, git for the "just the deliverable commits" path this ADR adds).

`sodabox rm` deliberately does not try to remove any host-side git remote —
the remote lives in whichever repo the user ran `git-remote` from, which `rm`
has no way to locate.

## Consequences

- **Positive:** Far less transferred clutter than a full-tree rsync; plays
  naturally with an in-guest coding agent that commits its own work; the
  remote configuration survives VM restarts with no upkeep; no new auth
  mechanism (reuses ADR-0011's hardened identity verbatim).
- **Negative / costs:** A second transport to reason about alongside rsync;
  requires `git` on the guest (added base-image surface, like `rsync`); a
  `git-proxy` invocation is one more `ssh` round trip per push/fetch than a
  direct `ssh://` URL would need.
- **Risks & open questions:** *Needs live verification on KVM*: first push
  into a fresh VM; a second push after a VM restart with no reconfiguration
  (the whole point of `ext::`); a push refused by `updateInstead` against a
  dirty guest checkout; a pull of an in-guest agent's commit; and a VM
  previously used only via rsync picking up `updateInstead` on first boot
  after this ships.

## Alternatives considered

- **Baked-in `ssh://user@host:port/path` remote URL** — rejected: it hard-codes
  a port the supervisor owns. (At the time of writing that port also changed on
  every restart; ADR-0011 has since made it stable per-VM state, but it can
  still be reassigned when an outside process holds it, and a stale URL fails
  in the least debuggable way.) `ext::` resolves the live endpoint fresh on
  every invocation instead, with no upkeep at all.
- **Bare repo + `post-receive` hook** on the guest, checking out into
  `/var/work/project` after each push — rejected: `receive.denyCurrentBranch
  = updateInstead` gets the same end result as a stock git config line, with
  no custom hook script to maintain and only one working directory to reason
  about.
- **A `sodabox`-wrapped push/pull with its own confirm/dry-run step**
  (mirroring `sync-host`) — rejected: git's own non-fast-forward and
  `updateInstead` refusals are a strictly stronger, content-aware safety
  property than rsync's file-list-and-confirm UX, so a sodabox wrapper would
  be redundant and would defeat the goal of plain, unwrapped `git
  push`/`git pull`.
