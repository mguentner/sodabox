# ADR-0016: SSH over vsock

- **Status:** Proposed
- **Date:** 2026-10-24
- **Deciders:** Project team
- **Supersedes / Superseded by:** — (would amend [ADR-0011](0011-ssh-and-sync.md) and [ADR-0013](0013-git-sync.md))

## Context

Today SSH reaches the guest over a chain of hops ([ADR-0011](0011-ssh-and-sync.md)):
the supervisor binds a host-loopback port, hands each accepted fd into the
per-VM netns over `SCM_RIGHTS`, and the netns child splices it into passt's
in-netns forward to guest:22. Keeping that chain working takes several extra
pieces:

- a per-VM port allocator (`meta.toml: ssh_port`, `VmMeta::allocate_ssh_port` in
  `crates/common/src/vm.rs`), with its own collision rules;
- the `ssh.endpoint` file the CLI reads to find the live port;
- an nft rule that exempts loopback↔loopback traffic, so the relay's hop to
  passt isn't diverted to the egress proxy;
- SSH depending on the networked stack, so a VM without networking (a
  foreground debug start) has no SSH at all.

The port also leaks into git. A remote can't hard-code a port the supervisor
owns, so [ADR-0013](0013-git-sync.md) routes git through
`ext::sodabox git-proxy <vm> …`, which looks up the endpoint again on every
push and fetch.

cloud-hypervisor supports virtio-vsock in "hybrid" mode: the device is backed by
a unix socket on the host, and a host client opens it with a one-line
`CONNECT <port>\n` handshake. That socket can live at a fixed path in the VM's
runtime dir.

## Decision

Carry host↔guest SSH over **virtio-vsock** instead of the loopback TCP relay.
Each VM's vsock socket sits at a path derived from its name. That lets an
ordinary SSH host alias reach it, and git uses that alias in a plain SSH remote
instead of the `ext::` git-proxy.

## Details

### Wiring

- **Host:** cloud-hypervisor gets
  `--vsock cid=<cid>,socket=<runtime_dir>/ssh.vsock`, with the path coming from
  a new `paths::vsock_path(vm)` next to `control_sock_path`.
- **Guest:** sshd also listens on `vsock::22` through a systemd socket unit in
  `nix/guest/base.nix`. The TCP listener can go once nothing uses it.
- **Client:** the CLI's `ssh`, rsync and git all use the same `ProxyCommand`. It
  opens the vsock socket, sends `CONNECT 22`, checks the `OK` reply, and then
  passes bytes through. The hardened, pinned-identity options
  (`hardened_ssh_opts`) don't change.
- **Removed:** the port allocator and `ssh_port`, `ssh.endpoint`, the
  `SCM_RIGHTS` relay, and the loopback exemption in nft. SSH no longer touches
  passt or the netns.

### git

The socket path is a pure function of the VM name, so a generated ssh_config
fragment can describe every VM up front:

```
Host sodabox-<vm>
  ProxyCommand <vsock connect helper> <runtime_dir>/ssh.vsock 22
  # ... hardened_ssh_opts, pinned identity, known_hosts ...
```

`sodabox git-remote` then sets an ordinary remote,
`sodabox-<vm>:/var/work/project`, and `git-proxy` and the `ext::` URL go away.
If the VM is down, the error still comes from the ProxyCommand ("socket not
found"), not a connection refused on some port.

## Consequences

- **Positive:**
  - fewer moving parts;
  - no port allocation and no port collisions;
  - SSH works even when a VM runs without networking;
  - SSH can't reach the egress path by construction;
  - git remotes are plain `ssh` remotes that other tools understand.
- **Negative / costs:**
  - a ProxyCommand is still needed for the hybrid-vsock handshake;
  - existing `ext::sodabox git-proxy` remotes need migrating (`git-remote` can
    rewrite them, but today it refuses to replace a different URL without
    `--force`, so the old `ext::` form needs to be recognised as safe to replace);
  - the generated ssh_config fragment has to be kept current and included.
- **Risks & open questions:**
  - **Which helper does the handshake:** `systemd-ssh-proxy` (its `vsock-mux/`
    form targets exactly this socket type, but needs a recent systemd on the
    host), `socat`, or a small hidden `sodabox` verb. The last one adds a sodabox
    proxy back, but a stateless one with no endpoint lookup.
  - **Guest→host direction:** in hybrid mode, a guest's `connect()` to the host
    CID is forwarded to `<socket>_<port>` on the host. Nothing must ever listen
    there. That needs stating as an invariant, and a test that guest-initiated
    vsock connections fail.
  - CID allocation: guest CIDs must be unique per host. This may come back as a
    small allocator in `meta.toml`, or be derived per VM. Not verified yet.
  - The relay is in ADR-0011's verified path; vsock throughput and latency for
    rsync haven't been measured.

## Alternatives considered

- **Keep the TCP relay and bake the now-stable port into an `ssh://` URL** —
  rejected for the reasons ADR-0013 gives: the port can still be reassigned, and
  a baked-in URL fails in the case that's hardest to debug.
- **Expose a unix socket through passt** — passt forwards TCP and UDP, not
  `AF_UNIX`, so this would still need the netns relay.
- **Status quo** — it works, but the allocator, endpoint file, nft exemption and
  git-proxy all exist only to work around the port.
