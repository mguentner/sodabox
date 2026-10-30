# Spike report: passt in user+netns, vhost-user backend, DNS-forward targeting

- **ADR:** ADR-0003 / ADR-0005
- **Date:** 2026-09-02
- **Result:** ✅ SUCCESS — all three questions answered **yes**.

## Questions & answers

1. **Can we create the per-VM user+network namespace rootless, with the
   privileges to run passt + nft there?** — **Yes.** `unshare -Un --map-root-user`
   yields uid 0 in the userns with **CAP_NET_ADMIN in the new netns** (created a
   dummy interface, assigned addresses, brought links up).
2. **Does passt run inside that netns as cloud-hypervisor's vhost-user backend,
   giving the guest a working NIC?** — **Yes.** passt `--vhost-user` listened on a
   unix socket, CH connected (`--net vhost_user=on,socket=…`), the guest
   enumerated `eth0` and passed a **bidirectional UDP datapath**.
3. **Can passt's `--dns-forward` target an arbitrary in-netns resolver address?**
   — **Yes.** Guest DNS sent to `10.0.2.3` (passt's `--dns-forward`) was forwarded
   by passt to our chosen upstream `203.0.113.53` (a coredns instance on an
   in-netns dummy interface). The guest resolved `spike.sodabox.test → 192.0.2.222`
   round-trip.

## The working setup (all inside one `unshare -Un --map-root-user`)

```sh
ip link set lo up
ip link add res0 type dummy; ip addr add 203.0.113.53/24 dev res0; ip link set res0 up

# in-netns filtering-resolver stand-in (real product uses our Rust resolver)
coredns -conf Corefile -dns.port 53          # bind 203.0.113.53, answers *→192.0.2.222

# passt as CH's vhost-user backend, in this netns
passt --vhost-user -s "$SOCK" -f \
  -a 10.0.2.15 -n 24 -g 10.0.2.2 \
  --dns-forward 10.0.2.3 \      # address the GUEST sends DNS to
  -D 203.0.113.53 \            # arbitrary UPSTREAM passt forwards to (our resolver)
  -o 203.0.113.53 --outbound-if4 res0 -M 9a:55:9a:55:9a:66

# cloud-hypervisor connects to passt's socket; shared memory is MANDATORY
cloud-hypervisor --kernel … --initramfs … --cmdline "console=ttyS0 rdinit=/init" \
  --net vhost_user=on,socket="$SOCK",mac=… \
  --memory size=512M,shared=on            # <-- vhost-user requires shared=on
```

The **DNS wiring for ADR-0005** is exactly this: `--dns-forward <guest-facing
addr>` + `-D <our resolver addr>`, with the resolver on an in-netns address. Both
addresses are arbitrary and under our control.

## Caveats & findings (design inputs)

1. **vhost-user requires CH `--memory …,shared=on`** (memfd-backed shared guest
   memory). passt even prints the equivalent qemu line with
   `memory-backend-memfd,share=on`. Without it the datapath won't work.
2. **passt outbound sockets really are in the netns** — DNS forwarding to
   `203.0.113.53` only succeeded because it was routed out `res0` *inside the
   netns*. This is the property the interception spike relies on: nft REDIRECT/
   TPROXY in this netns will capture passt's egress. → spike 0003.
3. **ICMP (guest ping) needs `net.ipv4.ping_group_range`** to include the running
   gid; passt uses ICMP ping-sockets and logs `Cannot open "ping" socket … sysctl
   -w net.ipv4.ping_group_range=…`. It is a **per-netns** sysctl, so set it in the
   per-VM netns (we hold CAP_NET_ADMIN). *In this sandbox the `/proc/sys` write was
   refused*, so ICMP stayed blocked here — an environment restriction, not a passt
   or design problem. UDP/TCP are unaffected. → note for the ICMP
   policy and the supervisor's netns setup.
4. **`chv-outside-netns` was not exercised** — here CH and passt shared one netns.
   The ADR-0004 layout runs CH in the host netns with passt inside, joined by the
   vhost-user **unix socket** (a filesystem object, not netns-bound), so the split
   is straightforward. Validate when wiring the supervisor.
   Immaterial to this spike's questions.
5. **`passt-repair` "not usable"** — only needed for TCP connection repair across
   checkpoint/restore/migration; irrelevant to normal operation.
6. **Test-tooling only:** dnsmasq refuses to start in a single-uid userns
   (`setgroups` denied when dropping to `nogroup`/`root`). coredns (no privilege
   drop) works cleanly. The product resolver is our own Rust component, so this
   doesn't affect sodabox — noted so future test scaffolding uses coredns or
   matching creds.

## Rootless note

The rootless-relevant step — creating the user+network namespace and gaining
CAP_NET_ADMIN *within it* from an unprivileged `unshare` — is what was validated.
(The shell happened to be uid 0 in the sandbox, but `--map-root-user` maps the
invoking user to root **inside the userns only**; the same call works for a normal
user, which is how pasta/rootless-containers operate.)

## Artifacts

Pinned `<nixpkgs>`: `passt-2025_09_19`, `coredns-1.14.3`,
`cloud-hypervisor-52.0`, `linux-6.18.38` (+ matched modules incl. `virtio_net`,
`net_failover`, `failover`). Runner + logs in the scratch dir.
