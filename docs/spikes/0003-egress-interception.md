# Spike report: egress interception (REDIRECT vs TPROXY) in a rootless netns

- **ADR:** ADR-0004
- **Date:** 2026-09-03
- **Result:** ✅ SUCCESS. **Decision: use TPROXY** (uniform TCP+UDP, direct
  original-dst recovery). REDIRECT works for TCP but is inadequate for UDP.

## Question

passt's outbound connections are **locally generated inside the per-VM netns**
(OUTPUT hook). Can we transparently divert them to a filter proxy and recover the
**original destination** the guest aimed at — for TCP *and* UDP — rootless, with
rules confined to the netns?

## What was tested (all inside `unshare -Un --map-root-user`, CAP_NET_ADMIN in the netns)

The host has `nf_nat`/`nf_conntrack`/`nft_chain_nat`/`nft_tproxy` available; the
netns uses them without touching host tables. A small C proxy recovered the
original dst two ways: `getsockopt(SO_ORIGINAL_DST)` (REDIRECT) and
`getsockname()` / `IP_RECVORIGDSTADDR` (TPROXY).

### Approach A — REDIRECT (nat OUTPUT)

```
table ip natt { chain output { type nat hook output priority -100;
  tcp dport 443 redirect to :18443
  udp dport 53  redirect to :18053 } }
```

- **TCP: works.** Client→`198.51.100.7:443` → proxy recovered
  `SO_ORIGINAL_DST = 198.51.100.7:443`.
- **UDP: original dst NOT recoverable this way.** The datagram is delivered but
  `IP_RECVORIGDSTADDR` returns the **rewritten** addr (`127.0.0.1:18053`). The
  original tuple *is* preserved in conntrack
  (`dst=198.51.100.9 dport=53`, visible in `/proc/net/nf_conntrack`), so a
  `libnetfilter_conntrack` lookup *could* recover it — but that is a workaround
  with lookup/lifetime races. **Rejected in favour of B.**

### Approach B — TPROXY (the chosen mechanism)

TPROXY is only legal in `mangle PREROUTING`, which locally-generated packets skip.
The standard fix (kernel tproxy docs; corroborated by the referenced dev.to post):
**mark in OUTPUT, then policy-route the marked packets back onto `lo`** so they
re-enter PREROUTING:

```
ip rule add fwmark 0x111 lookup 100
ip route add local default dev lo table 100
# rp_filter=0 on all/lo; route_localnet=1   (namespaced sysctls)

table ip mangle {
  chain out { type route hook output priority mangle;
    tcp dport 443 meta mark set 0x111
    udp dport 53  meta mark set 0x111 }
  chain pre { type filter hook prerouting priority mangle;
    meta l4proto tcp meta mark 0x111 tproxy to :18443 accept
    meta l4proto udp meta mark 0x111 tproxy to :18053 accept } }
```

Proxy sockets are bound with **`IP_TRANSPARENT`** (+ `IP_RECVORIGDSTADDR` for UDP).

- **TCP: works.** Original dst = accepted socket's local addr via
  `getsockname() = 198.51.100.7:443`. (`SO_ORIGINAL_DST` is correctly *absent* —
  TPROXY does no NAT.)
- **UDP: works, directly.** `IP_RECVORIGDSTADDR` cmsg =
  `198.51.100.9:53`. **No conntrack lookup needed** — this is the key correction
  over the first pass.

## Decision & rationale

**Use TPROXY.** It is one mechanism for **TCP, UDP and QUIC** (QUIC = UDP/443),
recovers the original destination **directly** (no NAT, no conntrack race), and
keeps the guest's source addressing intact. REDIRECT would force two code paths
(SO_ORIGINAL_DST for TCP, conntrack for UDP) for a strictly worse result.
`SO_ORIGINAL_DST`/REDIRECT remains a known-good fallback for TCP only.

> **Correction to the earlier draft of this spike:** the first pass concluded
> "TPROXY doesn't apply to passt's locally-generated traffic → use REDIRECT +
> conntrack for UDP." That was wrong: the OUTPUT-mark → `ip rule` → `local
> default dev lo` → PREROUTING re-entry makes TPROXY fully applicable to
> locally-generated traffic. Verified end-to-end above.

## Requirements / caveats for implementation

1. **Netns-scoped setup** (all confined to the per-VM netns, no host changes):
   `nft` mangle `out`/`pre` chains, `ip rule fwmark 0x111 lookup 100`,
   `ip route add local default dev lo table 100`.
2. **Namespaced sysctls** in the netns: `rp_filter=0` (all + lo) and
   `route_localnet=1`. Both were writable here (unlike `ping_group_range` in the
   passt spike). Confirm on target hosts; they're per-netns.
3. **IP_TRANSPARENT** on proxy sockets — needs CAP_NET_ADMIN, which we hold in the
   owned netns (not on the host).
4. **Loop avoidance:** the proxy's *allow-path* dial to the real destination must
   not be re-marked/re-intercepted. ADR-0004 already dials from the **host netns**,
   which sidesteps the netns rules entirely; alternatively exclude by
   uid-owner/cgroup/source (per the dev.to post). Confirm when wiring the proxy.
5. **ICMP:** no L4 port to divert to a userspace TCP/UDP proxy. A default-drop
   (`filter output ip protocol icmp drop`) installs cleanly. **Decision: deny ICMP
   by default** (fail-closed, consistent with deny-by-default egress); note passt
   uses ICMP ping-sockets for guest ping, so guest ping stays blocked unless a
   future policy explicitly allows it.

## Design inputs for downstream tasks

- **nft rules:** install the mangle OUTPUT-mark + PREROUTING-TPROXY
  ruleset above + `ip rule`/`ip route` + the two sysctls, all in the per-VM netns.
- **proxy TCP/UDP:** bind `IP_TRANSPARENT`; TCP original dst
  via `getsockname()`, UDP via `IP_RECVORIGDSTADDR`. One mechanism, no conntrack.
- **allow-path/events:** dial from the host netns to avoid the
  interception loop.

## Reference

Kernel docs: <https://docs.kernel.org/networking/tproxy.html>.

## Artifacts

Pinned `<nixpkgs>`: `nftables-1.1.6`, `iproute2`, `gcc` (cc-wrapper). Proxy
`origdst.c` + run scripts in the scratch dir.
