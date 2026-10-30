# ADR-0005: DNS filtering — domain allowlist as anti-exfil + egress derivation

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

Requirements: **DNS resolved on the host** using the host `resolv.conf`, and
**whitelistable DNS resolution**. Two distinct security purposes ride on how DNS
is handled, and it is important not to conflate them:

1. **DNS-QNAME exfiltration.** Even with deny-by-default *egress* by IP, a guest
   can leak data by *resolving* `<base64-secret>.badhost.com`: the query name
   carries the payload, and recursion via the sanctioned host resolver delivers
   it to the attacker's authoritative nameserver. No connection and no returned
   answer are needed, so IP/port egress filtering does **not** stop it. The only
   robust, non-MITM defense is to control **which names may be resolved at all**.

2. **Egress reachability.** Users reach internet services by *name*, not IP. It
   is ergonomic for "allow `github.com`" to make cloning work without the user
   discovering GitHub's IP ranges.

A single mechanism — a **domain allowlist at a host-side filtering resolver** —
serves both.

## Decision

Run a **host-side filtering DNS resolver** per VM. It enforces the VM's
**domain allowlist**: allowed names are resolved **upstream via the host
`resolv.conf`**; every other name is **refused** (blocking QNAME exfil). For an
allowed name, the resolver **authorizes the returned A/AAAA IPs in that VM's
egress allowlist** for the record's TTL. **Static IP/CIDR entries** coexist for
hosts reached directly without DNS. Both entry kinds carry optional **protocol +
port** scoping.

The shared-IP looseness of authorizing a name's resolved IPs (an unrelated name
on the same IP becomes reachable) is **explicitly accepted** — it is out of the
threat model, and the same coupling is what makes the domain allowlist double as
the anti-exfil gate.

## Details

### Allowlist entries (see [ADR-0006](0006-allowlist-model.md))

```
allow ip 192.168.3.2                 # LAN host; direct egress, no DNS
allow ip 10.0.0.0/24 udp:5555        # a CIDR, UDP port 5555 only
allow domain github.com tcp:443      # resolvable + resolved IPs reachable on tcp/443
allow domain example.com             # resolvable + resolved IPs reachable (any proto/port)
```

- A **`domain`** entry does two things: (a) permits resolution of that name
  (default-deny → non-listed names REFUSED), and (b) feeds its resolved IPs into
  the ephemeral egress set, scoped to the entry's proto/port.
- An **`ip`** entry authorizes egress directly and involves no DNS.

### Resolution path

```
guest app → guest stub (127.0.0.53) → 192.0.2.53 (guest's sole nameserver)
   → passt --dns-forward maps guest DNS onto the sodabox filtering resolver
      ├─ QNAME in domain allowlist?  ── no ──> REFUSED  (+ emit dns_blocked)
      │        yes
      ├─ resolve upstream via host /etc/resolv.conf
      ├─ insert answer A/AAAA IPs into the VM's ephemeral egress set (TTL-bounded)
      └─ return answer to guest      (+ emit dns_allowed {name, ips, ttl})
```

- **Resolve-via-host:** upstream resolution uses the host's `resolv.conf`
  nameservers, so systemd-resolved / split-DNS / VPN DNS / corporate resolvers
  all apply, and a single resolver identity is presented to the guest.
- **DNSSEC-safe on the forward leg:** passt rewrites only the packet
  destination; our resolver is the endpoint that applies policy and re-queries
  upstream.
- All of this lives inside the choice-D egress design
  ([ADR-0004](0004-egress-enforcement.md)): guest DNS is just another flow the
  per-VM netns funnels to the host-side components; the filtering resolver and
  the egress proxy are two parts of the same per-VM supervisor sharing the
  policy and the ephemeral IP set.

### Matching semantics

- Domain rules match a name and, by default, its subdomains; exact-only and
  `*.suffix` forms are configurable. **Anti-exfil caveat:** a suffix rule trusts
  that whole domain's authoritative DNS, so `secret.example.com` exfil is only
  possible if the attacker already controls `example.com`'s NS — a high bar, and
  the operator's choice when they allow a suffix.
- A/AAAA answers drive egress authorization; CNAME chains are followed and each
  hop's final A/AAAA are authorized. Other qtypes may resolve for an allowed
  name but create no egress entry.
- Blocked-name response: **REFUSED**.

### Anti-abuse

- Cap the count and total size of ephemeral egress entries per VM (a hostile app
  could spray allowed-name lookups).
- Enforce a **TTL floor and cap** on effective lifetime to bound churn and stop
  pinning stale IPs.

## Consequences

- **Positive:** One list, two robust guarantees — DNS exfil to non-allowlisted
  names is blocked, and reachability follows from names the user already knows;
  resolution honors the host stack; no MITM, no per-instance CA, no guest
  trust-store surgery.
- **Negative / costs:** Default-deny resolution means the user must allowlist the
  domains their app needs (paired naturally with the egress list); the ephemeral
  set churns with TTLs; CDNs may yield many IPs.
- **Risks & open questions:**
  - TTL races (connect just as an entry expires) → small grace period.
  - passt reads `/etc/resolv.conf` once at launch; a host resolver change needs a
    restart to affect the forward leg.
  - Whether to ship any seeded default-allow domains, or start fully empty.

## Alternatives considered

- **Resolve anything via host + pin port 53 to the host resolver** — withdrawn:
  the port-53 pin stops rogue-resolver use but leaves QNAME exfil wide open
  (recursion via the sanctioned resolver delivers the payload).
- **IP/CIDR allowlist only, no domain entries** — withdrawn: no anti-exfil, and
  users would have to discover IP ranges for every service.
- **L7 TLS termination (SNI/Host)** — the way cogbox whitelists by name;
  rejected here as non-minimal (mitmproxy + per-instance CA + guest trust
  injection).
