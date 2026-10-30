# ADR-0006: Allowlist model and runtime updates

- **Status:** Accepted
- **Date:** 2026-09-02
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

Egress ([ADR-0004](0004-egress-enforcement.md)) and DNS filtering
([ADR-0005](0005-dns-filtering.md)) both consult a per-VM allowlist. We need a
single, well-defined policy model covering **static IP/CIDR** rules and
**domain** rules, plus the **ephemeral** entries the DNS filter derives at
runtime — and a way to update policy while a VM runs.

## Decision

Each VM has a **declarative allowlist** of `ip` and `domain` rules, persisted
with the VM's config. At runtime the enforcement components hold an **effective
allowlist** = static rules **∪** DNS-derived ephemeral entries (TTL-bounded).
Policy is **deny-by-default**; anything not matched is blocked. Edits are applied
live via the VM's control socket ([ADR-0007](0007-control-plane.md)) — no
restart required.

## Details

### Rule types

- `ip <IPv4|IPv6 address or CIDR> [ports] [proto]` — static egress permit. No
  DNS involved. Optional port/proto scoping (default: any port, tcp+udp).
- `domain <name> [subdomains|exact|wildcard] [ports] [proto]` — permits
  resolution of the name (ADR-0005) and authorizes its resolved IPs while their
  TTL is valid. Proto/port scoping applies to the authorized IPs, so
  `domain github.com tcp:443` allows only TLS to whatever GitHub resolves to.

Both IPv4 and IPv6 are first-class, **including the `:PORT`/proto qualifier on
both** (unlike cogbox, whose `:PORT` qualifier is IPv4-only in v1).

### Data model (illustrative)

```
VmPolicy {
  version: u32,
  default: Deny,            # fixed; deny-by-default
  rules: [
    Ip     { cidr, ports?, proto? , note? },
    Domain { name, scope=Subdomains|Exact|Wildcard, ports?, proto?, note? },
  ],
  limits: { max_ephemeral_entries, ttl_floor_s, ttl_cap_s },
}
```

Ephemeral entries (runtime only, not persisted):

```
EphemeralAllow { ip, ports?, proto?, expires_at, origin_domain }
```

### Storage & format

- Persisted per VM under the VM's config dir
  ([ADR-0008](0008-persistent-storage.md)) as a human-editable file (TOML
  proposed) plus programmatic edits via CLI.
- On `vm start`, the supervisor loads the policy and hands it to the filter proxy
  and DNS filter.
- *Amended 2026-10-23 ([ADR-0015](0015-policy-profiles.md)).* Programmatic
  edits preserve comments: the file is edited in place, not re-serialized.
  Rules can be merged in from named profiles, each tagged with a
  `# from profile '<name>'` comment.

### Runtime updates

- CLI verbs: `sodabox allow ip …`, `sodabox allow domain …`, `sodabox deny …`,
  `sodabox policy show|edit`, scoped to a VM.
- The CLI writes the persisted policy **and** pushes the new version to the
  running supervisor over the control socket; the supervisor atomically swaps the
  effective policy (copy-on-write; in-flight allowed connections are unaffected,
  new connections use the new policy).
- Policy carries a monotonically increasing `version` so the TUI/CLI can show
  which version is live.

### Evaluation order

1. Static `ip` rules (fast path, longest-prefix / set membership).
2. DNS-derived ephemeral entries (only populated for allowed domains).
3. Otherwise: **deny** + emit event.

## Consequences

- **Positive:** One coherent model for both enforcement points; supports both
  "I know the IP" and "I know the domain" workflows; live edits without
  restart; auditable, declarative, version-stamped policy.
- **Negative / costs:** Two entry sources (static + ephemeral) to reason about;
  need care that a removed domain rule also purges its ephemeral entries.
- **Risks & open questions:**
  - Concurrency of live swaps vs. in-flight flows (define exactly what happens to
    established connections when a rule is revoked — proposal: leave established
    flows alone, block new ones; add an optional "kill on revoke").
  - Whether to support per-rule direction/port ranges in v1 or defer.

## Alternatives considered

- **Global (all-VM) allowlist** — simpler but breaks per-VM isolation and least
  privilege. Rejected; policy is per VM.
- **Immutable-at-start policy** — simplest, but the DNS coupling and interactive
  use both require runtime updates.
