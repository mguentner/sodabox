# ADR-0021: Pending egress requests — interactive approval with TTL

- **Status:** Proposed
- **Date:** 2026-10-16
- **Deciders:** Project team
- **Supersedes / Superseded by:** —

## Context

Egress is deny-by-default (ADR-0004/0006): a destination with no matching rule
is refused immediately — the transparent TCP proxy drops the connection, the UDP
proxy drops the datagram, and the filtering resolver answers `REFUSED`
(ADR-0005). That is the security invariant and it stays. But for a destination
the policy simply does not *know about yet*, an instant refusal is also the
worst UX: the user learns about the attempt only after it has already failed,
and letting it through afterwards requires re-running whatever the guest was
doing.

All enforcement components (TCP/UDP proxy, DNS resolver) run as tokio tasks in
the supervisor process (ADR-0007), next to the control socket and the event
stream the CLI/TUI already consume (ADR-0009). So the pieces needed to *pause* a
verdict, surface it, and resolve it interactively all live in one process; no
new IPC is required. The guest side tolerates a pause reasonably well:

- **DNS:** stub resolvers retransmit; a delayed answer is received, not failed.
- **TCP:** the transparent proxy owns both ends, so it can accept the SYN and
  simply not dial upstream until told to; TCP keepalive keeps the connection
  from dying while it sits.
- **UDP:** a datagram can be held in memory; UDP is best-effort anyway.

## Decision

When a verdict would be **deny-by-default because no rule matched** — i.e. the
destination is *undecided*, not explicitly denied — the enforcement component
does not refuse immediately. Instead it parks the request in a per-VM
**pending-request table** with a **30 s TTL** and surfaces it as a live
**Egress Requests** panel in the TUI, on the **Network tab, above the Egress
panel**. The user can **approve** — the flow proceeds exactly as if it had been
allowed from the start, and a **persistent allowlist rule** is added — or
**deny** — the flow is terminated as today. On TTL expiry the request is
**refused** (and the panel row disappears). Denying records the decision on the
VM's **blocklist**, so it isn't asked again. A blocklist entry refuses instantly;
holding is only for the undecided case.

## Details

### Semantics per protocol

- **DNS (ADR-0005).** The query is held, not answered. The upstream query is
  **not sent until approval** — an unapproved name must not leak to the host
  resolver/upstreams, preserving the anti-exfiltration property. On approve:
  resolve upstream, answer the (held) query normally; the guest just saw a
  slow resolver. Whether the answer grants egress is what the user chose when
  approving (see *Approval = a persistent rule*). On deny/expiry: `REFUSED`, as
  today.
  Identical queries within
  the hold window **coalesce** into one pending entry (retransmissions must not
  mint rows).
- **TCP (ADR-0004).** The transparent proxy accepts the guest-side connection,
  enables TCP keepalive on it for the length of the hold, and withholds the
  upstream dial until the verdict. Approve → dial and splice (the existing allow
  path). Deny/expiry → close the socket. The guest observes a stalled connect,
  then either an established connection or a reset. If the guest closes the
  connection while it is held, the proxy drops it, and a request with no client
  left is removed as `abandoned` rather than offered for approval. A socket can't
  tell a close from a half-close, so a client that half-closes during a hold and
  still wants the reply is dropped too and has to retry. Ordinary dials are
  exempt: the check starts 2 s into a dial.
- **UDP.** The first datagram of a flow to an undecided destination is held in
  memory; repeats are dropped until the verdict. Approve → forward it; the flow
  proceeds. Deny/expiry → silently drop, exactly as today. A denial stands for
  the 60 s flow TTL, so a chatty client doesn't re-ask on every retransmit; after
  that the next datagram is a new request, and a rule added in the meantime
  applies right away.

### Pending-request table

Owned by the supervisor, one table per VM:

- **Key (coalescing):** `(proto, destination, port)` — for DNS, the qname
  instead of an address.
- **TTL:** 30 s, static (not configurable).
- **Capacity cap:** e.g. 64 concurrent pending entries per VM. On overflow the
  **oldest is refused early** (FIFO eviction, `queue-full` verdict: nobody decided
  this, so the audit log must not say someone denied it). The cap bounds rows and
  event-stream pressure from a chatty or malicious guest.
- **Waiter cap:** 256 held enforcement calls per VM across all entries, since
  coalesced calls share one entry but each pins its own socket/task. At the cap
  a further call for a held destination is refused on the spot; a new destination
  makes room by refusing the oldest entries (`queue-full` too). This bounds memory
  and held sockets/fds.
- A held enforcement call awaits its entry via a per-request channel; the
  resolving side (control socket) completes it with approve/deny.
- **Release by rule:** the 1 s sweep also re-checks each entry against the live
  rules and approves any that a rule now covers, whichever way that rule got
  there: `soda allow`, a profile, a policy edit, or a DNS answer admitting an
  address. A request the policy allows must not count down and be refused. The
  check is polled because DNS admissions don't pass through a policy change.
- **Remembered lookups:** an address request whose remembered name (see the TUI
  section) has a `domain` rule covering its port and protocol gets its permit
  back instead of asking, if the address is public. A permit can be missing
  while the rule stands, since applications cache answers past their TTL and a
  lookup made before the rule existed admitted nothing. A new connection like
  that is approved on the spot, with no row and no notification, and the sweep
  applies the same check to rows already held, so one decision clears them all.
  The restored permit lasts 60 s and counts against the same caps as an answer.

### Approval = a persistent rule

Approving a request does not grant a one-shot pass; it **adds an allowlist rule
to the VM's policy** (ADR-0006), applied live via the control plane. What it adds
depends on what the row offers.

A row with a name opens a popup asking what to grant: a dns row, a refused row on
the DNS panel, and an address row whose address came from a lookup and is public.

```text
allow example.com
  Resolve only | HTTPS | HTTP+HTTPS | all ports | TCP [443,8443] | UDP [    ]
                                                             [confirm]
```

| Choice | Rule added (subdomain scope) |
| --- | --- |
| Resolve only (name rows) | `resolve`: the name resolves, its IPs gain no egress |
| This IP:port only (address rows) | `ip`, limited to the row's proto and port |
| HTTPS | `domain`, port 443 on either protocol: HTTP/3 runs over UDP |
| HTTP+HTTPS | `domain`, TCP port 80, and `domain`, port 443 on either protocol |
| all ports | `domain`, any port and protocol |
| TCP / UDP | `domain`, the listed ports on that protocol |

HTTPS is preselected on a name row. An address row preselects a choice covering
its own port, typed into the TCP or UDP field if no preset does, so the common
case stays two keys (`a`, `Enter`) inside the 30 s hold. An empty port field is
refused: the policy reads no ports as any port, and that is its own choice.

A row with no name has nothing to ask, so approving adds the `ip` rule at once:
an address with `no recent lookup`, a non-public address, or a blocked row on the
Egress panel, whose event carries no name.

**The decision is about a name and its ports, not its addresses.** A name behind
a load balancer or CDN returns several addresses that rotate, and asking about
each of them taught users nothing except to keep approving. Fine-grained control
stays available: Resolve only and This IP:port only keep every address and port
decision with the user.

**A `domain` rule still trusts whoever controls the name's records**, and the
guest may have picked the name. The popup makes the grant visible, but cannot
make it safe, so two limits apply:

- A **non-public answer** (loopback, private, link-local, shared address space,
  multicast, reserved, and IPv6 forms embedding one of those) is returned to the
  guest but admits nothing, whatever rule matched it. Connecting to it is a
  request of its own. Otherwise a name approved for its web service could open the
  host's LAN or a cloud metadata endpoint by changing a record. This applies to
  every `domain` rule, including written ones: a rule for an internal name needs
  an `ip` rule for its range. An `ip` rule is unaffected.
- **all ports** is never preselected. It also opens port 53 on those addresses
  (see *Port 53* below).

Rules add up. Every `domain` rule matching a name admits its answers with its own
ports and protocol, so allowing another port later, or a subdomain, extends what
is granted rather than replacing it. Where only `resolve` rules match, the name
resolves and admits nothing; a `resolve` rule next to a `domain` rule changes
nothing, so an approved DNS request never narrows a written rule.

A DNS answer is admitted before the guest receives it, so approving a dns row
leaves no gap. A `domain` rule picked on an address row isn't resolved by the TUI,
because the held connection's re-check would find no permit yet: the sweep
restores the permit and releases that row, and its siblings, within a second. A
row the chosen rule doesn't cover stays held for the user to decide.

### Denial = a blocklist entry

Some requests repeat for as long as the guest runs and will never be allowed.
Refusing one and forgetting it means asking again on the next retry, so denying
records the decision in `[[blocklist]]` in `policy.toml` (ADR-0006), applied live
the same way as an approval. Letting a row expire records nothing, which is the
"not now".

```text
block udp 203.0.113.5:443 via example.com
  This IP:port only | This name on udp 443 | All of this name
                                                       [confirm]
```

| Row | Recorded |
| --- | --- |
| dns | The exact name, without asking |
| Address with no name, or a non-public address | Its protocol, address and port, without asking |
| Address with a name: This IP:port only | The same |
| Address with a name: This name on `<proto> <port>` (preselected) | `domain` entry, exact name, that protocol and port |
| Address with a name: All of this name | `domain` entry, exact name, nothing else |

The preselected choice is what stops a loop: with a TCP-only rule on a name,
HTTP/3 asks about UDP 443 on each of its addresses, and the name has to keep
resolving. So only a `domain` entry with neither ports nor protocol refuses
lookups. Scope is exact by default, since a guest can ask for subdomains the user
has never seen, and refusing those silently should be a choice. `soda block` can
choose `--subdomains` or `--wildcard`.

**The order is allow rule, then blocklist, then hold.** The check sits in the
request table, which every enforcement path already reaches only after the allow
rules said no. So an entry can only turn a question into a refusal: it never
grants anything, `Allowlist::evaluate` doesn't know about it, and losing the list
costs a prompt rather than a hole. The sweep releases what a rule covers before
refusing what an entry covers, for the same reason, and that is also how the rows
an entry newly covers go away.

An entry therefore can't carve an exception out of a wider allow: next to
`domain example.com`, an entry for `tracker.example.com` does nothing, and
`soda block` says so. Exceptions would have to reach evaluation, DNS admission and
remembered lookups, and are a separate decision.

**Allowing over an entry asks.** An entry a new allow rule overlaps no longer
decides anything, but would come back into force if that rule were revoked. The
TUI and `soda allow` ask whether it should go, and it stays unless the answer is
yes; a `soda allow` with no terminal keeps it and says so. Entries on another port
or protocol aren't overlapped, so a TCP rule doesn't ask about a UDP entry on the
same name. A profile merge doesn't ask, and a profile can't carry entries.

**A name entry reaches addresses through remembered lookups**, so it is as good as
what they remember: past the hour, or after a supervisor restart, a cached address
is `no recent lookup` and asks again. A guest can also dodge a name entry by
looking the address up under another name it may resolve, or raise new requests
with new names. Neither gets it any egress; the caps above still bound the rows.

### Why a request was refused

A silent refusal is the cost of not asking, so every refused flow and query says
why, on its row in the TUI (right after the tag, as a long name gets cut off) and
in `soda logs`:

| Reason | When |
| --- | --- |
| `blocklist` | An entry matched, so nobody was asked |
| `timed out` | Nobody answered within the hold |
| `queue full` | A cap was hit, so nobody was asked |
| `not covered` | Approved, but no rule covered it on the re-check |
| `denied` | Refused over the control socket with nothing recorded, which the TUI no longer does |
| `no access` | A connection to the gateway (ADR-0020) while it is off or not granted |

The Policy panel lists the two sides as **Allowlist** and **Blocklist** under one
cursor. `d`/Enter revokes a rule (every rule on its target, like `soda revoke`) or
unblocks one entry (they differ by what they refuse), and the footer says which.

### Control protocol & events

- Control socket (ADR-0007) gains `RequestResolve { id, allow }` (idempotent;
  resolving an already-expired/removed request is a no-op) and `RequestList`
  (the current pending set, so a freshly started TUI shows held requests
  without waiting for new ones).
- Two new `Event` variants (ADR-0009), also written to `events.log` for audit:
  - `RequestPending { id, kind, proto, destination, port?, via?, expires_ts }`
  - `RequestResolved { id, verdict }` — verdict is `approved`, `denied`,
    `expired`, `abandoned`, `queue-full`, or `blocklisted`.
- `Egress` and `Dns` events gain an optional `reason` (above).

### TUI (ADR-0009)

- New **Egress Requests** panel on the **Network tab, above the Egress panel**:
  one row per pending request with its destination and a per-row countdown of
  the remaining TTL.
- An address row says where the address came from, since a connection carries
  only an IP and port and the user needs more to judge it:
  `tcp 203.0.113.5:443 via example.com`, the name whose lookup most recently
  returned it (remembered for an hour, as applications cache answers past their
  TTL), or `no recent lookup` when the guest reached it without one, which is
  worth a second look. This is a hint, not proof: it says what the guest looked
  up, not who owns the address, and a guest can point a name of its own at
  anything. So it is shown dim rather than as a verified identity, and long names
  keep their end (the part that says who runs them). A rule granted on that name
  covers an address only while the name's lookups keep explaining it.
- `Enter`/`a` approves, opening the popup on a row with a name; `d` denies, opening
  the block popup on an address with a name. In a popup `←`/`→` or `Tab` choose,
  typing fills the TCP or UDP port field, `Enter`
  confirms and `Esc` cancels without deciding, leaving the row counting down. A
  popup shows the row's remaining time, and while one is open the Status logo is
  taken down, since it would be drawn over it. The question whether a new allow
  should clear blocklist entries takes `y` or `n`, not `Enter`, which has just
  confirmed the allow. The cursor/panel-focus model is the
  existing one (the new panel joins the focus cycle). The cursor follows the
  request, not the row position: when the highlighted request goes away the
  selection clears, so a key press never acts on a request the user didn't pick.
- The event stream is lossy under load, so the panel reconciles: when the stream
  reports dropped events the TUI re-fetches `RequestList` (notifying if that
  reveals new requests), and a row past its `expires_ts` is removed even if its
  `RequestResolved` was lost. Approving first checks that the request is still
  pending, so a stale row never adds a rule.
- **Countdown color ramp**, by remaining TTL: **white → yellow → orange → red →
  dark red → purple**; at expiry the row is deleted. The TUI already renders
  every tick, so this is a pure function of `expires_ts` vs. now.
- **Notifications.** A new `RequestPending` triggers a terminal notification:
  **OSC 9** (`ESC ] 9 ; <message> BEL`, the "growl" notification escape) plus
  the **terminal bell** (`BEL`). The message is the static text
  `<vm> has new egress requests`: destinations are guest-controlled (a DNS name
  can hold any byte) and must not reach a raw escape sequence. For the same
  reason the TUI scrubs control characters from every frame, `soda logs` prints
  them escaped, and a domain name containing them can't become a rule. The TUI
  key `n` cycles the mode:
  `off | notification | bell | all` — which of the two mechanisms (or neither,
  or both) is emitted. The mode persists in the CLI/TUI config in the config
  dir (`$XDG_CONFIG_HOME/sodabox/tui.toml`, key `notify`), so it survives
  restarts. Only `RequestPending` notifies; resolved requests do not. The TUI
  must emit the escape sequences itself (stdout), since it is the process
  attached to the user's terminal. Default: `all` — a pending request is
  exactly the thing the user is not looking at the screen for.

## Consequences

- **Positive:** the user can let an unknown destination through *in time*,
  before the guest application gives up — the guest never observes a policy
  decision at all, only latency; managing requests becomes first-class TUI UX
  instead of post-hoc log archaeology.
- **Negative / costs:** held DNS answers mean the guest's resolver may retransmit
  and applications may exceed their own timeouts (getaddrinfo commonly gives up
  before 30 s) — the approve path helps only for callers that retry or are
  still waiting; held TCP sockets and held datagrams consume memory/fds until
  the cap; the pending table, two new control commands, two new event variants,
  a `resolve` rule kind, a TUI panel, the allow popup and a notify setting are real
  implementation surface. Choosing Resolve only or This IP:port only still means
  more prompts: a name behind a CDN or with rotating addresses asks again for each
  new address and accumulates `ip` rules. That is what those choices are for. A
  written `domain` rule for an internal name now prompts for its addresses, and
  with no TUI open those connections are refused when the hold expires.
- **Risks & open questions:**
  - **Trusting a name:** a `domain` rule from the popup opens its ports on whatever
    public address the name's owner publishes, so approving a name the guest could
    have registered amounts to allowing those ports on most of the internet. The
    popup shows the name; the user has to judge it. A shared hosting name carries
    the same risk through its subdomains. A remembered lookup extends this by up to
    an hour past the record's TTL.
  - **Recording a mistake:** `d` on a dns row is one key with a lasting effect, and
    what it refuses then fails with no prompt. The row's reason and the Policy
    panel are how it gets noticed and undone.
  - **Retry loops:** a held connection stalled for 30 s, a blocklisted one fails at
    once, so a guest retrying in a loop spins faster and logs a blocked event per
    attempt. The event ring and `events.log` are bounded, but a loop can push
    useful history out. Coalescing them is open.
  - **Prompt fatigue:** an interactive path can train users to reflexively
    approve. This is a UX feature, not a security boundary — deny-by-default
    and the audit log remain the boundary, and the approval is a *recorded*
    persistent rule.
  - **Flooding:** a guest can mint pending requests deliberately; the cap plus
    FIFO-deny bounds it, and rows coalesce per destination.
  - **Port 53:** approving a `tcp`/`udp` request to port 53 gives the guest a
    DNS path that bypasses the filtering resolver (ADR-0005), and with it a
    possible exfiltration channel. The row shows exactly what is being asked
    for; users must know what approving it means.
  - **DNS tunnelling:** a `resolve` rule grants no egress, but it is still a data
    path. Holding a query protects an unapproved name, not an approved one: once
    `example.com` is approved, the guest can put data in queries such as
    `<data>.example.com`, which reach that domain's authoritative servers through
    the upstream resolver, and can read data back from the answers. The subdomain
    scope is what makes this open-ended. It is the ADR-0005 suffix caveat, and
    the same holds for a `domain` rule. An approved name therefore means trusting
    whoever runs that domain with what the guest can send, so a name the guest
    could have registered itself deserves more care than a known service. The
    subdomain scope stays because exact matching would break most real use
    (`www.`, `api.`, CDN hostnames) and prompt for every hostname.
  - The exact OSC 9 support matrix across terminal emulators (iTerm2, kitty,
    WezTerm, …) — plain-`BEL` fallback is why the bell is a separate mode.

## Alternatives considered

- **Status quo (instant refuse)** — simplest and what the current code does;
  rejected: the user is always one guest-side retry too late.
- **Ask via desktop notification** — out of scope (rootless, no host
  integration) and duplicative; the TUI-local OSC 9/bell covers it.
- **Hold blocklisted requests too** — rejected: an entry is a decision the user
  already made; holding it would make "deny" mean "maybe".
- **A deny that only refuses that attempt** — the earlier behaviour. Rejected:
  a request that repeats forever asked forever. Expiry remains for "not now".
- **Deny rules as a `Rule` kind** — rejected: `rules` is treated as allow-only
  throughout (`soda revoke`, the sweep's "a rule matched" check, DNS matching), and
  an older binary fails to parse an unknown kind but ignores an unknown table.
- **A blocklist that wins over allow rules** — would allow exceptions, but has to
  reach evaluation, DNS admission and remembered lookups, and a blocked shared CDN
  address would then break a name allowed later. Rejected for now.
- **One-shot grants** — rejected: the same destination would ask again on every
  connection, and a grant would leave no audit trail in policy.
- **Always prompting per IP:Port after a DNS approval** — the earlier decision
  here: the DNS row added only a `resolve` rule, so that no approval opened more
  than its row showed. Replaced: a name returning ten addresses meant ten prompts,
  which trains exactly the reflexive approval this feature has to avoid. It remains
  available as Resolve only.
- **Approving a DNS request with a fixed `domain` rule** — one key, no popup.
  Rejected: every port and protocol on whatever the name resolves to, for a row
  that says nothing about either. The popup keeps that choice explicit.
- **Applying the non-public limit to popup rules only** — written rules would keep
  reaching internal names unprompted. Rejected for now: it needs a field on the rule
  and makes two kinds of `domain` rule that look alike but behave differently.
- **Auto-approve with a warning** — rejected outright: it violates
  deny-by-default.
- **Configurable TTL** — considered; rejected for now (30 s, static) to keep
  the surface minimal. Revisit if real usage shows guest-side resolvers
  consistently give up earlier.
