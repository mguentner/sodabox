# ADR-0020: Inference gateway

- **Status:** Proposed
- **Date:** 2026-10-30
- **Deciders:** Project team
- **Supersedes / Superseded by:** — (narrows the "target state" of
  [ADR-0019](0019-dotfile-collections.md) for inference APIs; would amend
  [ADR-0006](0006-allowlist-model.md))

## Context

Most VMs run coding agents, and every agent needs an inference API key
(Anthropic, OpenAI, Mistral, OpenRouter, a self-hosted vLLM, …). Today that
key reaches the guest as a dotfile ([ADR-0019](0019-dotfile-collections.md)),
where untrusted code (ADR-0001) can read it and send it to any host the policy
allows. ADR-0019 names the goal: credentials stay on the host. Its sketch has
the egress proxy terminate TLS with a per-VM CA and inject headers.

Inference keys are also *billing* credentials. A leaked key costs money until
someone revokes it. So keeping them out of the guest matters more than for most
secrets, and a guest that can use a key needs a limit on how much it can use.

Users also want **model aliases**: the guest asks for `foo:13b`, and the host
decides that on VM1 this means `the_actual_foo:13b` at provider A. That keeps
provider choice and model upgrades on the host side, with no edits inside VMs.

Facts that shape the options:

- The egress proxy (ADR-0004) already receives **every** guest TCP connection
  through TPROXY, along with its original destination, in a host-side process
  the guest can't reconfigure. A connection to a reserved address inside the
  per-VM 10.0.2.0/24 can be handed to an in-process handler instead of being
  dialed out. No new listener and no new transport are needed.
- The DNS filter (ADR-0005) can answer a reserved name under the guest search
  domain `sodabox.internal`, and only when the policy allows it.
- Agent CLIs use **provider-native** APIs. Claude Code speaks the Anthropic
  Messages API (`ANTHROPIC_BASE_URL`), Codex speaks the OpenAI Responses API
  (`OPENAI_BASE_URL`), and most open-model tools speak OpenAI Chat Completions
  or Ollama. All of them accept a base-URL override.
- Subscription logins (Claude.ai, ChatGPT) use OAuth with rotating refresh
  tokens, not static keys.

## Options

**A. Transparent DPI / TLS-terminating injection** (the ADR-0019 sketch;
Docker Sandboxes and Gondolin, among others, do this). The proxy terminates TLS
for chosen hosts with a per-VM CA, and the guest trusts that CA and holds a
placeholder key. The proxy swaps the placeholder for the real key.
Pros: works for any HTTPS API with no client config. Cons: every guest must
trust a CA, and that has to be set up for each runtime (Node ignores the system
store unless told otherwise, and Python, Go and Rust each have their own
store). It needs a full TLS MITM stack, and certificate pinning or HTTP/3
breaks it. It also does nothing for aliases or quotas: the proxy only knows
which host a request goes to, not which model it asks for.

**B. A gateway service with its own API.** The guest uses an explicit endpoint
over plain HTTP. The gateway authenticates upstream, rewrites the model and
enforces quotas. Pros: no CA and no MITM. The gateway sees the model and the
token usage, so aliases, quotas and a dashboard come almost for free. Cons:
clients must be pointed at it, and a single "OpenAI-compatible" front end
can't serve Claude Code or Codex without translation (see B′).

**B′. A gateway that keeps each provider's own API (pass-through per API
format)**, a variant of B. The gateway exposes one route family per API format
(`/anthropic/v1/messages`, `/openai/v1/chat/completions`,
`/openai/v1/responses`, …). For a request in a given format it resolves the
`model` field through the VM's aliases, swaps the auth, and streams the body
through otherwise unchanged. There is no translation in v1. Pros: every native
client works, including features that translation tends to lose (prompt
caching, thinking, tool-use details). The amount of code is much smaller than
a translating gateway's.

**C. Explicit forward proxy with sealed tokens** (fly.io's
[tokenizer](https://github.com/superfly/tokenizer)). The guest holds an
encrypted token that only the proxy can decrypt, and sends it in a
`Proxy-Tokenizer` header over plain HTTP to the proxy. The proxy decrypts it,
injects the real key and does TLS upstream. Pros: generic for any HTTP API, and
no CA. Cons: the sealed token is a bearer *capability*. A copy works from any
other VM that can reach the proxy, unless it is bound to that VM. Clients need
`HTTP_PROXY` plus a custom header, which agent CLIs don't support. And like A,
it knows nothing about models. This option fits non-inference APIs better
(see below).

**D. Scoped, short-lived keys in the guest.** The host mints a key for each VM
with a spend cap (OpenRouter provisioned keys, Anthropic workspaces, OpenAI
project keys), puts it in the VM, and revokes it on `stop`. Pros: no gateway at
all. Cons: the key is still in the guest, and it depends on the provider having
an admin API for minting keys. It limits the damage of a leak but doesn't stop
one. This option complements the others; it doesn't replace them.

**E. Different transport: vsock or virtio-serial instead of the network.**
This only changes how B or B′ is reached. It needs an in-guest shim
(TCP ↔ vsock) and breaks ADR-0016's invariant that nothing listens for
guest-initiated vsock connections. Rejected: the TPROXY path already gives a
host-side endpoint the guest can't bypass, with no guest changes.

**F. Run the agent loop on the host and only tools in the VM.** This removes
the problem, but it means a different product shape: each agent harness would
need host integration. Out of scope.

**G. Adopt an existing gateway** (LiteLLM, agentgateway, Envoy AI Gateway,
Bifrost) as a sidecar process instead of building one. It would give us
translation and many providers. The costs: a big dependency (LiteLLM is
Python), a second config model next to `policy.toml`, and none of them knows
which VM a request comes from unless we add per-VM auth tokens, which puts a
secret back in the guest. We keep this as an **escape hatch** instead of
building on it: a provider is just a base URL, so a user can point a provider
at a LiteLLM instance running on the host (the gateway dials from the host
netns, so `localhost` works).

## Decision

Build **B′**: an inference gateway that keeps each provider's API format, runs
**in each VM's supervisor** as part of the egress proxy, and is reached at a
**reserved address that the VM's policy has to enable**. Credentials and
provider definitions stay host-side. Model aliases, and with them which models
a VM may use, are part of the VM's policy.

## Details

### Scope of the first implementation

The first pass (branch `token-gateway`) serves:

- **OpenAI-compatible Chat Completions**, for `openai` providers (OpenAI,
  OpenRouter, vLLM, Ollama's `/v1`, …) and `mistral` providers.
- **Ollama's native API**, for `ollama` providers.

The Anthropic Messages API and the OpenAI Responses API come later. So do
profile merging of `[[models]]`, the TUI gateway panel (inference events show
in the egress panel until then), and `soda provider test`.

**Routing is by path, without prefixes.** Clients keep their usual base URL,
and the path says which format they speak:

| Path | Format | Served by providers with `api =` |
|---|---|---|
| `POST /v1/chat/completions`, `GET /v1/models` | OpenAI | `openai`, `mistral` |
| `POST /api/chat`, `POST /api/generate`, `GET /api/tags` | Ollama | `ollama` |

Path prefixes (`/openai/...`) were dropped because Ollama clients take only a
host (`OLLAMA_HOST`) and call `/api/...` at the root. The model lists return
the VM's aliases, never upstream model names. When the Anthropic format is
added, its `/v1/messages` path doesn't collide with these.

### Reachability

```
guest: OPENAI_BASE_URL=http://inference.sodabox.internal/v1
       OLLAMA_HOST=http://inference.sodabox.internal
  │ DNS: inference.sodabox.internal → 10.0.2.4   (only if a rule allows it,
  │                                               else REFUSED like any name)
  ▼
passt → netns TPROXY → proxy: original dst 10.0.2.4:80
  │   dst == gateway address?  yes → in-process gateway (hyper, HTTP/1.1)
  │                            no  → PolicyDialer as today
  ▼
gateway: parse, resolve alias, check quota, strip client auth,
         inject provider auth, dial upstream from host netns (TLS), stream back
```

- **Configuring the gateway and granting access are separate steps.** A
  `[gateway]` section in `policy.toml` switches the gateway on and holds its
  settings. A `[[rules]]` entry of `kind = "service"` lets the VM reach it.
  This lets a gateway be fully configured while the VM still has no access to
  it, and access stays a rule like every other grant (ADR-0006). Without the
  rule, 10.0.2.4 is handled like any other destination not on the allowlist:
  blocked, with an event. 10.0.2.4 is never routed anywhere. **Off by
  default.**
- The upstream host does **not** need to be in the VM's allowlist. The gateway
  dials it on its own behalf. A VM that only talks to the gateway can have
  `api.mistral.ai` removed from its policy, which removes a direct path out.
- The gateway reaches providers over rustls with the **host's trust store**,
  so a self-hosted provider behind a private CA works. It follows no
  redirects, so the credential can't be carried to another host.
- In v1 the guest leg is plain HTTP/1.1, which is enough for streaming (SSE)
  over a leg that never leaves the host (guest → passt → netns). If HTTPS is
  needed later, for clients that refuse `http://` base URLs or for
  defence-in-depth, the gateway can serve TLS with a sodabox-issued
  certificate for its own name only. The guest then trusts that CA for
  `*.sodabox.internal` only: we serve that name ourselves, so this is not a
  MITM of anyone else's traffic. mTLS can be added the same way, but the
  connection already identifies the VM, so it only matters if the gateway
  ever moves out of the supervisor.
- If a client needs WebSockets (e.g. realtime APIs), the HTTP/1.1 `Upgrade` is
  passed through. That's not needed for the APIs in scope.
- **Identity comes from the connection.** A connection that arrives on VM1's
  proxy is from VM1. The guest needs no gateway token, and clients get a
  placeholder key (`sodabox`) only because the SDKs insist on one.

### Providers (host-wide, never copied into a VM)

`$XDG_CONFIG_HOME/sodabox/providers/<name>.toml`, named like profiles
(ADR-0015):

```toml
description = "Mistral La Plateforme"
api = "mistral"                        # openai | mistral | ollama
base_url = "https://api.mistral.ai/v1" # including the version path
# The secret is fetched at use and cached in memory only, never written to disk
# by sodabox. Same idea as git's credential helpers.
auth = { command = ["pass", "show", "llm/mistral"] }
```

```toml
api = "ollama"
base_url = "http://127.0.0.1:11434"    # the gateway dials from the host netns
# no auth: a local Ollama needs none
```

- `auth.command` (or `auth.env`) keeps the secret in the user's own store.
  sodabox stores no secrets, which matches ADR-0019's "don't build secret
  features". Only the first line of the command's output counts, so `pass`
  entries work as they are.
- `auth.header` defaults to `authorization` with the `Bearer` scheme. Another
  header (e.g. `x-api-key`) gets the bare credential unless `auth.scheme` says
  otherwise.
- If a provider answers 401 or 403, the cached credential is dropped, so a
  rotated key is fetched again on the next request.
- Provider files are read on every request, so edits apply without restarting
  the VM.
- A provider file holds the *how* (endpoint, auth). A VM's policy holds the
  *what* (which models). The ledger holds *how much* (token balances).

### Aliases (per VM, in `policy.toml`)

```toml
[gateway]                            # configures and switches on the gateway
enabled = true
# quota = "unlimited"                # optional: no quota for any alias on this VM

[[rules]]                            # grants this VM access to it
kind = "service"
name = "inference"

[[models]]
alias = "big"                        # what the guest sends as "model"
provider = "mistral"
model = "mistral-large-latest"       # what goes upstream
initial_quota = 0                    # optional: balance on first use (default 0)

[[models]]
alias = "foo:13b"
provider = "local"
model = "the_actual_foo:13b"
quota = "unlimited"                  # optional: no quota for this alias
```

- Aliases are an **allowlist**: a model name with no alias is rejected (404
  in the client's API format, plus a `Blocked` event). There is no raw
  pass-through. The aliases are exactly the set of models (and costs) the VM
  can reach.
- An alias only resolves to a provider with the same API format as the
  incoming route. Crossing formats is an error in v1; the workaround is the
  LiteLLM escape hatch above.
- This lives in `policy.toml` for the same reasons as ADR-0015: one auditable
  file per VM, comment-preserving edits, live updates through
  `PolicySet` (the supervisor swaps the alias table the way it swaps the
  allowlist), and profiles can carry `[[models]]` tables. A `claudecode-gw`
  profile then replaces the direct-egress `claudecode` profile.
- Exact matching only in v1. Globs (`foo:*`) can come later if needed.

### Token quotas

Each VM has a token **balance per alias**. The user grants tokens to it and
requests use them up. There are no time windows (per day, per minute), no cap
on a single request, and no money (see *Not in scope: money*).

- **Balances are state, not policy.** They live in an append-only ledger in
  the VM's data dir, `$XDG_DATA_HOME/sodabox/<vm>/quota.jsonl`, which the guest
  can't reach:

  ```
  {"ts":…, "alias":"big",     "delta":0,       "reason":"initial"}
  {"ts":…, "alias":"big",     "delta":2000000, "reason":"grant"}
  {"ts":…, "alias":"big",     "delta":-48211,  "reason":"usage", "tokens":48211}
  {"ts":…, "alias":"foo:13b", "delta":0,       "reason":"unmetered", "tokens":9120}
  ```

  The balance is the sum of the deltas. The ledger is the audit trail of what
  was granted and used. Balances survive restarts, so restarting a VM never
  refills it.
- **Initial balance:** the first request for an alias writes an `initial`
  entry with the alias's `initial_quota` (0 if not set).
- **Top-up:** `soda quota grant <alias> <tokens>` (later also a hotkey in the
  TUI). The CLI appends the grant to the ledger and, if the VM is running,
  asks the supervisor to re-read it (`QuotaReload`), so the new balance applies
  at once. Each entry is a single append to an `O_APPEND` file, so the CLI and
  the supervisor never interleave lines. Grants can be made before the VM
  first uses the alias.
- **What counts:** input + output tokens (output includes reasoning), minus
  cache reads. Cache reads are tracked and shown, but don't use up quota.
  Agents re-send their cached context every turn, so counting it would make
  quotas drain at a rate that has little to do with the work done. (Cache
  writes, which only the Anthropic API reports, will be tracked with that
  format.)
- **The balance belongs to the alias.** Re-pointing an alias to another
  provider or model keeps its balance. Removing an alias keeps its history in
  the ledger, and adding it back continues from the old balance.
- **Unlimited:** `quota = "unlimited"` turns off the quota for one alias
  (`[[models]]`) or for every alias on the VM (`[gateway]`). The VM-wide
  setting wins. It's policy, not ledger state: it's auditable in
  `policy.toml`, can come from a profile, and changes live via `PolicySet`.
  - Usage is still tracked and logged, but marked unmetered and **not**
    subtracted from the balance. The balance stays where it was.
  - Switching back to limited continues from that balance, so a period of
    unlimited use never leaves a large negative balance behind.
  - `initial_quota` and grants still work while unlimited and apply once the
    alias is limited again.
- **Enforcement:** a request is let through if its alias is unlimited or its
  balance is above zero. The usage is booked when the request finishes. With
  no cap on a single request, one that starts with tokens left can take the
  balance **below zero**. It is never cut off mid-stream; the next request is
  refused. The overshoot is at most one response per request in flight.
  That's accepted.
- **When the quota is used up**, the gateway returns the error each API's own
  clients treat as "out of credit, don't retry", so the agent shows it
  instead of retrying:
  - OpenAI-compatible: `429`, `code: insufficient_quota`. A plain 429 would
    be retried with backoff; this code is not.
  - Ollama: `403` with a plain `error` string. Ollama has no quota error of
    its own, and a 429 could be retried.
  - Anthropic (when added): `400`, `type: invalid_request_error` (the shape of
    Anthropic's own "credit balance too low" error).

  The message says what to do: `sodabox: token quota for 'big' on VM 'vm1' is
  used up. Grant more on the host: soda quota grant big <tokens> --vm vm1`. A
  `QuotaExhausted` event shows it in the TUI too.

### Not in scope: money

sodabox counts tokens, not money. Calculating cost needs a price for each
model and each kind of token. Those prices change without notice, there's no
API to look them up, and only the provider's bill is authoritative. Spend
limits belong at the provider (workspace or project spend caps, OpenRouter key
credit limits). Anyone who wants costs can compute them from the token counts
in the event log.

### Request handling

- Upstream headers are built fresh: `content-type`, the client's `accept`, and
  the provider's auth header. Nothing else from the client is forwarded, so
  its auth headers (`authorization`, `x-api-key`, …) never reach a provider.
- Rewrite only `model` in the JSON body (plus the stream-usage option below).
  Stream the response through without buffering.
- Read token usage from each API's own reporting:
  - **Chat Completions:** the `usage` object, on the last chunk of a stream.
    OpenAI only sends it when the request sets `stream_options.include_usage`,
    so the gateway sets it for `openai` providers, or streamed requests would
    go uncounted.
  - **Mistral:** sends usage on its last chunk without being asked, so its
    requests are left as they are.
  - **Ollama:** `prompt_eval_count`/`eval_count` on the `done: true` object.
  - **Non-streamed responses:** the same fields in the body.
  - **Later formats:** Anthropic reports input and cache usage in
    `message_start` and output in `message_delta`; OpenAI Responses in
    `response.completed`.
- A client that disconnects mid-stream is still billed by the provider. The
  gateway books the usage seen so far and marks the request incomplete.
- This is a new parser exposed to the guest, so it gets the same care as the
  proxy:
  - request bodies are capped at 32 MiB;
  - clients get 30 s to send their headers;
  - a provider may stay silent for up to 10 minutes mid-response (reasoning
    models think before the first token);
  - at most 8 requests per VM are in flight, and more wait.
- Upstream error bodies are passed on with their status, cut to one line, with
  the credential redacted (some providers echo part of the key).
- Events: `Event::Inference { ts, verdict, api, alias, provider, model,
  status, tokens { input, output, reasoning, cache_read }, complete,
  latency_ms }` and `Event::QuotaExhausted { ts, alias }`. Metadata only.
  Prompts and completions are **never** logged.

### CLI / TUI

```
soda provider ls | show <name>             # `test <name>` comes later
soda model ls [--vm <vm>]
soda model add <alias> <provider>/<model> [--initial-quota N] [--vm <vm>]
soda model rm <alias> [--vm <vm>]
soda quota show [--vm <vm>]
soda quota grant <alias> <tokens> [--vm <vm>]   # e.g. 2M
soda quota unlimited [<alias>] [--vm <vm>]      # no alias: the whole VM
soda quota limited [<alias>] [--vm <vm>]
soda gateway enable|disable [--vm <vm>]   # the [gateway] section
soda allow service inference [--vm <vm>]  # the access rule
soda deny inference [--vm <vm>]           # removes the access rule
```

- A **Gateway panel** in the existing per-VM `soda tui` (ADR-0009): recent
  requests (alias → provider/model, status, tokens, latency) and the alias
  table with each alias's balance (`∞` when unlimited). Hotkeys add, re-point
  or remove an alias, grant tokens, and switch unlimited on or off. Alias
  edits use the same persist-then-push path as allow/deny; grants go to the
  ledger.
- The cross-VM overview (`soda tui` with no VM, already planned) fans out over
  control sockets. It shows token usage and balances per VM, with used-up
  quotas highlighted.
  **No separate gateway TUI.**

### Why one gateway per VM, not one shared gateway

A single gateway would give us:
1. one overview;
2. quotas shared across VMs;
3. one place that unlocks credentials;
4. shared upstream connection pools;
5. a single writer for rotating OAuth refresh tokens.

(1) is already solved by fan-out (ADR-0007). (4) doesn't matter at agent
request rates. (3) is handled by `auth.command` plus an in-memory cache. That
leaves (2) and (5) as real reasons. Against them, a shared gateway would be
the first always-running process (ADR-0007 rejected a daemon). It would need
to know *which VM* sent each request, which means per-VM tokens in the guest
or per-VM sockets back into the supervisor anyway. And a crash would take down
every VM's inference instead of one.

So: one gateway per VM now. Quotas are per VM by design (the user grants
tokens to a VM), so (2) isn't needed. If OAuth or shared quotas become
requirements, add a small **host credential broker** that the per-VM gateways
call to get credentials and record usage. That broker would hold secrets and
counters but no guest-facing surface, which is the part worth sharing.

## Consequences

- **Positive:**
  - Inference keys never enter a VM.
  - Which models a VM may use is part of its auditable policy, and how many
    tokens it was granted and has used is in an auditable ledger.
  - When a quota runs out, the agent shows a clear error that says how to
    grant more, instead of failing silently.
  - Provider and model changes happen on the host, with no edits inside the
    VM.
  - No MITM. v1 needs no guest trust-store changes, and later TLS would only
    cover the gateway's own name.
  - It reuses the proxy, DNS filter, control socket, event stream and TUI
    that already exist.
  - Direct egress to provider APIs can be dropped from VM policies.
- **Negative / costs:**
  - It adds a guest-facing HTTP parser on the host.
  - Clients must be pointed at the gateway with environment variables or
    agent config. A guest Nix module or dotfile collection can set these.
  - Each API format is a separate route family to maintain.
  - No translation between API formats.
  - Quotas are in tokens, per VM and per alias. There are no dollar figures,
    so spend caps must be set at the provider.
  - A request can push a balance below zero, by up to one response per
    request in flight.
  - Quotas are topped up by hand. A VM left alone stops when its quota runs
    out, which is intended. Where that isn't wanted, the VM or alias is set
    to unlimited, and provider-side caps are the only limit left.
- **Risks & open questions:**
  - **Subscription/OAuth logins** (Claude.ai, ChatGPT) are out of scope for
    v1, which supports only API keys. Later support doesn't need DPI, because
    the client already talks to the gateway. It does need provider-specific
    auth handling, refresh tokens that rotate safely across VMs, and a check
    of the providers' terms.
  - **Not yet verified on a live VM:** that passt forwards guest connections
    to 10.0.2.4, an address inside its own guest subnet, into the netns where
    TPROXY catches them. If it doesn't, the gateway moves to an address outside
    10.0.2.0/24; it is a single constant in the supervisor.
  - Do all target clients accept an `http://` base URL? If one doesn't, use
    the TLS option above. (Path prefixes are gone, see *Scope of the first
    implementation*.)
  - The quota-exhausted errors are chosen so that agents show them instead of
    retrying. Not yet verified per agent (Mistral Vibe, Ollama clients, …).
  - Mistral is assumed to report usage on its last stream chunk without
    `stream_options` (as its API reference shows). If it doesn't, streamed
    Mistral requests are booked with zero tokens; a live request will tell.
  - Building rustls's `ring` backend needs a C compiler. The dev shell and the
    Nix build provide one; a bare `cargo build` outside them does not.
  - Non-inference APIs (GitHub, package registries, AWS) are out of scope
    here and need their own ADR.

## Alternatives considered

See *Options* above. In short: A (DPI injection) is fragile and blind to
models. C (sealed tokens) is generic but blind to models and unsupported by
agent CLIs. D (scoped keys) still puts a key in the guest, though it's worth
using alongside. E (vsock) changes only the transport and breaks ADR-0016's
invariant. F (agent on host) is a different product. G (adopt LiteLLM and
similar) costs a large dependency, a second config model and per-VM tokens; it
stays an escape hatch as a provider URL. Of the B variants, a single
OpenAI-compatible front end was rejected because native agent CLIs need their
own APIs.

- **Embedding agentgateway (as a library or a bundled binary).** It's built as
  a full gateway product (Kubernetes, MCP and agent-to-agent routing, a policy
  language). It is much larger than B′ needs and isn't meant to be used as a
  library, and as a separate process it has the problems listed under G.
  Rejected as a dependency. We use it as a **reference** for each API's
  details (auth headers, how usage is reported in streams, error shapes).
  Users can still run it themselves behind a provider URL.
