# ADR-0015: Policy profiles

- **Status:** Accepted
- **Date:** 2026-10-23
- **Deciders:** Project team
- **Supersedes / Superseded by:** — (amends [ADR-0006](0006-allowlist-model.md))

## Context

Most VMs run one or more coding agents, and each agent needs the same few
endpoints: Claude Code needs `api.anthropic.com` plus its login hosts, Mistral
tools need `api.mistral.ai`, and so on. Typing these in with `sodabox allow` for
every VM is tedious and error-prone, and the resulting `policy.toml` doesn't
record why a rule is there. The policy must stay auditable: looking at one VM's
`policy.toml` should show exactly what that VM may reach, and why.

## Decision

A **profile** is a named set of allow rules in
`$XDG_CONFIG_HOME/sodabox/profiles/<name>.toml`. sodabox ships **vendor**
profiles and keeps them current there. Users add their own files next to them.
Profiles are **merged into** a VM's `policy.toml`, at `create --profiles a,b` or
later with `sodabox profile add a,b`. Each merged rule is preceded by a
`# from profile '<name>'` comment. All policy edits preserve comments, so that
provenance survives later edits.

## Details

### Profile format

```toml
description = "Claude Code: Anthropic API and account login"

# Claude API requests.
[[rules]]
kind = "domain"
name = "api.anthropic.com"
scope = "exact"
ports = "443"
proto = "tcp"
```

- The same `[[rules]]` tables as `policy.toml` (ADR-0006), plus an optional
  `description`. No `version` or `limits`: those belong to the VM. Unknown keys
  are rejected, so a stray `version` or a typo fails instead of being ignored.
- Every rule is validated with the allowlist's own parsers when the profile
  loads. One bad rule rejects the whole profile.
- Names are `[a-z0-9][a-z0-9_-]*` (≤ 64 chars). A name becomes a file name, so
  this also stops `--profiles ../x` from escaping the profiles dir.
- No includes, for now.

### Vendor profiles

- Shipped in the repo's `profiles/` and embedded into the binary
  (`include_str!`, like the guest input of ADR-0012): `claudecode`, `github`,
  `mistral`, `nixpkgs`, `openai`. The agent profiles allow only exact hosts on
  `tcp:443`; optional telemetry, error reporting and auto-updaters are left out.
  `github` and `nixpkgs` allow their hosts and subdomains on any port (for
  `github`, that lets git over SSH work too).
- **sodabox owns these files.** Before any command that reads profiles, a vendor
  file that is missing or differs from the shipped copy is rewritten atomically,
  and a warning is printed if local changes were discarded. Each file's header
  says so and tells the user to copy it under a new name to customise it.
- A user file with a vendor name is overwritten. `sodabox profile ls` labels each
  profile `vendor` or `user`. A vendor profile a later release stops shipping is
  left in place, since it can't be told apart from a user file.

### Merging

- Profiles merge in the order given. A rule the policy already contains (equal in
  every field) is skipped, so applying a profile twice is a no-op, and overlapping
  profiles don't duplicate rules. The first occurrence keeps its provenance
  comment.
- A merged rule is copied **as written in the profile**: its comments and
  formatting come along, with `# from profile '<name>'` added above it. The
  profile file's header (the comment before `description`) is not copied.
- The merged policy is validated (compiled to an allowlist) before anything is
  written. `create` resolves and merges profiles before any side effect, so an
  unknown profile creates nothing. `create --profiles` on a VM that already has a
  `policy.toml` is an error pointing at `profile add`.
- `profile add` goes through the same persist-then-push-live path as
  `sodabox allow`: version bump, `PolicySet` to a running supervisor.
- **Snapshot semantics:** a VM's policy holds copies of the rules. Changing or
  updating a profile later doesn't affect VMs it was already applied to. That's
  what keeps each `policy.toml` a complete, self-contained record.

### Comment-preserving policy edits

`policy.toml` used to be rewritten from the parsed struct on every save, which
dropped all comments. Now every writer goes through `PolicyFile`, a
format-preserving `toml_edit` document: `allow`, `deny`, the TUI's quick
actions, `policy edit`, `create` and `profile add`. An edit touches only what it
changes:

- adding a rule appends a `[[rules]]` table;
- removing one drops its table together with the comments attached to it;
- the version bump rewrites only the `version` value (keeping a trailing comment).

`policy show` prints the file as written. The enforced `VmPolicy` is always
parsed from the document, so there is no second representation to drift.

### Reserved VM names

The config dir holds one `<vm>/` per VM next to the shared `guest/` and
`profiles/` dirs, so `create` refuses the VM names `guest` and `profiles`.

### CLI

```
sodabox create <vm> --profiles claudecode,mistral
sodabox profile ls
sodabox profile show <name>
sodabox profile add <name>[,<name>…] [--vm <vm>]
```

## Consequences

- **Positive:** common agent setups take one flag; each `policy.toml` says
  exactly what is allowed and which profile it came from; hand-written
  comments in `policy.toml` now survive every edit; vendor endpoint lists can be
  fixed in a release without users hand-editing files.
- **Negative / costs:** a fix to a vendor profile doesn't reach existing VMs; the
  user has to re-apply it (the merge adds only what's missing). Rules shared by two
  profiles carry only the first one's provenance comment.
- **Risks & open questions:**
  - Vendor endpoint lists are taken from each vendor's published network
    requirements (as of 2026-10) and can go stale.
  - No `profile remove` yet. Removing by provenance comment would also drop a
    rule that a second profile needs but didn't tag.
  - Vendor rules pin `proto = "tcp"`, so HTTP/3 (QUIC over udp/443) is blocked.
    Clients fall back to TCP.

## Alternatives considered

- **A `profile` field on each rule** for provenance. Structured, and it would
  make `profile remove` easy, but it puts provenance into the enforcement model
  and the control protocol. Rejected in favour of comments, which need the
  file to be edited in place anyway, and in place is what users expect when
  they annotate their policy by hand.
- **Reference profiles from the policy and resolve them at load (live
  linking).** Rejected: the effective policy would depend on files outside the
  VM's data dir and change silently when a profile changes, which defeats
  auditing.
- **Never overwrite vendor files** (like the guest input, ADR-0012). Rejected:
  vendor endpoint lists need to be fixable by a release, and user customisation
  is a copy away.
