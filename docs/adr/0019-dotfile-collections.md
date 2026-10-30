# ADR-0019: Dotfile collections

- **Status:** Accepted
- **Date:** 2026-10-25
- **Deciders:** Project team
- **Supersedes / Superseded by:** — (extends the config disk of [ADR-0011](0011-ssh-and-sync.md))

## Context

Every new VM starts with an empty `/root` (ADR-0014), so each coding agent has
to be set up again by hand: `~/.claude/settings.json`, an agent's provider
config, a `~/.gitconfig`. The same few setups recur (Claude Code, Claude Code
via Bedrock, pi with Mistral, …) and should take one flag, like policy profiles
do for the allowlist (ADR-0015).

Some of these setups need credentials, e.g. an API key or an AWS profile. Any
file that passes through Nix ends up in the host's `/nix/store`, which every
host user can read, and in the guest's store image. So credentials must not go
through Nix.

The home disk is formatted by the guest (ext4, `x-systemd.makefs`), so the
rootless host can't write files onto it. The only host→guest file channel is
the read-only config disk, which is rebuilt at every launch (ADR-0011).

## Decision

A **collection** is a folder under `$XDG_CONFIG_HOME/sodabox/dotfiles/<name>/`
holding files for `/root`. `soda create <vm> --dotfiles a,b` merges the
named collections in order and copies the result into the VM's data dir (later
collections win, and every conflict prints a warning). Every start ships that
copy to the guest on the config disk. A guest service copies it into `/root`
once, never overwriting existing files.

**Plain files never touch the Nix store**, so they may hold credentials. A
collection may also have a `default.nix` that generates files. It is evaluated
by Nix and must never contain or read secrets.

## Details

### Collection format

```
$XDG_CONFIG_HOME/sodabox/dotfiles/
  claudecode/
    .claude/settings.json        # plain file → /root/.claude/settings.json
    .claude/CLAUDE.md
  claudecode_aws/
    .aws/config                  # plain, may hold credentials (keep it 0600)
    default.nix                  # optional, generated files
```

- **Plain files:** everything in the folder except a top-level `default.nix`
  is copied to the same path under `/root`, keeping its mode bits (`0600`
  stays `0600`). Only regular files and folders are allowed. A symlink, device
  or socket fails the collection, so a link can't pull in files from elsewhere
  on the host.
- **Generated files:** `default.nix` is a function
  `{ lib }: { "<path under /root>" = { text = "…"; mode = "0644"; }; … }`
  (`mode` is optional, default `0644`, and no other keys are accepted). `lib`
  comes from the shared guest's pinned nixpkgs (ADR-0012), so
  `lib.recursiveUpdate`, `lib.generators` and `builtins.toJSON` are there to
  build config files. sodabox only **evaluates** it
  (`nix-instantiate --eval --strict --json`, with the evaluator `nix/dotfiles.nix`
  embedded in the binary) and writes the text itself. Nothing is built. Two
  rules:
  - Text that refers to a store path (string context, e.g. `"${./x}"`) is
    rejected. Such a path is not necessarily in the guest's store image and
    would dangle inside the VM. There's no `pkgs` either: put a package into
    the guest `configuration.nix` and refer to it by name (`foo` on `PATH`).
  - **No secrets.** The collection's `default.nix` is read by Nix, and a path
    interpolated into a string (`"${./x}"`) is copied into the world readable
    `/nix/store` before the check above can refuse it. Credentials stay plain
    files.
- A path supplied by both the plain files and the `default.nix` of one
  collection is an error.
- Names follow the profile rule (ADR-0015): `[a-z0-9][a-z0-9_-]*`, ≤ 64 chars.
  Paths must be relative, without `..`.
- `dotfiles` joins `guest` and `profiles` as a reserved VM name, since the
  config dir holds one `<vm>/` folder per VM next to these shared ones.

### Merging and snapshot

- `create --dotfiles a,b` merges in the order given. If two collections supply
  the same path, the later one wins and sodabox warns, e.g.
  `dotfiles: .claude/settings.json from 'claudecode' replaced by 'claudecode_aws'`.
  An unknown collection or an invalid one fails `create` before any side effect,
  like an unknown profile.
- The merged tree is written to `$XDG_DATA_HOME/sodabox/<vm>/dotfiles/` (0700),
  and the collection names go into `meta.toml` as a record.
- **Snapshot semantics** (as for profiles): changing a collection later doesn't
  affect VMs that were already created. The VM's `dotfiles/` folder is its own
  copy, and you can edit it before the first start. There is no re-apply
  command.

### Delivery to the guest

- At every start the supervisor stages the VM's `dotfiles/` folder into the
  config disk under `dotfiles/`. erofs keeps the mode bits, `--all-root` makes
  every file root-owned, and the image file is 0600 on the host (ADR-0011).
- The guest service `sodabox-dotfiles` runs after the `/root` bind and before
  `sshd`. If `/persistent/home/sodabox/dotfiles-provisioned` is missing, it
  copies `/run/sodabox/dotfiles/` into `/root` without overwriting existing
  files, then writes the marker.
- Per persistence mode (ADR-0014): `full` and `home` keep the home disk, so the
  copy happens once and the files belong to the VM from then on. A `none` VM's
  home disk is scratch, so it gets them again at every boot.

## Consequences

- **Positive:**
  - A setup takes one flag. A collection of plain files needs no Nix at all at
    `create`.
  - Credentials never enter the Nix store.
  - Dotfiles don't change the guest image, so editing them never rebuilds it.
  - Conflict warnings show up once, at `create`, in the CLI.
  - Each VM's `dotfiles/` is an exact record of what it was given.
- **Negative / costs:**
  - Credentials are copied into every VM's data dir that uses them. They're
    deleted with the VM, and the data dir is private to the user.
  - Inside the guest, `/run/sodabox/dotfiles` stays readable while the VM runs.
    That reveals nothing new: the same files are in `/root`, and the guest is
    meant to have them.
  - A fix to a collection doesn't reach existing VMs.
- **Risks & open questions:**
  - A `default.nix` can still read a secret into the store against the rules.
    sodabox can't detect that, so the docs and the collection header have to
    say it clearly.
  - The config disk grows with the dotfiles. Collections are expected to be
    small (kilobytes), so there's no size limit for now.

## Target state: credentials stay out of the VM

**Putting credentials into the VM is a stopgap, not the goal.** A VM runs
untrusted agent code (ADR-0001), and anything inside it can be read and sent
out through any host the policy allows. The goal is for the egress proxy
(ADR-0004) to **inject credentials**:
- For hosts that have a credential, the proxy terminates TLS with a per-VM CA
  that the guest trusts.
- It adds the API key or auth header on the host side.
- The guest only ever has a placeholder.

This ADR does not design that.

Until then, credential handling here stays deliberately minimal: a plain file
copied once, nothing else. **Don't add** secret-specific features to dotfiles,
e.g.:
- encryption at rest,
- secret stores or keyring integration,
- per-file secret flags,
- rotation,
- templating secrets into generated files,
- re-sync of changed secrets.

Each of these would be work on a path the proxy is meant to replace. Changes
that make dotfiles better *as config* are fine.

## Alternatives considered

- **Build the collections into the guest image (a NixOS module in `mkGuest`)**:
  - Pros: conflicts become NixOS `warnings`, and generated files could refer
    to guest packages.
  - Cons: every file, credentials included, would land in the store and the
    store image, and every dotfile change would rebuild the image.
  - Rejected.
- **A separate `secrets/` folder per collection on the config disk, the rest
  via Nix:** two delivery paths where one does it. With "plain files never
  touch the store", the split adds nothing. Rejected.
- **home-manager:**
  - It's a large dependency.
  - Its files are read-only symlinks into the store, which breaks agents that
    rewrite their own config (`~/.claude.json`, `settings.json`).
  - Users can still use it in their own `configuration.nix`.
  - Rejected.
- **Live links (read the collections at every start):** a VM's setup would
  change without notice when a collection changes, and `none` VMs would differ
  from `full` ones. Snapshot semantics match profiles. Rejected.
- **Vendor collections shipped by sodabox (like vendor profiles):** not for
  now. They can be added later without changing this design.
