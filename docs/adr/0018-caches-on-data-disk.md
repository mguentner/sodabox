# ADR-0018: Tool caches on the data disk

- **Status:** Accepted
- **Date:** 2026-10-25
- **Deciders:** Project team
- **Supersedes / Superseded by:** Amends [ADR-0014](0014-persistence-modes.md)
  (guest layout)

## Context

ADR-0014 puts all of `/root` on the home disk, which is 1G by default, so that
tool config survives in `home` mode. But `/root` also holds the caches of
package managers and toolchains: `~/.cargo/registry`, `~/go/pkg/mod`, the pnpm
store, `~/.cache` and so on. A few builds fill the home disk. This happens in
every mode, not only `home`. In `home` mode it also undoes the point of the mode:
a stopped VM keeps paying for caches that can be rebuilt.

`/root` therefore holds two kinds of data with opposite needs: small config
that should be kept, and large caches that can be thrown away.

## Decision

Bind a fixed, user-extensible list of known cache directories under `/root`
from the data disk (`/persistent/cache/<dir>` → `/root/<dir>`). Everything else
in `/root` stays on the home disk.

## Details

- `nix/guest/cache-dirs.nix` (imported by `base.nix`) defines
  `sodabox.cacheDirs`, a list of paths relative to `/root`. The default:
  `.cache`, `.cargo/registry`, `.cargo/git`, `.rustup/toolchains`,
  `.rustup/downloads`, `go/pkg/mod`, `.npm`, `.local/share/pnpm/store`,
  `.bun/install/cache`, `.gradle/caches`, `.m2/repository`.
- Only the cache parts of a tool's directory are listed, never the whole
  directory: `~/.cargo/config.toml` and `credentials.toml`, rustup's
  `settings.toml`, and so on stay on the home disk.
- Each entry becomes a `fileSystems` bind with `nofail`, nested under the
  `/root` bind. systemd orders a mount after the mounts of its parent paths.
- The bind sources are created in stage 1 by `persistent-layout`, for the same
  reason the rest of the layout is (ADR-0014): tmpfiles would run too late, and
  the `nofail` bind would fail silently. systemd creates the mount points itself.
- Users extend the list in their guest `configuration.nix` (ADR-0012), e.g.
  `sodabox.cacheDirs = options.sodabox.cacheDirs.default ++ [ ".foo/cache" ];`,
  or replace it.

Resulting behaviour per mode (ADR-0014):

| `persist` | caches |
|---|---|
| `full` | kept (data disk) |
| `home` | dropped at stop |
| `none` | dropped at stop |

## Consequences

- **Positive:**
  - The home disk only grows with real config, so the 1G default is enough.
  - A stopped `home` VM costs roughly the size of its config again.
  - Works for every shell and process (login or not, ssh commands, rsync),
    because it changes no environment variables. Tools can't replace or delete
    the mount the way they can a symlink.
  - The guest layout stays mode-agnostic.
- **Negative / costs:**
  - The list needs maintenance. A cache that isn't on it still lands on the home
    disk. That failure is loud (disk full) and is fixed with one line.
  - In `home`/`none`, caches are rebuilt after every restart (more downloads).
  - Removing a cache directory itself (`rm -rf ~/.cache`) fails with `EBUSY`.
    Its contents are still removed.
- **Risks & open questions:**
  - Listing a directory that holds config (not only cache) loses that config in
    `home` mode. The option description warns about this.

Covered by `nix/tests/persist-modes.nix`: the cache binds sit on `/dev/vdc`, and
a marker in `~/.cache` survives a `full` restart but not a `home` one.

## Alternatives considered

- **Environment variables** (`CARGO_HOME`, `GOMODCACHE`, `npm_config_cache`, …).
  Rejected: some are too coarse (`CARGO_HOME` also holds config and
  credentials), they only reach every shell if set through pam_env, and each tool
  needs its own variable.
- **Symlinks** into the data disk. Rejected: some tools replace or delete a
  symlinked directory, and the links would have to be recreated every boot.
- **Allowlisting config instead** (`/root` on the data disk, known config paths
  bound from the home disk, impermanence style). Rejected: a missing entry
  silently loses config in `home` mode, which is worse than a full disk. ADR-0014
  already rejected per-dotfile lists for the home.
- **nix-community/preservation** for the binds. It fits, but adds an external
  dependency to the trusted base module for about a dozen mounts. Its source
  paths mirror the target path, and it would need `nofail` added through
  `commonMountOptions`.
- **A larger home disk.** It doesn't fix the problem: in `home` mode the
  caches would then be kept.
