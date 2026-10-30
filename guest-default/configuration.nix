# Default sodabox guest configuration — this file is YOURS.
#
# sodabox materializes this into your config dir; edit it to shape what the
# guest contains (packages, services, users). sodabox owns *how* the guest is
# built and booted (kernel, store image, launch) — see ADR-0012. Update the
# pinned nixpkgs with `npins update` in this directory.
#
# This is the "all VMs" layer: each VM's own <config-dir>/<vm>/guest/
# configuration.nix imports it and adds that VM's settings (e.g. its hostname).
# Use lib.mkDefault here for anything a VM layer should be able to override.
{ pkgs, ... }:
let
  sources = import ./npins;
  # Agent tools from github:numtide/llm-agents.nix. It's a flake, so bridge it
  # into this non-flake eval with getFlake (its store-path context must be
  # discarded for getFlake to accept it), then take its `packages.<system>`
  # set — which exposes each tool at top level (e.g. `llm-agents.claude-code`).
  #
  # We deliberately use the flake's packages rather than its `shared-nixpkgs`
  # overlay: the overlay would nest everything under `pkgs.llm-agents.*` (to
  # avoid clobbering ~150 names into `pkgs`), which reads confusingly next to a
  # `let` binding of the same name. This way `llm-agents` is just a package set
  # you index directly, and its tools come prebuilt against llm-agents' own
  # pinned nixpkgs (so its binary cache applies).
  llm-agents =
    (builtins.getFlake (builtins.unsafeDiscardStringContext sources."llm-agents.nix".outPath))
    .packages.${pkgs.stdenv.hostPlatform.system};
in
{
  environment.systemPackages = with pkgs; [
    coreutils
    bashInteractive
    # Uncomment to include Claude Code (or any other llm-agents.nix tool) in
    # the guest — `llm-agents` is the package set bound above:
    # llm-agents.claude-code
  ];

  # Tool state needs nothing here: base.nix binds the whole of /root out of the
  # home disk (ADR-0008/0014), so ~/.config, ~/.claude, ~/.gitconfig and
  # whatever the next tool invents all survive a reboot on their own. Your work
  # tree lives in /var/work, which is where a login lands and where sync writes.
  system.stateVersion = "24.11";
}
