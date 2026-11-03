# This VM's guest configuration — this file is YOURS (ADR-0012).
#
# `soda create` writes it once per VM, to <config-dir>/guests/<vm>/, and never
# rewrites it. It layers on top of the shared guest configuration, so:
#
#   - "all VMs" settings go in the shared <config-dir>/shared/configuration.nix
#     (imported below);
#   - "this VM" settings go here.
#
# nixpkgs comes from ./npins, which points at the shared pins by default.
# Replace the symlink with a real npins dir to pin this VM separately.
{ ... }:
{
  imports = [ ../../shared/configuration.nix ];

  # Chosen by `soda create --hostname name|static|random`; edit freely.
  networking.hostName = "@HOSTNAME@";
}
