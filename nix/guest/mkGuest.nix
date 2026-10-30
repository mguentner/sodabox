# sodabox-owned guest build function (ADR-0012). This defines *how* a guest is
# built; the user supplies only the inputs (a guest dir with `configuration.nix`
# and npins-pinned `nixpkgs`). The Rust CLI invokes this with an impure
# `nix-build`, passing the guest dir.
#
#   nix-build nix/guest/mkGuest.nix --argstr guestDir <dir> -A kernel
#   nix-build nix/guest/mkGuest.nix --argstr guestDir <dir> -A store   # erofs image
#
# `nixpkgs` may be overridden (testing / `--override`); by default it comes from
# the guest's npins.
{
  guestDir,
  system ? builtins.currentSystem,
  nixpkgs ? null,
}:
let
  npinsPath = guestDir + "/npins";
  sources = if nixpkgs == null && builtins.pathExists npinsPath then import npinsPath else { };
  nixpkgsPath =
    if nixpkgs != null then
      nixpkgs
    else if sources ? nixpkgs then
      sources.nixpkgs
    else
      throw "mkGuest: no nixpkgs — provide the guest's npins or pass --arg nixpkgs";

  configuration = guestDir + "/configuration.nix";

  # sodabox owns the base module (the non-negotiable "how"); the user's
  # configuration.nix is layered on top.
  eval = import (nixpkgsPath + "/nixos/lib/eval-config.nix") {
    inherit system;
    modules = [
      ./base.nix
      configuration
    ];
  };

  cfg = eval.config;
  pkgs = eval.pkgs;

  toplevel = cfg.system.build.toplevel;
  kernel = cfg.system.build.kernel;
  initrd = cfg.system.build.initialRamdisk;

  # Read-only /nix/store image of the guest's closure (spike 0004). Built by a
  # sodabox-owned derivation so it is reproducible and cached.
  store = pkgs.callPackage ./erofs-store.nix { inherit toplevel; };
in
{
  inherit
    toplevel
    kernel
    initrd
    store
    ;
  # Convenience passthru for the launcher.
  kernelPath = "${kernel}/bzImage";
}
