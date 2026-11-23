# Adds `sodabox` to a nixpkgs package set, built against that set.
# Usable without flakes, e.g.:
#   nixpkgs.overlays = [ (import /path/to/sodabox/nix/overlay.nix) ];
final: _prev: {
  sodabox = final.callPackage ./package.nix { };
}
