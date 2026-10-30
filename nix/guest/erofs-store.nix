# Build a read-only erofs image of a guest closure's /nix/store (ADR-0008,
# spike 0004). Attached as /dev/vda and mounted at /nix/.ro-store; the base
# module overlays `store/` onto /nix/store.
#
# Image layout (mounted at /nix/.ro-store):
#   store/                 the closure's store paths (overlay lowerdir → /nix/store)
#   nix-path-registration  closureInfo's DB dump, loaded via `nix-store --load-db`
#                          at boot so the guest Nix DB knows these paths are valid.
#                          Kept OUTSIDE store/ so it never appears
#                          in /nix/store. Without it GC treats the whole store as
#                          unregistered garbage and nix-collect-garbage wipes it.
{
  stdenvNoCC,
  erofs-utils,
  closureInfo,
  toplevel,
  compression ? "lz4",
}:
let
  ci = closureInfo { rootPaths = [ toplevel ]; };
in
stdenvNoCC.mkDerivation {
  name = "sodabox-guest-store.erofs";
  nativeBuildInputs = [ erofs-utils ];
  buildCommand = ''
    mkdir -p root/store
    while read -r p; do
      cp -a "$p" root/store/
    done < ${ci}/store-paths
    cp ${ci}/registration root/nix-path-registration
    mkfs.erofs -z${compression} "$out" root
  '';
}
