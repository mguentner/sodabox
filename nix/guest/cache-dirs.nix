# Tool caches under /root, moved off the home disk (ADR-0018). Imported by
# base.nix.
#
# /root lives on the small home disk (ADR-0014) because it holds the tool
# config worth keeping. Package managers also write their caches there, and
# those fill the disk quickly. Each directory listed in `sodabox.cacheDirs` is
# bound from the data disk instead:
#
#   /persistent/cache/<dir>  → bind → /root/<dir>
#
# So caches follow the data disk: kept in `full`, scratch in `home`/`none`. The
# guest still never knows the mode. Users extend the list in their
# configuration.nix (`sodabox.cacheDirs = options.sodabox.cacheDirs.default ++
# [ … ]`) or replace it.
{ config, lib, ... }:
let
  cfg = config.sodabox;
in
{
  options.sodabox.cacheDirs = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [
      ".cache" # XDG cache: pip, uv, go build cache, nix eval cache, …
      ".cargo/registry"
      ".cargo/git"
      ".rustup/toolchains"
      ".rustup/downloads"
      "go/pkg/mod"
      ".npm"
      ".local/share/pnpm/store"
      ".bun/install/cache"
      ".gradle/caches"
      ".m2/repository"
    ];
    description = ''
      Directories under /root that hold rebuildable caches. Each one is bound
      from /persistent/cache/<dir> on the data disk, so it neither fills the
      home disk nor is kept in `home`/`none` VMs. Paths are relative to /root.
      Only list caches: anything here is lost at stop unless the VM is `full`.
    '';
  };

  config = {
    assertions = map (dir: {
      assertion = dir != "" && !lib.hasPrefix "/" dir && !lib.elem ".." (lib.splitString "/" dir);
      message = "sodabox.cacheDirs: `${dir}` must be a relative path under /root without `..`";
    }) cfg.cacheDirs;

    # Bind sources must exist before stage 2 mounts them, the same reason the
    # rest of the layout is made in stage 1 (see `persistent-layout` in
    # base.nix). `script` is `lines`, so this appends to base.nix's mkdir.
    # systemd creates the mount points under /root by itself.
    boot.initrd.systemd.services.persistent-layout.script = lib.concatMapStrings (
      dir: "mkdir -p ${lib.escapeShellArg "/sysroot/persistent/cache/${dir}"}\n"
    ) cfg.cacheDirs;

    # Nested under the /root bind; systemd orders each mount after the mounts of
    # its parent paths, so /root (and /root/.cargo/…) is in place first.
    # `nofail` matches the other binds, so a diskless VM still boots.
    fileSystems = lib.listToAttrs (
      map (dir: {
        name = "/root/${dir}";
        value = {
          device = "/persistent/cache/${dir}";
          fsType = "none";
          options = [
            "bind"
            "nofail"
          ];
        };
      }) cfg.cacheDirs
    );
  };
}
