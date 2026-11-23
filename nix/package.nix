{
  lib,
  stdenv,
  rustPlatform,
  makeWrapper,
  installShellFiles,
  cloud-hypervisor,
  passt,
  erofs-utils,
  nftables,
  iproute2,
  openssh,
  rsync,
}:

rustPlatform.buildRustPackage {
  pname = "sodabox";
  version = "0.0.0";

  # Rust sources plus guest-default/, profiles/, the logo asset and
  # nix/dotfiles.nix (embedded via include_str!/include_bytes! in
  # crates/cli/src/{guest,profile,tui}.rs and
  # crates/common/src/dotfiles.rs) — keep docs/, target/ out of the
  # build.
  src =
    let
      fs = lib.fileset;
    in
    fs.toSource {
      root = ../.;
      fileset = fs.unions [
        ../Cargo.toml
        ../Cargo.lock
        ../crates
        ../guest-default
        ../profiles
        ../assets/logo_120x256.png
        ./dotfiles.nix
      ];
    };

  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = [
    makeWrapper
    installShellFiles
  ];

  # Pin every host tool sodabox drives at runtime (ADR-0010): each call
  # site reads a SODABOX_* override (bare-name default), so --set-default
  # gives reproducible pinned paths that a developer can still override.
  # mkfs.erofs (config disk + guest nix-build) and openssh's ssh-keygen/
  # ssh (ADR-0011 host↔guest access) resolve from PATH by their bare
  # names, so they go on the wrapper PATH too. The guest's
  # /nix/store is delivered ONLY as a per-guest erofs closure image
  # (ADR-0008) — the whole host store is never shared, so no virtiofsd.
  # nix-build and nix-instantiate are deliberately NOT pinned — the code default resolves the
  # host's own Nix, which --prefix PATH leaves reachable.
  postInstall =
    let
      inherit (lib)
        getExe
        getExe'
        makeBinPath
        optionalString
        ;
      inherit (stdenv) buildPlatform hostPlatform;
    in
    ''
      # Ship the guest build tooling (mkGuest.nix + base.nix +
      # erofs-store.nix) so the installed binary can nix-build it at
      # runtime (ADR-0012); nix-build only reads it, so RO store perms are fine.
      mkdir -p $out/share/sodabox
      cp -r ${./guest} $out/share/sodabox/guest

      wrapProgram $out/bin/soda \
        --set-default SODABOX_GUEST_NIX_DIR    $out/share/sodabox/guest \
        --set-default SODABOX_CLOUD_HYPERVISOR ${getExe cloud-hypervisor} \
        --set-default SODABOX_CH_REMOTE        ${getExe' cloud-hypervisor "ch-remote"} \
        --set-default SODABOX_PASST            ${getExe' passt "passt"} \
        --set-default SODABOX_NFT              ${getExe' nftables "nft"} \
        --set-default SODABOX_IP               ${getExe' iproute2 "ip"} \
        --prefix PATH : ${
          makeBinPath [
            cloud-hypervisor
            passt
            erofs-utils
            nftables
            iproute2
            openssh
            rsync
          ]
        }
    ''
    # Dynamic completion stubs (ADR-0009): each one calls back into the
    # wrapped binary on Tab, so VM, profile and dotfile names are live.
    # Generating them runs the binary, hence the cross-compile guard.
    # Autoloaded from site-functions, the zsh stub only registers its
    # completer, so call it once to complete the very first Tab too.
    + optionalString (buildPlatform.canExecute hostPlatform) ''
      installShellCompletion --cmd soda \
        --bash <(COMPLETE=bash $out/bin/soda) \
        --fish <(COMPLETE=fish $out/bin/soda) \
        --zsh <(COMPLETE=zsh $out/bin/soda; echo '_clap_dynamic_completer_soda "$@"')
    '';

  meta = {
    description = "Rootless microVM sandbox with deny-by-default egress";
    mainProgram = "soda";
    platforms = lib.platforms.linux;
  };
}
