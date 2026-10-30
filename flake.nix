{
  description = "sodabox — rootless microVM sandbox with deny-by-default egress";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.git-hooks.url = "github:cachix/git-hooks.nix";
  inputs.git-hooks.inputs.nixpkgs.follows = "nixpkgs";

  outputs =
    {
      self,
      nixpkgs,
      git-hooks,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});

      # Pre-commit hooks (git-hooks.nix): rustfmt, clippy and nixfmt. The dev
      # shell installs them into .git/hooks; `nix flake check` runs them too.
      # The check runs in the sandbox without network, so clippy gets the
      # crates from Cargo.lock vendored.
      preCommit =
        system: pkgs:
        git-hooks.lib.${system}.run {
          src = ./.;
          settings.rust.check.cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ./Cargo.lock; };
          hooks = {
            rustfmt.enable = true;
            clippy = {
              enable = true;
              settings.denyWarnings = true;
              settings.extraArgs = "--all-targets";
            };
            nixfmt.enable = true;
          };
        };
    in
    {
      packages = forAllSystems (
        system: pkgs: rec {
          sodabox = pkgs.rustPlatform.buildRustPackage {
            pname = "sodabox";
            version = "0.0.0";

            # Rust sources plus guest-default/, profiles/ and nix/dotfiles.nix (embedded via
            # include_str! in crates/cli/src/{guest,profile}.rs and crates/common/src/dotfiles.rs)
            # — keep docs/, target/ out of the build.
            src =
              let
                fs = pkgs.lib.fileset;
              in
              fs.toSource {
                root = ./.;
                fileset = fs.unions [
                  ./Cargo.toml
                  ./Cargo.lock
                  ./crates
                  ./guest-default
                  ./profiles
                  ./nix/dotfiles.nix
                ];
              };

            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = [ pkgs.makeWrapper ];

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
                inherit (pkgs.lib) getExe getExe' makeBinPath;
              in
              ''
                # Ship the guest build tooling (mkGuest.nix + base.nix +
                # erofs-store.nix) so the installed binary can nix-build it at
                # runtime (ADR-0012); nix-build only reads it, so RO store perms are fine.
                mkdir -p $out/share/sodabox
                cp -r ${./nix/guest} $out/share/sodabox/guest

                wrapProgram $out/bin/sodabox \
                  --set-default SODABOX_GUEST_NIX_DIR    $out/share/sodabox/guest \
                  --set-default SODABOX_CLOUD_HYPERVISOR ${getExe pkgs.cloud-hypervisor} \
                  --set-default SODABOX_CH_REMOTE        ${getExe' pkgs.cloud-hypervisor "ch-remote"} \
                  --set-default SODABOX_PASST            ${getExe' pkgs.passt "passt"} \
                  --set-default SODABOX_NFT              ${getExe' pkgs.nftables "nft"} \
                  --set-default SODABOX_IP               ${getExe' pkgs.iproute2 "ip"} \
                  --prefix PATH : ${
                    makeBinPath [
                      pkgs.cloud-hypervisor
                      pkgs.passt
                      pkgs.erofs-utils
                      pkgs.nftables
                      pkgs.iproute2
                      pkgs.openssh
                      pkgs.rsync
                    ]
                  }
              '';

            meta = with pkgs.lib; {
              description = "Rootless microVM sandbox with deny-by-default egress";
              mainProgram = "sodabox";
              platforms = platforms.linux;
            };
          };
          default = sodabox;
        }
      );

      apps = forAllSystems (
        system: _pkgs: rec {
          sodabox = {
            type = "app";
            program = "${self.packages.${system}.sodabox}/bin/sodabox";
          };
          default = sodabox;
        }
      );

      devShells = forAllSystems (
        system: pkgs: {
          default = pkgs.mkShell {
            # Installs the pre-commit hooks (see preCommit) on entering the shell.
            inherit (preCommit system pkgs) shellHook;
            # Rust toolchain plus the runtime helpers the tool drives at run time.
            # In the built package these are pinned into the wrapper (see
            # packages.sodabox); here they are just on the dev shell's PATH.
            packages =
              (preCommit system pkgs).enabledPackages
              ++ (with pkgs; [
                cargo
                rustc
                clippy
                rustfmt
                pkg-config
                cloud-hypervisor
                passt
                erofs-utils
                nftables
                iproute2
                openssh
                rsync
                git
              ]);
          };
        }
      );

      # The pre-commit hooks on every system, plus the NixOS integration tests
      # (nix/tests). Those boot real sodabox VMs inside the test VM, so they
      # need nested KVM on the build host; x86_64 only.
      checks = forAllSystems (
        system: pkgs:
        {
          pre-commit = preCommit system pkgs;
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          persist-modes = pkgs.testers.runNixOSTest (
            import ./nix/tests/persist-modes.nix {
              inherit nixpkgs;
              sodabox = self.packages.x86_64-linux.sodabox;
            }
          );
        }
      );

      # Same formatter as the nixfmt pre-commit hook.
      formatter = forAllSystems (_system: pkgs: pkgs.nixfmt);
    };
}
