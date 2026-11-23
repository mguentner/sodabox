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
        _system: pkgs: rec {
          sodabox = pkgs.callPackage ./nix/package.nix { };
          default = sodabox;
        }
      );

      # Adds `pkgs.sodabox` to a nixpkgs instance (see nix/overlay.nix):
      #   nixpkgs.overlays = [ sodabox.overlays.default ];
      overlays.default = import ./nix/overlay.nix;

      apps = forAllSystems (
        system: _pkgs: rec {
          sodabox = {
            type = "app";
            program = "${self.packages.${system}.sodabox}/bin/soda";
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
                go-grip
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
          # The inference gateway against a real Ollama server, with the model
          # fetched once into the store (nix/tests/ollama-model.nix).
          inference-gateway = pkgs.testers.runNixOSTest (
            import ./nix/tests/inference-gateway.nix {
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
