# Integration test for the persistence modes (ADR-0014): real sodabox VMs —
# supervisor, netns, passt, nft, cloud-hypervisor on nested KVM, ssh — started
# and stopped inside a NixOS test VM, checking what each mode keeps.
#
# The test VM has no network, so the guest cannot be nix-built at `start` time
# (the default guest input fetches its pins). Instead it is built here, from the
# repo's own mkGuest.nix/base.nix and a minimal configuration, and sodabox is
# pointed at it through its `SODABOX_NIX_BUILD` seam: a stub that prints the
# prebuilt store paths in `nix-build -A kernel -A initrd -A store -A toplevel`
# order. Everything after the build is the real thing.
#
# Needs nested virtualization on the build host (the guest is a KVM VM inside
# the test VM). Run: nix build .#checks.x86_64-linux.persist-modes
{ nixpkgs, sodabox }:
{ pkgs, lib, ... }:
let
  guest = import ../guest/mkGuest.nix {
    guestDir = ./guest;
    system = pkgs.stdenv.hostPlatform.system;
    nixpkgs = nixpkgs.outPath;
  };

  fakeNixBuild = pkgs.writeShellScript "fake-nix-build" ''
    printf '%s\n' ${guest.kernel} ${guest.initrd} ${guest.store} ${guest.toplevel}
  '';

  # sodabox as the unprivileged user (it is rootless by design), with a short
  # runtime dir (unix socket paths must stay under SUN_LEN).
  sb = pkgs.writeShellScriptBin "sb" ''
    exec ${pkgs.util-linux}/bin/runuser -u alice -- env \
      HOME=/home/alice XDG_RUNTIME_DIR=/run/sb \
      SODABOX_NIX_BUILD=${fakeNixBuild} \
      ${lib.getExe sodabox} "$@"
  '';
in
{
  name = "sodabox-persist-modes";

  nodes.machine = {
    virtualisation = {
      memorySize = 4096;
      cores = 2;
      diskSize = 4096;
    };
    boot.kernelModules = [
      "kvm-amd"
      "kvm-intel"
    ];

    users.users.alice = {
      isNormalUser = true;
      extraGroups = [ "kvm" ];
    };
    systemd.tmpfiles.rules = [ "d /run/sb 0700 alice users -" ];

    environment.systemPackages = [
      sb
      pkgs.openssh
    ];
  };

  # One sodabox VM per mode: vm-full (--persist full), vm-home (--persist home),
  # vm-none (--persist none).
  testScript = ''
    D = "/home/alice/.local/share/sodabox"

    def disk(vm, img):
        return f"{D}/{vm}/{img}"

    def start(vm):
        # Detached start; its own output goes to a file so the backgrounded
        # supervisor never holds the test driver's pipe open.
        machine.succeed(f"sb start {vm} --net >/tmp/start-{vm}.log 2>&1")
        machine.wait_until_succeeds(f"sb ssh {vm} -- true", timeout=900)

    def stop(vm):
        machine.succeed(f"sb stop {vm}")
        # The supervisor releases the data-disk lock last — after deleting the
        # scratch disks — so a free lock means the stop has fully completed.
        machine.wait_until_succeeds(f"flock -n {disk(vm, 'data.img.lock')} true", timeout=300)

    def guest(vm, cmd):
        return machine.succeed(f"sb ssh {vm} -- '{cmd}'")

    # A guest-side store write goes through the nix daemon into the store
    # overlay's upper on the data disk. The marker is content-addressed, so it
    # lands at the same path on every boot; that path is what we look for.
    store_marker = {}

    def write_markers(vm):
        guest(vm, "echo cfg > /root/keep && echo work > /var/work/keep"
                  " && echo cache > /root/.cache/keep")
        store_marker[vm] = guest(
            vm, "echo store > /tmp/keep-marker && nix-store --add /tmp/keep-marker"
        ).strip()
        assert store_marker[vm].startswith("/nix/store/"), store_marker[vm]
        guest(vm, "sync")

    # What the guest got from the dotfile collections (ADR-0019): the conflicting
    # file, a file only `base` has, and the mode of `agent`'s credentials.
    def dotfiles(vm):
        return guest(vm, "cat /root/.claude/settings.json /root/.gitconfig"
                         " && stat -c %a /root/.aws/credentials").split()

    def surviving_markers(vm):
        found = guest(vm, f"for f in /root/keep /root/.cache/keep /var/work/keep {store_marker[vm]}; "
                          "do test -e $f && echo $f; done; true").split()
        return ["store" if f == store_marker[vm] else f for f in found]

    machine.wait_for_unit("multi-user.target")
    machine.succeed("test -c /dev/kvm")

    # Two collections that both supply .claude/settings.json; `agent` comes last
    # and wins.
    machine.succeed(
        "runuser -u alice -- sh -c 'd=/home/alice/.config/sodabox/dotfiles"
        " && mkdir -p $d/base/.claude $d/agent/.claude $d/agent/.aws"
        " && echo base > $d/base/.claude/settings.json && echo base > $d/base/.gitconfig"
        " && echo agent > $d/agent/.claude/settings.json"
        " && echo secret > $d/agent/.aws/credentials && chmod 600 $d/agent/.aws/credentials'"
    )

    with subtest("create provisions only the kept disks"):
        out = machine.succeed("sb create vm-full --disk 1G --home-disk 256M --cpus 1"
                              " --dotfiles base,agent 2>&1")
        assert "settings.json from 'base' replaced by 'agent'" in out, out
        machine.succeed("sb create vm-home --persist home --disk 1G --home-disk 256M --cpus 1")
        machine.succeed("sb create vm-none --persist none --disk 1G --home-disk 256M --cpus 1"
                        " --dotfiles base,agent")
        machine.succeed(f"test -e {disk('vm-full', 'data.img')} && test -e {disk('vm-full', 'home.img')}")
        machine.succeed(f"test ! -e {disk('vm-home', 'data.img')} && test -e {disk('vm-home', 'home.img')}")
        machine.succeed(f"test ! -e {disk('vm-none', 'data.img')} && test ! -e {disk('vm-none', 'home.img')}")
        listing = machine.succeed("sb ls")
        rows = [l.split() for l in listing.splitlines()[1:]]
        for vm, mode in [("vm-full", "full"), ("vm-home", "home"), ("vm-none", "none")]:
            assert any(r[0] == vm and r[4] == mode for r in rows), listing

    with subtest("the guest layout is the same in every mode"):
        start("vm-home")
        mounts = guest("vm-home", "cat /proc/mounts")
        for dev, target in [("/dev/vdc", "/persistent"), ("/dev/vdd", "/persistent/home"),
                            ("/dev/vdd", "/root"), ("/dev/vdc", "/var/work"),
                            ("/dev/vdc", "/root/.cache"), ("/dev/vdc", "/root/.cargo/registry")]:
            assert f"{dev} {target} ext4" in mounts, f"{dev} on {target} missing:\n{mounts}"
        stop("vm-home")

    with subtest("full keeps everything"):
        start("vm-full")
        assert dotfiles("vm-full") == ["agent", "base", "600"], dotfiles("vm-full")
        # Copied once: a later edit is the VM's own and survives the restart.
        guest("vm-full", "echo mine > /root/.gitconfig")
        write_markers("vm-full")
        stop("vm-full")
        machine.succeed(f"test -e {disk('vm-full', 'data.img')} && test -e {disk('vm-full', 'home.img')}")
        start("vm-full")
        kept = surviving_markers("vm-full")
        assert kept == ["/root/keep", "/root/.cache/keep", "/var/work/keep", "store"], kept
        assert dotfiles("vm-full") == ["agent", "mine", "600"], dotfiles("vm-full")
        stop("vm-full")

    with subtest("home keeps /root only and frees the data disk at stop"):
        start("vm-home")
        machine.succeed(f"test -e {disk('vm-home', 'data.img')}")
        write_markers("vm-home")
        pin = machine.succeed(f"cat {D}/vm-home/known_hosts")
        stop("vm-home")
        machine.succeed(f"test ! -e {disk('vm-home', 'data.img')}")
        machine.succeed(f"test -e {disk('vm-home', 'home.img')}")
        start("vm-home")
        kept = surviving_markers("vm-home")
        assert kept == ["/root/keep"], kept
        # Same host key across the restart: the pin was neither changed nor refused.
        assert machine.succeed(f"cat {D}/vm-home/known_hosts") == pin
        stop("vm-home")
        machine.succeed(f"test ! -e {disk('vm-home', 'data.img')}")

    with subtest("none keeps nothing yet keeps a verified, host-held ssh identity"):
        start("vm-none")
        machine.succeed(f"test -e {disk('vm-none', 'data.img')} && test -e {disk('vm-none', 'home.img')}")
        # The pin is written by the host before the first connection (no TOFU)
        # and matches the key the guest actually serves.
        host_fp = machine.succeed(f"ssh-keygen -lf {D}/vm-none/ssh_host_ed25519_key.pub").split()[1]
        guest_fp = guest("vm-none", "ssh-keygen -lf /persistent/home/sodabox/ssh_host_ed25519_key").split()[1]
        assert host_fp == guest_fp, (host_fp, guest_fp)
        machine.succeed(f"grep -q '^sodabox-vm-none ssh-ed25519 ' {D}/vm-none/known_hosts")
        guest("vm-none", "echo mine > /root/.gitconfig")
        write_markers("vm-none")
        stop("vm-none")
        machine.succeed(f"test ! -e {disk('vm-none', 'data.img')} && test ! -e {disk('vm-none', 'home.img')}")
        start("vm-none")
        kept = surviving_markers("vm-none")
        assert kept == [], kept
        # Scratch home: the dotfiles are copied in again at every boot.
        assert dotfiles("vm-none") == ["agent", "base", "600"], dotfiles("vm-none")
        stop("vm-none")
        machine.succeed(f"test ! -e {disk('vm-none', 'data.img')} && test ! -e {disk('vm-none', 'home.img')}")

    with subtest("rm --keep-disk keeps exactly the kept disks"):
        machine.succeed("sb rm vm-full --keep-disk --yes")
        machine.succeed(f"ls {D}/vm-full | sort | tr '\\n' ' ' | grep -qx 'data.img home.img '")
        machine.succeed("sb rm vm-home --keep-disk --yes")
        machine.succeed(f"ls {D}/vm-home | tr '\\n' ' ' | grep -qx 'home.img '")
        machine.succeed("sb rm vm-none --keep-disk --yes")
        machine.succeed(f"test ! -e {D}/vm-none")
  '';
}
