# sodabox base guest module — the non-negotiable "how" of a sodabox guest
# (ADR-0012). Layered under the user's configuration.nix by mkGuest.nix.
#
# Headless microVM for cloud-hypervisor direct kernel boot (spike 0001). The
# immutable /nix/store is delivered as a read-only erofs image (spike 0004,
# ADR-0008) and made writable with an overlay whose writable upper lives on the
# persistent disk — so guest-side installs cache across reboots and
# cost guest RAM only when no persistent disk is attached; the root itself is
# tmpfs.
#
# Every VM has two read-write disks with one fixed layout (ADR-0008/0014); the
# host decides which of them are kept and which are scratch (recreated blank
# each start, deleted at stop) per the VM's `persist` mode, so nothing here
# depends on the mode:
#
#   /persistent/            ← /dev/vdc, the data disk
#     nix-store/            → upper+work for the /nix/store overlay
#     work/                 → bind → /var/work  (sync work tree, login lands here)
#     cache/<dir>           → bind → /root/<dir> (tool caches, cache-dirs.nix)
#   /persistent/home/       ← /dev/vdd, the home disk
#     root/                 → bind → /root      (the whole home, so *all* per-tool
#                                                state survives — no per-dotfile
#                                                mounts to enumerate)
#     sodabox/              → sodabox's own state (sshd host key); not mounted
#
# Caches under /root (~/.cache, ~/.cargo/registry, …) are bound back onto the
# data disk by cache-dirs.nix (ADR-0018), so they don't fill the home disk.
{
  config,
  lib,
  pkgs,
  ...
}:
{
  imports = [ ./cache-dirs.nix ];

  # No bootloader — cloud-hypervisor boots the kernel + initrd directly.
  boot.loader.grub.enable = false;

  # systemd in stage-1: the writable-store upper lives on the
  # persistent disk, so the disk must be formatted (`x-systemd.makefs`) and
  # mounted in the initrd *before* the /nix/store overlay assembles.
  # `systemd-makefs` and the mount-dependency ordering (overlay-after-disk, via
  # the upperdir path) only exist under systemd initrd; the scripted initrd
  # cannot makefs. Stage-1 is also where the folder layout is created (see
  # `persistent-layout` below).
  boot.initrd.systemd.enable = true;

  # Drivers stage-1 needs to reach the virtio store image and assemble the
  # overlay, plus console/net/data.
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_console"
    "virtio_net"
    "erofs"
    "overlay"
  ];
  boot.kernelParams = [ "console=ttyS0" ];

  # Root is tmpfs; /nix/store is the read-only erofs (attached as /dev/vda,
  # mounted at /nix/.ro-store) overlaid with a disk-backed upper
  # so package installs/GC roots can be written. The erofs root holds `store/`
  # (the closure paths, used as the overlay lowerdir) and `nix-path-registration`
  # (the DB dump loaded at boot, see boot.postBootCommands).
  fileSystems."/" = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [ "mode=0755" ];
  };
  fileSystems."/nix/.ro-store" = {
    device = "/dev/vda";
    fsType = "erofs";
    neededForBoot = true;
    options = [ "ro" ];
  };
  # The writable upper layer for /nix/store. It
  # lives on the persistent disk under `/persistent/nix-store`, so guest-side
  # installs and GC roots survive reboots and cost guest RAM only when no
  # persistent disk is attached (see the fallback note below). Persistent
  # *system* packages still come from the declarative closure (ADR-0010), not
  # this overlay; the overlay just caches ad-hoc guest-side store writes.
  #
  # Fallback to tmpfs when diskless: the upper/work dirs sit under
  # /persistent, whose mount is `nofail`. If /dev/vdc is present, stage-1
  # makefs's and mounts it before this overlay assembles (systemd orders the
  # overlay after persistent.mount via the upperdir path), so the upper is on
  # disk. If no disk is attached, persistent.mount is skipped and /persistent
  # stays a directory on the tmpfs root, so the overlay's auto-created upper
  # transparently lands in RAM — the "boots without a persistent disk" guarantee
  # is preserved (its installs are then volatile, as before). The upper/work
  # directories are created by stage-1 (systemd initrd's overlay pre-mount
  # service) before the overlay mounts.
  fileSystems."/nix/store" = {
    overlay = {
      lowerdir = [ "/nix/.ro-store/store" ];
      upperdir = "/persistent/nix-store/store";
      workdir = "/persistent/nix-store/work";
    };
    neededForBoot = true;
  };

  # Register the store closure in the guest Nix DB and pin the running system as
  # a GC root. The erofs image ships the store *paths* but not their
  # DB registration; without this the guest DB treats the whole store as
  # unregistered, so `nix-collect-garbage` computes a near-empty live set and
  # whiteouts essentially all of /nix/store in the overlay upper — bricking the
  # system. That upper is now persistent, so the damage would even
  # survive a reboot. `nix-store --load-db` (idempotent) makes the paths valid and
  # records their references so GC can trace liveness; setting the system profile
  # gives GC a concrete root. Runs every boot; the Nix DB lives on the tmpfs root
  # (/nix/var), so it must be repopulated each time. Mirrors the nixos-install /
  # sd-image bootstrap, adapted to our read-only registration path.
  boot.postBootCommands = lib.mkAfter ''
    if [ -f /nix/.ro-store/nix-path-registration ]; then
      ${config.nix.package.out}/bin/nix-store --load-db < /nix/.ro-store/nix-path-registration
    fi
    ${config.nix.package.out}/bin/nix-env -p /nix/var/nix/profiles/system --set /run/current-system
  '';

  # Read-only per-VM config disk (ADR-0011): the supervisor
  # attaches a small erofs image as the guest's second virtio-blk disk
  # (/dev/vdb, always second so its name is deterministic) carrying
  # ssh/authorized_keys and future launch data. Not neededForBoot (consumed by
  # post-boot services); `nofail` so a VM launched without it still boots.
  fileSystems."/run/sodabox" = {
    device = "/dev/vdb";
    fsType = "erofs";
    options = [
      "ro"
      "nofail"
    ];
  };

  # The data disk (ADR-0008/0011): the guest's third virtio-blk
  # device (/dev/vdc, RW), mounted at /persistent. It carries the writable-store
  # upper (`nix-store/`) and the sync work tree (`work/project`,
  # soda sync-vm/sync-host). The host provisions it as a blank sparse raw file
  # — once for a `full` VM, at every start for a `home`/`none` VM, whose data disk
  # is scratch (ADR-0014) — so it may carry no filesystem: `x-systemd.makefs`
  # makes systemd mkfs it (ext4) when blank, and otherwise just mounts it.
  #
  # `neededForBoot`: mounted in stage-1 so the writable-store upper
  # is ready before the /nix/store overlay assembles. `nofail` keeps a diskless
  # VM bootable — under systemd initrd a missing /dev/vdc just skips this mount
  # (the overlay then falls back to a tmpfs upper on the root fs, see /nix/store
  # above) instead of failing the boot.
  fileSystems."/persistent" = {
    device = "/dev/vdc";
    fsType = "ext4";
    neededForBoot = true;
    options = [
      "nofail"
      "x-systemd.makefs"
    ];
  };

  # The home disk (ADR-0014): the fourth virtio-blk device (/dev/vdd, RW),
  # mounted at /persistent/home. It carries the home (`root/`) and sodabox's own
  # state (`sodabox/`, the sshd host key) — the small part of a VM worth keeping
  # when the rest is thrown away, which is why it is a disk of its own: the host
  # keeps it for `full` and `home` VMs and makes it scratch only for `none`. Same
  # blank-disk handling as the data disk. Mounted in stage-1 (`neededForBoot`)
  # only so that `persistent-layout` below can create its folders; systemd orders
  # it after /persistent, on which it is nested.
  fileSystems."/persistent/home" = {
    device = "/dev/vdd";
    fsType = "ext4";
    neededForBoot = true;
    options = [
      "nofail"
      "x-systemd.makefs"
    ];
  };

  # The folder layout on both disks, created in stage-1. It has to happen here
  # and not via `systemd.tmpfiles.rules`: tmpfiles runs *after* local-fs.target,
  # i.e. after the bind mounts below have already tried (and, with `nofail`,
  # silently failed) to mount a source that does not exist yet — persistence
  # would only kick in one boot late. Stage-1 has the disks mounted already
  # (`neededForBoot`, under /sysroot/persistent), so the directories exist well
  # before anything binds them.
  #
  # Diskless (`nofail`): the sysroot-persistent mounts are simply skipped, the
  # mkdir lands on the tmpfs root and the binds below bind tmpfs→tmpfs —
  # volatile, as before, and the boot still succeeds.
  boot.initrd.systemd.services.persistent-layout = {
    description = "Create the persistent-disk folder layout";
    wantedBy = [ "initrd-fs.target" ];
    before = [ "initrd-fs.target" ];
    after = [
      "sysroot-persistent.mount"
      "sysroot-persistent-home.mount"
    ];
    unitConfig.DefaultDependencies = false;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = "mkdir -p /sysroot/persistent/work /sysroot/persistent/home/root /sysroot/persistent/home/sodabox";
  };

  # The home and the work tree, bound out of the two disks. Binding *all* of
  # /root (rather than enumerating ~/.config, ~/.claude, … per tool) is the
  # point: every tool's state persists, including tools that ignore XDG, and
  # nothing has to be added here when a new one shows up. Only known caches are
  # carved back out onto the data disk (cache-dirs.nix).
  #
  # /var/work is where an interactive login lands (see environment.loginShellInit)
  # and where sync writes (`/var/work/project`, ADR-0011) — deliberately outside
  # $HOME, so a sync can never scribble over the home's tool state, and on the
  # data disk, so a `home` VM drops it at stop (the project comes back via sync).
  #
  # Ordering needs no `after`: both disks are `neededForBoot`, so they are
  # mounted in the initrd and survive the switch-root — they are already there
  # before stage-2 reaches local-fs.target and these binds. `nofail` matches the
  # disk mounts, so a diskless VM still boots.
  fileSystems."/root" = {
    device = "/persistent/home/root";
    fsType = "none";
    options = [
      "bind"
      "nofail"
    ];
  };
  fileSystems."/var/work" = {
    device = "/persistent/work";
    fsType = "none";
    options = [
      "bind"
      "nofail"
    ];
  };

  # Log in *into the work tree*, not into $HOME: /var/work is where the user's
  # project lives, and /root is now just where tool state happens to sit. Login
  # shells only (/etc/profile), which covers `soda ssh` and the serial console
  # autologin; `ssh <vm> -- cmd` and rsync's non-login shell are untouched — which
  # matters, because a profile that emits output breaks rsync (a bare `cd` emits
  # none).
  environment.loginShellInit = "cd /var/work 2>/dev/null || true";

  # rsync and git are the two host↔guest sync transports (ADR-0011,
  # ADR-0013), so the guest must provide both — same "non-negotiable base,
  # like sshd" rationale as rsync. git ships git-upload-pack/git-receive-pack,
  # which is what the ssh-invoked push/fetch actually runs guest-side.
  environment.systemPackages = [
    pkgs.rsync
    pkgs.git
  ];

  # SSH access (ADR-0011). The supervisor forwards a host-loopback
  # port to this sshd via passt (→ guest:22). Keys come solely from the read-only
  # config disk mounted at /run/sodabox, so AuthorizedKeysFile points only
  # there — the guest cannot add its own keys. Key auth only; root login by key.
  #
  # Host key on the home disk (ADR-0014): a single ed25519 host
  # key under /persistent/home/sodabox — sodabox's own state, deliberately *not*
  # inside the persisted home, so sshd-keygen depends on the disk mount alone and
  # the key can't be caught up in anything the user does to /root. sshd-keygen
  # creates it on first boot and reuses it thereafter (its ConditionFileNotEmpty
  # skips regeneration), so the key is **stable across reboots** — which lets the
  # host pin it (TOFU) and do real host-key verification instead of blind trust.
  # A `persist = "none"` VM, whose home disk is scratch, gets its key from the
  # host instead (sodabox-host-key below). If no disk is present it falls back to
  # an ephemeral key on the tmpfs root.
  services.openssh = {
    enable = true;
    hostKeys = [
      {
        path = "/persistent/home/sodabox/ssh_host_ed25519_key";
        type = "ed25519";
      }
    ];
    settings = {
      PasswordAuthentication = lib.mkDefault false;
      KbdInteractiveAuthentication = lib.mkDefault false;
      PermitRootLogin = lib.mkDefault "prohibit-password";
      AuthorizedKeysFile = lib.mkDefault "/run/sodabox/ssh/authorized_keys";
    };
  };
  # The host key lives on the home disk, so its generation must wait for that
  # mount — otherwise sshd-keygen writes to the pre-mount tmpfs and the mount
  # then shadows it, leaving sshd with no host key. We also `sync` immediately
  # after generating the key so this one-time, first-boot write reaches home.img
  # promptly. Normal stops now do a clean ACPI shutdown that flushes everything,
  # so this is belt-and-suspenders for the hard-kill fallback path
  # (e.g. a guest that hangs before it can power off); condition-gated to the first
  # boot, so it costs nothing later.
  systemd.services.sshd-keygen = {
    after = [ "persistent-home.mount" ];
    wants = [ "persistent-home.mount" ];
    serviceConfig.ExecStartPost = "${pkgs.coreutils}/bin/sync";
  };

  # Host-held host key (`persist = "none"`, ADR-0014): a VM that keeps nothing
  # would mint a new host key every boot, which the host's pin refuses. Instead
  # the host owns the key and ships it on the read-only config disk; install it
  # where sshd looks before sshd-keygen runs, whose ConditionFileNotEmpty then
  # skips generation. Other modes ship no key, and this is skipped.
  systemd.services.sodabox-host-key = {
    description = "Install the host-provided sshd host key";
    wantedBy = [ "sshd.service" ];
    before = [
      "sshd-keygen.service"
      "sshd.service"
    ];
    after = [
      "run-sodabox.mount"
      "persistent-home.mount"
    ];
    wants = [
      "run-sodabox.mount"
      "persistent-home.mount"
    ];
    unitConfig.ConditionPathExists = "/run/sodabox/ssh/ssh_host_ed25519_key";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${pkgs.coreutils}/bin/install -D -m 0600 /run/sodabox/ssh/ssh_host_ed25519_key /persistent/home/sodabox/ssh_host_ed25519_key";
    };
  };

  # Dotfiles (ADR-0019): a VM created with `--dotfiles` gets its merged
  # collections on the config disk. Copy them into /root once, never over a file
  # that is already there, and keep their modes. The marker lives on the home
  # disk next to the host key, so a `full`/`home` VM copies once and owns the
  # files from then on, while a `none` VM (scratch home) gets them at every boot.
  systemd.services.sodabox-dotfiles = {
    description = "Copy the VM's dotfiles into /root";
    wantedBy = [ "multi-user.target" ];
    before = [ "sshd.service" ];
    after = [
      "run-sodabox.mount"
      "root.mount"
      "persistent-home.mount"
    ];
    wants = [
      "run-sodabox.mount"
      "root.mount"
      "persistent-home.mount"
    ];
    unitConfig = {
      ConditionPathIsDirectory = "/run/sodabox/dotfiles";
      ConditionPathExists = "!/persistent/home/sodabox/dotfiles-provisioned";
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      ${pkgs.coreutils}/bin/cp -rT --preserve=mode --update=none /run/sodabox/dotfiles /root
      ${pkgs.coreutils}/bin/touch /persistent/home/sodabox/dotfiles-provisioned
      ${pkgs.coreutils}/bin/sync
    '';
  };

  # Idempotently prepare the sync work dir as a git push target (ADR-0013).
  # `mkdir -p` makes this safe for a VM never synced at all; `git init` only
  # runs if `.git` is absent, so a VM that has only ever used rsync (which
  # pushes `.git` too, ADR-0011) just gets `updateInstead` applied in place —
  # no migration step, push-able on the very next boot. The config line is
  # re-applied unconditionally every boot (same "rebuilt each launch" posture
  # as authorized_keys/the config disk) so nothing guest-side can quietly
  # defeat it.
  systemd.services.sodabox-git-init = {
    description = "Prepare the sodabox sync work dir as a git push target";
    wantedBy = [ "multi-user.target" ];
    after = [ "var-work.mount" ];
    requires = [ "var-work.mount" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = pkgs.writeShellScript "sodabox-git-init" ''
        set -eu
        dir=/var/work/project
        mkdir -p "$dir"
        [ -d "$dir/.git" ] || ${pkgs.git}/bin/git -C "$dir" init -q
        ${pkgs.git}/bin/git -C "$dir" config receive.denyCurrentBranch updateInstead
        # /root (and its ~/.gitconfig) persists across boots, so guard this
        # with --get-all instead of a bare --add: unconditional --add would
        # grow a duplicate entry every boot forever.
        ${pkgs.git}/bin/git config --global --get-all safe.directory \
          | ${pkgs.gnugrep}/bin/grep -qFx "$dir/.git" \
          || ${pkgs.git}/bin/git config --global --add safe.directory "$dir/.git"
      '';
    };
  };

  # Guest time from the host clock over PTP, not NTP. NTP needs egress to a
  # time server, which the deny-by-default policy doesn't grant, and a guest
  # that was paused (host suspend, SIGSTOP) comes back minutes or hours behind.
  # `ptp_kvm` turns the host's clock into a PTP hardware clock for the guest,
  # read with a KVM hypercall, and chrony disciplines the system clock against
  # it, with no network involved. The module is loaded in stage-1 so /dev/ptp0
  # exists before chronyd starts; it is the guest's only PTP device, so the name
  # is fixed.
  boot.initrd.kernelModules = [ "ptp_kvm" ];
  services.timesyncd.enable = false;
  services.chrony = {
    enable = true;
    servers = [ ];
    # No RTC to trim; the PHC is the only source.
    enableRTCTrimming = false;
    # The module's makestep caps the number of steps; after a pause the clock
    # can be far off at any point, so step whenever the offset exceeds 1 s.
    makestep.enable = false;
    extraConfig = ''
      refclock PHC /dev/ptp0 poll 2 dpoll -2 offset 0 stratum 2
      makestep 1 -1
    '';
  };

  # Minimal, headless, autologin on the serial console.
  services.getty.autologinUser = lib.mkDefault "root";
  documentation.enable = lib.mkDefault false;
  documentation.nixos.enable = lib.mkDefault false;
  networking.hostName = lib.mkDefault "sodabox-guest";

  system.stateVersion = lib.mkDefault "24.11";
}
