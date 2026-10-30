# sodabox

![sodabox](./assets/logo.png)

microVMs for agents, analyses and experiments powered by NixOS

- run multiple VMs on a single host
- fully filtered traffic egress using policies and profiles
- ssh access
- file transfer via rsync or git (virtiofs planned)
- emphermal, home-peristed or full-persisted VMs
- disk, memory and CPU cores are configurable

## Shell completion

The nix package installs completions for bash, zsh and fish. They complete
VM, profile and dotfile collection names as well as subcommands and flags.
Without the package, load them from your shell's startup file:

```sh
source <(COMPLETE=bash soda)   # ~/.bashrc
source <(COMPLETE=zsh soda)    # ~/.zshrc
COMPLETE=fish soda | source    # ~/.config/fish/config.fish
```

## Architecture

TODO

## Workflows

TODO

## Influences

- https://github.com/finbarr/yolobox
- https://github.com/illustris/cogbox

## License

MIT
