# Minimal guest for the integration tests (nix/tests). Layered on sodabox's
# base module by mkGuest.nix, exactly like a user's guest; kept tiny so the
# guest closure builds fast and the test VM needs no network.
{ ... }:
{
  networking.hostName = "sodabox-test";
  system.stateVersion = "24.11";
}
