# The integration-test guest plus curl, for the inference gateway test
# (nix/tests/inference-gateway.nix): the guest calls the gateway like a
# client would.
{ pkgs, ... }:
{
  imports = [ ../guest/configuration.nix ];
  environment.systemPackages = [ pkgs.curl ];
}
