# Evaluates one dotfile collection's `default.nix` (ADR-0019) to plain JSON:
#
#   { "<path under /root>" = { text = "…"; mode = "0644"; }; … }
#
# Embedded in the soda binary and run with `nix-instantiate --eval --strict
# --json`; nothing is built. The collection gets only `lib`, taken from the
# shared guest's pinned nixpkgs (ADR-0012), so a generated file is plain text by
# construction. Text with store-path context (`${pkgs.foo}`, `${./file}`) is
# refused: it would dangle inside the VM.
{ collection, guestDir }:
let
  sources = import (/. + guestDir + "/npins");
  lib =
    if sources ? nixpkgs then
      import (sources.nixpkgs + "/lib")
    else
      throw "dotfiles: the guest input at ${guestDir} pins no nixpkgs";

  files = import (/. + collection + "/default.nix") { inherit lib; };

  check =
    path: f:
    let
      where = "dotfiles: ${collection}/default.nix: `${path}`";
      unknown = lib.subtractLists [
        "text"
        "mode"
      ] (builtins.attrNames f);
    in
    if !builtins.isAttrs f then
      throw "${where} must be an attribute set { text; mode?; }"
    else if unknown != [ ] then
      throw "${where} has unknown keys: ${lib.concatStringsSep ", " unknown}"
    else if !(f ? text) || !builtins.isString f.text then
      throw "${where} needs `text`, a string"
    else if builtins.hasContext f.text then
      throw "${where} refers to a store path; generated files must be plain text"
    else if f ? mode && !builtins.isString f.mode then
      throw "${where}: `mode` must be a string such as \"0600\""
    else
      {
        inherit (f) text;
        mode = f.mode or "0644";
      };
in
if builtins.isAttrs files then
  builtins.mapAttrs check files
else
  throw "dotfiles: ${collection}/default.nix must return an attribute set of files"
