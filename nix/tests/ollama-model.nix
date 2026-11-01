# A model from the Ollama library as a fixed-output derivation, laid out as
# an Ollama models directory:
#
#   manifests/registry.ollama.ai/library/<model>/<tag>
#   blobs/sha256-<digest>
#
# so a NixOS test can serve it without network (the test VM has none). The
# fetch is a fixed-output derivation, which may use the network; each blob
# is checked against the sha256 digest the manifest names, and `hash` pins
# the whole tree, so a tag that moves upstream fails here instead of
# silently changing the test.
#
# Usage: pkgs.callPackage ./ollama-model.nix { } { model = "qwen3"; tag = "0.6b"; hash = "sha256-…"; }
{
  lib,
  stdenvNoCC,
  curl,
  jq,
  cacert,
}:
{
  model,
  tag,
  hash,
}:
stdenvNoCC.mkDerivation {
  name = "ollama-${model}-${tag}";

  nativeBuildInputs = [
    curl
    jq
  ];
  SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
  impureEnvVars = lib.fetchers.proxyImpureEnvVars;

  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
  outputHash = hash;

  buildCommand = ''
    registry=https://registry.ollama.ai/v2/library/${model}
    manifest=$out/manifests/registry.ollama.ai/library/${model}/${tag}
    mkdir -p $out/blobs "$(dirname "$manifest")"

    curl -fsSL --retry 3 \
      -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
      "$registry/manifests/${tag}" -o "$manifest"

    for digest in $(jq -r '.config.digest, .layers[].digest' "$manifest"); do
      blob=$out/blobs/''${digest/:/-}
      curl -fsSL --retry 3 "$registry/blobs/$digest" -o "$blob"
      echo "''${digest#sha256:}  $blob" | sha256sum --check --quiet
    done
  '';
}
