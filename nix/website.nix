{
  lib,
  stdenv,
  nodejs,
  pnpm,
  fetchPnpmDeps,
  pnpmConfigHook,
}:

# Static landing page (website/, Astro). The result is the dist/ directory,
# ready to be served by any web server. Fonts and images are vendored in the
# source, so the build needs no network beyond the fixed-output pnpm store.
stdenv.mkDerivation (finalAttrs: {
  pname = "sodabox-website";
  version = "0.0.1";

  # website/ without local build state (node_modules, dist, .astro).
  src =
    let
      fs = lib.fileset;
    in
    fs.toSource {
      root = ../website;
      fileset = fs.difference ../website (
        fs.unions [
          (fs.maybeMissing ../website/node_modules)
          (fs.maybeMissing ../website/dist)
          (fs.maybeMissing ../website/.astro)
        ]
      );
    };

  nativeBuildInputs = [
    nodejs
    pnpm
    pnpmConfigHook
  ];

  # Update after changing website/pnpm-lock.yaml: set to lib.fakeHash,
  # build, and copy the hash from the error.
  pnpmDeps = fetchPnpmDeps {
    inherit (finalAttrs) pname version src;
    inherit pnpm;
    fetcherVersion = 5;
    hash = "sha256-lYVuypyBgzRIKWJVYvdgNk5RyLod483kE5jfK/CzpGk=";
  };

  buildPhase = ''
    runHook preBuild
    pnpm build
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    cp -r dist $out
    runHook postInstall
  '';
})
