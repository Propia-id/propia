{ pkgs }:

let
  beamPackages = pkgs.beam.packages.erlang_27;
  elixir = beamPackages.elixir_1_18;

  # Fetch Mix dependencies reproducibly.
  mixFodDeps = beamPackages.fetchMixDeps {
    pname = "sovra-mix-deps";
    version = "0.1.0";
    src = ../backend;
    sha256 = "sha256-1kbW2jgm2AH/NBRoI/bzrvHg44MPpnFhMC1gwxphwe0=";
  };

  # Fetch pnpm dependencies reproducibly.
  pnpmDeps = pkgs.pnpm.fetchDeps {
    pname = "sovra-frontend-deps";
    version = "0.1.0";
    src = ../frontend;
    hash = "sha256-CgraAn76o95nIBggaDFwTMFjDmJfjz5/aRzsPVGzbKU=";
    fetcherVersion = 3;
  };

in {

  # Elixir Mix release for the Phoenix backend.
  #
  # __noChroot disables the Nix sandbox for this derivation because
  # ex_keccak and ex_secp256k1 download precompiled Rust NIFs at
  # compile time via rustler_precompiled.
  sovra-backend = beamPackages.mixRelease {
    pname = "sovra";
    version = "0.1.0";
    src = ../backend;

    inherit mixFodDeps elixir;

    nativeBuildInputs = [ pkgs.gcc pkgs.gnumake pkgs.openssl ];

    MIX_ENV = "prod";

    # rustler_precompiled needs a writable HOME for its NIF download cache.
    HOME = "/tmp";

    # Keep the Erlang cookie so the release can start without RELEASE_COOKIE.
    removeCookie = false;

    # Allow network access for rustler_precompiled NIF downloads.
    __noChroot = true;
  };

  # Static build of the issuer frontend (Vite/React).
  sovra-issuer = pkgs.stdenv.mkDerivation {
    pname = "sovra-issuer";
    version = "0.1.0";
    src = ../frontend;

    nativeBuildInputs = [
      pkgs.nodejs_24
      pkgs.pnpm
      pkgs.pnpm.configHook
    ];

    inherit pnpmDeps;

    buildPhase = ''
      runHook preBuild
      pnpm --filter @sovra/issuer build
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out
      cp -r issuer/dist/* $out/
      runHook postInstall
    '';

    doCheck = false;
  };
}
