{ pkgs }:

let
  beamPackages = pkgs.beam.packages.erlang_27;
  elixir = beamPackages.elixir_1_18;

  # Fetch Mix dependencies reproducibly.
  mixFodDeps = beamPackages.fetchMixDeps {
    pname = "sovra-mix-deps";
    version = "0.1.0";
    src = ../backend;
    sha256 = "sha256-hWIOkVThsN9cgIqJsHNRTmNg4OE6rIT2zy3vxb57GzA=";
  };

  # Fetch pnpm dependencies reproducibly.
  pnpmDeps = pkgs.pnpm.fetchDeps {
    pname = "sovra-frontend-deps";
    version = "0.1.0";
    src = ../frontend;
    hash = "sha256-CgraAn76o95nIBggaDFwTMFjDmJfjz5/aRzsPVGzbKU=";
    fetcherVersion = 3;
  };

  # Prefetch precompiled Rust NIFs for ex_keccak and ex_secp256k1.
  # These are normally downloaded at compile time by rustler_precompiled,
  # which breaks the Nix sandbox. We fetch them ahead of time as
  # fixed-output derivations and provide them via the cache path.
  #
  # Erlang 27 has NIF version 2.17, which falls back to 2.16 tarballs.
  # We include both Linux x86_64 (CI/server) and macOS aarch64 (local dev).
  nifCache = pkgs.linkFarm "rustler-nif-cache" [
    { name = "libexkeccak-v0.7.8-nif-2.16-x86_64-unknown-linux-gnu.so.tar.gz";
      path = pkgs.fetchurl {
        url = "https://github.com/exWeb3/ex_keccak/releases/download/v0.7.8/libexkeccak-v0.7.8-nif-2.16-x86_64-unknown-linux-gnu.so.tar.gz";
        sha256 = "1Ej5BhCzs0Kw8i3EQm5/0+6aXD4ZrRxWbEOB5Fm+NWY=";
      }; }
    { name = "libexkeccak-v0.7.8-nif-2.16-aarch64-apple-darwin.so.tar.gz";
      path = pkgs.fetchurl {
        url = "https://github.com/exWeb3/ex_keccak/releases/download/v0.7.8/libexkeccak-v0.7.8-nif-2.16-aarch64-apple-darwin.so.tar.gz";
        sha256 = "FJFMAKkNwg0G0/ix+R/1ljuC22KcSe9eSU6VLUSkwdA=";
      }; }
    { name = "libex_secp256k1-v0.7.6-nif-2.16-x86_64-unknown-linux-gnu.so.tar.gz";
      path = pkgs.fetchurl {
        url = "https://github.com/ayrat555/ex_secp256k1/releases/download/v0.7.6/libex_secp256k1-v0.7.6-nif-2.16-x86_64-unknown-linux-gnu.so.tar.gz";
        sha256 = "wfen2JDJGgZzc2oRbSF6rfNFjPZiN8LAAS2f6tJlUDo=";
      }; }
    { name = "libex_secp256k1-v0.7.6-nif-2.16-aarch64-apple-darwin.so.tar.gz";
      path = pkgs.fetchurl {
        url = "https://github.com/ayrat555/ex_secp256k1/releases/download/v0.7.6/libex_secp256k1-v0.7.6-nif-2.16-aarch64-apple-darwin.so.tar.gz";
        sha256 = "L3bKW95I1pPOS90dVldHIsxK96LlF+YcEe4VlJfRwpM=";
      }; }
  ];

in {

  # Elixir Mix release for the Phoenix backend.
  sovra-backend = beamPackages.mixRelease {
    pname = "sovra";
    version = "0.1.0";
    src = ../backend;

    inherit mixFodDeps elixir;

    nativeBuildInputs = [ pkgs.gcc pkgs.gnumake pkgs.openssl ];

    MIX_ENV = "prod";

    # Point rustler_precompiled at our prefetched NIF tarballs.
    RUSTLER_PRECOMPILED_GLOBAL_CACHE_PATH = nifCache;

    # rustler_precompiled needs a writable HOME for metadata files.
    HOME = "/tmp";

    # Keep the Erlang cookie so the release can start without RELEASE_COOKIE.
    removeCookie = false;
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
