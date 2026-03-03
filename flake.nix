{
  description = "Sovra - Decentralized identity platform";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    foundry.url = "github:shazow/foundry.nix/monthly";
  };

  outputs = { self, nixpkgs, flake-utils, foundry }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ foundry.overlay ];
        };

        # Elixir with Erlang/OTP 27
        erlang = pkgs.beam.interpreters.erlang_27;
        elixir = pkgs.beam.packages.erlang_27.elixir_1_18;

        linuxOnlyPackages = pkgs.lib.optionals pkgs.stdenv.isLinux [
          pkgs.inotify-tools
        ];

      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            # Elixir / Erlang
            erlang
            elixir

            # Database
            pkgs.postgresql_18

            # Cache
            pkgs.redis

            # Frontend
            pkgs.nodejs_24
            pkgs.pnpm

            # Smart contracts
            pkgs.foundry-bin

            # Build tools
            pkgs.gnumake
            pkgs.gcc
            pkgs.openssl
          ] ++ linuxOnlyPackages;

          shellHook = ''
            # Postgres — match backend/config/dev.exs
            export PGUSER="''${PGUSER:-postgres}"
            export PGPASSWORD="''${PGPASSWORD:-postgres}"
            export PGDATABASE="''${PGDATABASE:-sovra_dev}"
            export PGHOST="''${PGHOST:-localhost}"

            # Elixir/Mix config
            export MIX_HOME="''${MIX_HOME:-$PWD/.nix-mix}"
            export HEX_HOME="''${HEX_HOME:-$PWD/.nix-hex}"
            export ERL_AFLAGS="''${ERL_AFLAGS:--kernel shell_history enabled}"

            echo "Sovra dev environment"
            echo ""
            echo "Quick start:"
            echo "  make backend    # Phoenix server on :4000"
            echo "  make issuer     # Issuer frontend"
            echo "  make test       # Run all tests"
            echo ""
          '';

          LANG = "en_US.UTF-8";
          LC_ALL = "en_US.UTF-8";
        };
      }
    ) // {
      nixosModules.sovra = import ./nix/nixos-module.nix;
    };
}
