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
        pkgs = nixpkgs.legacyPackages.${system};
        foundryPkgs = foundry.defaultPackage.${system};

        # Elixir with Erlang/OTP 27
        erlang = pkgs.beam.interpreters.erlang_27;
        elixir = pkgs.beam.packages.erlang_27.elixir_1_18;

        linuxOnlyPackages = pkgs.lib.optionals pkgs.stdenv.isLinux [
          pkgs.inotify-tools
        ];

        packages = import ./nix/packages.nix { inherit pkgs; };

      in {
        inherit packages;

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
            foundryPkgs

            # Build tools
            pkgs.gnumake
            pkgs.gcc
            pkgs.openssl
          ] ++ linuxOnlyPackages;

          shellHook = ''
            # Postgres — local instance via Unix socket (no TCP)
            export PGDATA="$PWD/.pg-data"
            export PGHOST="$PWD/.pg-socket"
            export PGUSER="''${USER}"
            export PGDATABASE="''${PGDATABASE:-sovra_dev}"

            # Initialise cluster on first entry
            if [ ! -d "$PGDATA" ]; then
              echo "Initialising PostgreSQL data directory…"
              initdb --no-locale --encoding=UTF8 -U "$PGUSER" >/dev/null
            fi

            # Ensure socket directory exists
            mkdir -p "$PGHOST"

            # Start Postgres if not already running
            if ! pg_isready -q 2>/dev/null; then
              pg_ctl start -l "$PGDATA/postgres.log" \
                -o "-k $PGHOST -c listen_addresses=" \
                >/dev/null
            fi

            # Elixir/Mix config
            export MIX_HOME="''${MIX_HOME:-$PWD/.nix-mix}"
            export HEX_HOME="''${HEX_HOME:-$PWD/.nix-hex}"
            export ERL_AFLAGS="''${ERL_AFLAGS:--kernel shell_history enabled}"

            echo "Sovra dev environment"
            echo "  Postgres: socket at $PGHOST (user: $PGUSER)"
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
