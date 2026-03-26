# NixOS module for deploying Sovra in production.
#
# Usage in your NixOS configuration:
#
#   imports = [ sovra.nixosModules.sovra ];
#
#   services.sovra = {
#     enable = true;
#     domain = "sovra.example.com";
#     backendPath = "/opt/sovra/backend";
#     issuerPath = "/opt/sovra/issuer";
#     secretKeyBaseFile = "/run/secrets/sovra-secret-key-base";
#     databaseUrl = "ecto://sovra:password@localhost/sovra_prod";
#   };

{ config, lib, pkgs, ... }:

let
  cfg = config.services.sovra;
in
{
  options.services.sovra = {
    enable = lib.mkEnableOption "Sovra identity platform";

    domain = lib.mkOption {
      type = lib.types.str;
      description = "Public domain name for the Sovra instance.";
      example = "sovra.example.com";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 4000;
      description = "Port the Phoenix server listens on.";
    };

    secretKeyBaseFile = lib.mkOption {
      type = lib.types.path;
      description = "Path to file containing SECRET_KEY_BASE.";
    };

    databaseUrl = lib.mkOption {
      type = lib.types.str;
      description = "Ecto database URL (ecto://USER:PASS@HOST/DATABASE).";
    };

    backendPath = lib.mkOption {
      type = lib.types.str;
      default = "/opt/sovra/backend";
      description = "Path to the deployed Mix release directory.";
    };

    issuerPath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Path to the deployed issuer frontend static files. When set, Nginx serves them at /.";
    };

    localPostgres = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to run a local PostgreSQL instance.";
    };

    localRedis = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to run a local Redis instance.";
    };

    nginx = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether to configure Nginx as a reverse proxy.";
      };

      enableACME = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether to enable ACME/Let's Encrypt TLS.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    # ── System user ─────────────────────────────────────────────────────────
    users.users.sovra = {
      isSystemUser = true;
      group = "sovra";
      home = "/var/lib/sovra";
      createHome = true;
    };
    users.groups.sovra = {};

    # ── Phoenix systemd service ─────────────────────────────────────────────
    systemd.services.sovra = {
      description = "Sovra Phoenix server";
      after = [ "network.target" ]
        ++ lib.optional cfg.localPostgres "postgresql.service"
        ++ lib.optional cfg.localRedis "redis-sovra.service";
      wants = lib.optional cfg.localPostgres "postgresql.service"
        ++ lib.optional cfg.localRedis "redis-sovra.service";
      wantedBy = [ "multi-user.target" ];

      environment = {
        PHX_SERVER = "true";
        PHX_HOST = cfg.domain;
        PORT = toString cfg.port;
        DATABASE_URL = cfg.databaseUrl;
        RELEASE_TMP = "/tmp/sovra";
      };

      serviceConfig = {
        Type = "exec";
        User = "sovra";
        Group = "sovra";
        WorkingDirectory = "/var/lib/sovra";
        ExecStart = "${cfg.backendPath}/bin/sovra start";
        ExecStop = "${cfg.backendPath}/bin/sovra stop";
        Restart = "on-failure";
        RestartSec = 5;

        # Read SECRET_KEY_BASE from file and write it to an EnvironmentFile.
        # The "+" prefix runs as root so we can read the secret file,
        # then the main process runs as sovra with the env loaded.
        ExecStartPre = "+" + (pkgs.writeShellScript "sovra-env" ''
          SECRET_KEY_BASE=$(cat ${cfg.secretKeyBaseFile})
          echo "SECRET_KEY_BASE=$SECRET_KEY_BASE" > /run/sovra/env
          chmod 600 /run/sovra/env
          chown sovra:sovra /run/sovra/env
        '');
        EnvironmentFile = "/run/sovra/env";
        RuntimeDirectory = "sovra";

        # Security hardening
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ReadWritePaths = [ "/var/lib/sovra" "/tmp/sovra" ];
      };
    };

    # ── PostgreSQL ──────────────────────────────────────────────────────────
    services.postgresql = lib.mkIf cfg.localPostgres {
      enable = true;
      ensureDatabases = [ "sovra_prod" ];
      ensureUsers = [{
        name = "sovra";
        ensureDBOwnership = true;
      }];
    };

    # ── Redis ───────────────────────────────────────────────────────────────
    services.redis.servers.sovra = lib.mkIf cfg.localRedis {
      enable = true;
      port = 6379;
      bind = "127.0.0.1";
    };

    # ── Nginx reverse proxy ─────────────────────────────────────────────────
    services.nginx = lib.mkIf cfg.nginx.enable {
      enable = true;
      recommendedProxySettings = true;
      recommendedTlsSettings = true;
      recommendedOptimisation = true;
      recommendedGzipSettings = true;

      virtualHosts.${cfg.domain} = {
        forceSSL = cfg.nginx.enableACME;
        enableACME = cfg.nginx.enableACME;

        # API routes → Phoenix backend
        locations."/api" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          proxyWebsockets = true;
        };

        # WebSocket endpoint
        locations."/live" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          proxyWebsockets = true;
        };

        # Issuer frontend at / (SPA with fallback to index.html)
        locations."/" = if cfg.issuerPath != null then {
          root = cfg.issuerPath;
          tryFiles = "$uri $uri/ /index.html";
        } else {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          proxyWebsockets = true;
        };
      };
    };

    # ── ACME ────────────────────────────────────────────────────────────────
    security.acme = lib.mkIf (cfg.nginx.enable && cfg.nginx.enableACME) {
      acceptTerms = true;
    };

    # ── Firewall ────────────────────────────────────────────────────────────
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.nginx.enable [ 80 443 ];
  };
}
