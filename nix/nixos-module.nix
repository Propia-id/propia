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
#     envFile = "/etc/sovra/env";
#     nginx.acmeEmail = "admin@example.com";
#   };
#
# The env file must contain at minimum:
#   DATABASE_URL=ecto://sovra@localhost/sovra
#   SECRET_KEY_BASE=<64+ char secret>
#   GUARDIAN_SESSION_SECRET=<secret>
#   GOOGLE_CLIENT_ID=<id>
#   GOOGLE_CLIENT_SECRET=<secret>
#   GOOGLE_REDIRECT_URI=https://yourdomain.com/wallet/auth/callback
#   VAULT_TOKEN=<OpenBao app token>

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

    envFile = lib.mkOption {
      type = lib.types.path;
      default = "/etc/sovra/env";
      description = ''
        Path to environment file containing all runtime secrets and config.
        Must contain DATABASE_URL, SECRET_KEY_BASE, GUARDIAN_SESSION_SECRET,
        GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
        and VAULT_TOKEN. Optionally REVOCATION_REGISTRY_ADDRESS for
        on-chain credential revocation.
      '';
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

    localVault = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to run a local OpenBao instance for Transit key management.";
    };

    kmsKeyId = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "AWS KMS key ID for OpenBao auto-unseal. When set, OpenBao uses KMS instead of Shamir.";
      example = "alias/openbao-unseal";
    };

    kmsRegion = lib.mkOption {
      type = lib.types.str;
      default = "us-east-1";
      description = "AWS region for the KMS key used for auto-unseal.";
    };

    vaultEnvFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to environment file for the OpenBao service (e.g., AWS credentials for KMS auto-unseal).";
      example = "/etc/openbao/env";
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

      acmeEmail = lib.mkOption {
        type = lib.types.str;
        description = "Email address for ACME/Let's Encrypt certificate registration.";
        example = "admin@example.com";
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
        ++ lib.optional cfg.localRedis "redis-sovra.service"
        ++ lib.optional cfg.localVault "openbao.service";
      wants = lib.optional cfg.localPostgres "postgresql.service"
        ++ lib.optional cfg.localRedis "redis-sovra.service"
        ++ lib.optional cfg.localVault "openbao.service";
      wantedBy = [ "multi-user.target" ];

      environment = {
        PHX_SERVER = "true";
        PHX_HOST = cfg.domain;
        PORT = toString cfg.port;
        ISSUER_BASE_URL = "https://${cfg.domain}";
        ISSUER_FRONTEND_URL = "https://${cfg.domain}";
      } // lib.optionalAttrs cfg.localVault {
        VAULT_ADDR = "http://127.0.0.1:8200";
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

        # Load all secrets and config from the env file
        EnvironmentFile = cfg.envFile;

        # Security hardening
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ReadWritePaths = [ "/var/lib/sovra" ];
      };
    };

    # ── PostgreSQL ──────────────────────────────────────────────────────────
    services.postgresql = lib.mkIf cfg.localPostgres {
      enable = true;
      ensureDatabases = [ "sovra" ];
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

    # ── OpenBao (Transit key store) ────────────────────────────────────────
    systemd.tmpfiles.rules = lib.mkIf cfg.localVault [
      "d /var/lib/openbao/data 0700 openbao openbao -"
    ];

    systemd.services.openbao = lib.mkIf cfg.localVault {
      description = "OpenBao Secret Management";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "exec";
        User = "openbao";
        Group = "openbao";
        StateDirectory = "openbao";
        ExecStart = "${pkgs.openbao}/bin/bao server -config=/etc/openbao/config.hcl";
        Restart = "on-failure";
        RestartSec = 5;
      } // lib.optionalAttrs (cfg.vaultEnvFile != null) {
        EnvironmentFile = cfg.vaultEnvFile;
      } // {
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ReadWritePaths = [ "/var/lib/openbao" ];
      };
    };

    users.users.openbao = lib.mkIf cfg.localVault {
      isSystemUser = true;
      group = "openbao";
      home = "/var/lib/openbao";
      createHome = true;
    };
    users.groups.openbao = lib.mkIf cfg.localVault {};

    environment.systemPackages = lib.mkIf cfg.localVault [ pkgs.openbao ];

    environment.etc."openbao/config.hcl" = lib.mkIf cfg.localVault {
      text = ''
        storage "raft" {
          path = "/var/lib/openbao/data"
          node_id = "sovra-1"
        }

        # TLS is disabled because the listener is bound to localhost only.
        # Any process that could sniff loopback traffic already has
        # privileges to read the token from the env file directly,
        # so TLS would not add meaningful protection here.
        listener "tcp" {
          address     = "127.0.0.1:8200"
          tls_disable = 1
        }

        api_addr     = "http://127.0.0.1:8200"
        cluster_addr = "http://127.0.0.1:8201"

        ${lib.optionalString (cfg.kmsKeyId != null) ''
        seal "awskms" {
          region     = "${cfg.kmsRegion}"
          kms_key_id = "${cfg.kmsKeyId}"
        }
        ''}
      '';
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

        # API-key endpoints → Phoenix backend
        locations."/api" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          proxyWebsockets = true;
        };

        # Staff dashboard endpoints → Phoenix backend
        locations."/dashboard" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          proxyWebsockets = true;
        };

        # Wallet-facing endpoints (OID4VCI, OID4VP, holder auth, recovery) → Phoenix backend
        locations."/wallet" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          proxyWebsockets = true;
        };

        # OpenAPI specs (dashboard/wallet/api) → Phoenix backend
        locations."/openapi" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
        };

        # WebSocket endpoint
        locations."/live" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          proxyWebsockets = true;
        };

        # Well-known metadata → Phoenix backend.
        # Matches at any path depth so it covers both shapes:
        #   /.well-known/oauth-authorization-server/<workspace_did>   (RFC 8414)
        #   /<workspace_did>/.well-known/openid-credential-issuer     (OID4VCI 1.0)
        locations."~ /\\.well-known/" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
        };

        # Health check → Phoenix backend
        locations."/health" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
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
      defaults.email = cfg.nginx.acmeEmail;
    };

    # ── Firewall ────────────────────────────────────────────────────────────
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.nginx.enable [ 80 443 ];
  };
}
