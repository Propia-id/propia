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
#   STORED_KEYS_ENCRYPTION_KEY=<base64 of 32 bytes, e.g. openssl rand -base64 32>
#   GOOGLE_CLIENT_ID=<id>
#   GOOGLE_CLIENT_SECRET=<secret>
#   GOOGLE_REDIRECT_URI=https://yourdomain.com/wallet/auth/callback
#   SIGNER_URL=<KMS signer service URL, e.g. http://sovra-signer:4001>
#   SIGNER_TOKEN=<shared bearer token for the signer RPC>
#   POSTMARK_API_KEY=<Postmark server API token>
#   EMAIL_FROM_ADDRESS=<sender verified on the Postmark account>

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
        STORED_KEYS_ENCRYPTION_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
        GOOGLE_REDIRECT_URI, SIGNER_URL + SIGNER_TOKEN (to reach the KMS
        signer service), and POSTMARK_API_KEY + EMAIL_FROM_ADDRESS (to send
        transactional email).
        Optionally REVOCATION_REGISTRY_ADDRESS for on-chain credential
        revocation.
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

    # Cryptographic signing (P-256 workspace keys) is handled by AWS KMS via a
    # dedicated signer service reached over the network — see SIGNER_URL /
    # SIGNER_TOKEN in the env file. This module runs only the API tier; the
    # signer service itself is provisioned separately (fleet infra).

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
        ++ lib.optional cfg.localPostgres "postgresql.service";
      wants = lib.optional cfg.localPostgres "postgresql.service";
      wantedBy = [ "multi-user.target" ];

      environment = {
        PHX_SERVER = "true";
        PHX_HOST = cfg.domain;
        PORT = toString cfg.port;
        ISSUER_BASE_URL = "https://${cfg.domain}";
        ISSUER_FRONTEND_URL = "https://${cfg.domain}";
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
