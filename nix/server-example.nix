# Example NixOS configuration for a Sovra server.
#
# This file is a reference — adapt it to your server's configuration.nix.
#
# Prerequisites on the server:
#   1. NixOS installed
#   2. Tailscale enabled for SSH access from CI
#   3. An `admin` user with sudo access (created by nixos-infect)
#   4. Env file at /etc/sovra/env with all required secrets (incl. SIGNER_URL /
#      SIGNER_TOKEN pointing at the KMS signer service — see docs/deployment.md)
#
# Required GitHub Secrets:
#   - TS_OAUTH_CLIENT_ID / TS_OAUTH_SECRET — Tailscale OAuth client credentials
#   - DEPLOY_HOST — Tailscale hostname of this server (e.g. "sovra-server")

{ sovra, ... }:

{
  imports = [ sovra.nixosModules.sovra ];

  services.sovra = {
    enable = true;
    domain = "sovra.example.com";
    backendPath = "/opt/sovra/backend";
    issuerPath = "/opt/sovra/issuer";
    envFile = "/etc/sovra/env";
    nginx.acmeEmail = "admin@example.com";
  };

  # Tailscale for secure access from CI
  services.tailscale.enable = true;

  # Allow admin user to restart Sovra (used by CI)
  security.sudo.extraRules = [{
    users = [ "admin" ];
    commands = [
      { command = "/run/current-system/sw/bin/systemctl restart sovra"; options = [ "NOPASSWD" ]; }
    ];
  }];

  # Ensure deploy directories exist
  systemd.tmpfiles.rules = [
    "d /opt/sovra/backend 0755 admin users -"
    "d /opt/sovra/issuer 0755 admin users -"
  ];
}
