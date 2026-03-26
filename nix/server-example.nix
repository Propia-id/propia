# Example NixOS configuration for a Sovra server.
#
# This file is a reference — adapt it to your server's configuration.nix.
#
# Prerequisites on the server:
#   1. NixOS installed
#   2. Tailscale enabled for SSH access from CI
#   3. An `admin` user with sudo access (created by nixos-infect)
#   4. Secret key base stored at the configured path
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
    secretKeyBaseFile = "/run/secrets/sovra-secret-key-base";
    databaseUrl = "ecto://sovra:password@localhost/sovra_prod";
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
