# Example NixOS configuration for a Sovra server.
#
# This file is a reference — adapt it to your server's configuration.nix.
#
# Prerequisites on the server:
#   1. NixOS installed
#   2. Tailscale enabled for SSH access from CI
#   3. A `deploy` user with sudo access to `systemctl restart sovra`
#   4. Secret key base stored at the configured path
#   5. /opt/sovra/backend and /opt/sovra/issuer directories owned by `deploy`
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

  # Deploy user — CI connects as this user via Tailscale SSH
  users.users.deploy = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
  };

  # Allow deploy user to restart Sovra and run rsync to /opt/sovra
  security.sudo.extraRules = [{
    users = [ "deploy" ];
    commands = [
      { command = "/run/current-system/sw/bin/systemctl restart sovra"; options = [ "NOPASSWD" ]; }
    ];
  }];

  # Ensure deploy directories exist
  systemd.tmpfiles.rules = [
    "d /opt/sovra/backend 0755 deploy deploy -"
    "d /opt/sovra/issuer 0755 deploy deploy -"
  ];
}
