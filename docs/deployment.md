# Deployment

## Overview

Sovra deploys to a **NixOS** server. The first deploy sets up the server infrastructure (Nginx, PostgreSQL, Redis, systemd services). Subsequent deploys use the **CD workflow** to update application code via GitHub Actions.

| | First deploy | CD workflow |
|---|---|---|
| **What** | NixOS config + server infrastructure | Backend release + issuer static files |
| **How** | `nixos-rebuild switch` on server | rsync artifacts + `systemctl restart` |
| **When** | Once (or when infra changes) | Every code deploy |

## Architecture

```
GitHub Actions (CD)
  │
  │  1. nix build .#sovra-backend
  │  2. nix build .#sovra-issuer
  │
  │  3. Tailscale SSH
  ▼
NixOS Server
  ├── /opt/sovra/backend/    ← rsync from CI
  ├── /opt/sovra/issuer/     ← rsync from CI
  │
  ├── Nginx (port 443)
  │   ├── /        → issuer static files
  │   ├── /api/*   → Phoenix backend (proxy)
  │   └── /live/*  → Phoenix WebSocket (proxy)
  │
  ├── sovra.service          ← Phoenix on port 4000
  ├── PostgreSQL
  └── Redis
```

## Server Setup

### 1. Install NixOS

Start from a fresh [NixOS installation](https://nixos.org/manual/nixos/stable/#sec-installation). After install you'll have:

- `/etc/nixos/configuration.nix` -- system config
- `/etc/nixos/hardware-configuration.nix` -- auto-generated hardware config

### 2. Migrate to flake-based config (if using nixos-infect)

If your server was provisioned with `nixos-infect`, it uses **channel-based** NixOS with a pattern like:

```nix
let
  unstable = import <nixos-unstable> { config = {}; overlays = []; };
in { config, lib, pkgs, ... }: {
  imports = [ ./hardware-configuration.nix ./networking.nix ];
  # ...
}
```

To use the Sovra NixOS module, convert to a flake:

1. Remove the `let unstable = import <nixos-unstable> ...` block from `configuration.nix`
2. Change the function signature to accept `unstable` via specialArgs: `{ config, lib, pkgs, unstable, ... }:`
3. Create `/etc/nixos/flake.nix` (below) which passes `unstable` and imports the Sovra module
4. Run `nixos-rebuild switch --flake /etc/nixos#sovra-server` instead of `nixos-rebuild switch`

Create `/etc/nixos/flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    sovra.url = "git+ssh://git@github.com/lambdaclass/sovra";
  };

  outputs = { nixpkgs, nixpkgs-unstable, sovra, ... }: {
    nixosConfigurations.sovra-server = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = {
        inherit sovra;
        unstable = nixpkgs-unstable.legacyPackages.x86_64-linux;
      };
      modules = [
        ./hardware-configuration.nix
        ./configuration.nix
        sovra.nixosModules.sovra
      ];
    };
  };
}
```

### 3. Configure the Sovra service

Add to `/etc/nixos/configuration.nix`:

```nix
{ sovra, ... }: {
  # Enable flakes
  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # Sovra service
  services.sovra = {
    enable = true;
    domain = "yourdomain.com";
    backendPath = "/opt/sovra/backend";
    issuerPath = "/opt/sovra/issuer";
    envFile = "/etc/sovra/env";
    nginx.acmeEmail = "admin@yourdomain.com";
  };

  # Tailscale for CI access
  services.tailscale.enable = true;

  # Allow admin to restart Sovra without password (used by CI)
  security.sudo.extraRules = [{
    users = [ "admin" ];
    commands = [
      { command = "/run/current-system/sw/bin/systemctl restart sovra";
        options = [ "NOPASSWD" ]; }
    ];
  }];

  # Create deploy directories
  systemd.tmpfiles.rules = [
    "d /opt/sovra/backend 0755 admin users -"
    "d /opt/sovra/issuer 0755 admin users -"
  ];
}
```

See [`nix/server-example.nix`](../nix/server-example.nix) for a complete reference.

### 4. Create the env file and apply

Create `/etc/sovra/env` with all required secrets:

```bash
sudo mkdir -p /etc/sovra
sudo tee /etc/sovra/env > /dev/null <<'EOF'
DATABASE_URL=ecto://sovra@localhost/sovra
SECRET_KEY_BASE=<run: openssl rand -base64 64 | tr -d '\n'>
GUARDIAN_SESSION_SECRET=<run: openssl rand -base64 64 | tr -d '\n'>
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/api/v1/holder/auth/callback
EOF
sudo chmod 600 /etc/sovra/env

# Apply the configuration
nixos-rebuild switch --flake /etc/nixos#sovra-server
```

This sets up PostgreSQL, Redis, Nginx (with Let's Encrypt TLS), the systemd service, and firewall rules.

### 5. Connect Tailscale

```bash
tailscale up
```

Note the Tailscale hostname -- you'll need it for the `DEPLOY_HOST` GitHub secret.

## CD Workflow

After the server is set up, all subsequent deploys happen via the **CD workflow** (`.github/workflows/cd.yml`), triggered manually from the GitHub Actions UI ("Run workflow" button).

The workflow:

1. Builds backend (`nix build .#sovra-backend`) and issuer (`nix build .#sovra-issuer`)
2. Connects to the server via Tailscale SSH
3. Rsyncs artifacts to `/opt/sovra/backend/` and `/opt/sovra/issuer/`
4. Restarts the `sovra` systemd service

### Required GitHub Secrets

| Secret | Description |
|---|---|
| `TS_OAUTH_CLIENT_ID` | Tailscale OAuth client ID (create at [admin.tailscale.com](https://login.tailscale.com/admin/settings/oauth), tag: `ci`). Stored as a **variable**, not a secret. |
| `TS_OAUTH_SECRET` | Tailscale OAuth client secret |
| `DEPLOY_HOST` | Tailscale hostname of the server |

### When to re-run `nixos-rebuild`

The CD workflow only updates application code. You need to SSH into the server and run `nixos-rebuild switch` if you change:

- The NixOS module (`nix/nixos-module.nix`) -- e.g. new env vars, nginx config, systemd settings
- The server's `configuration.nix` -- e.g. new users, firewall rules, packages
- The flake input version of Sovra on the server

## Environment Variables

All runtime config lives in `/etc/sovra/env` on the server. This file is loaded by both the systemd service and the migration command.

Required:

| Variable | Description |
|---|---|
| `DATABASE_URL` | Ecto database URL (e.g. `ecto://sovra@localhost/sovra`) |
| `SECRET_KEY_BASE` | Cookie/session signing key (64+ chars) |
| `GUARDIAN_SESSION_SECRET` | Session signing secret |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID (wallet auth) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | OAuth callback URL |

Set automatically by the NixOS module (not in env file):

| Variable | Description |
|---|---|
| `PHX_HOST` | Public domain name (from `services.sovra.domain`) |
| `PHX_SERVER` | Always `true` |
| `PORT` | Phoenix listen port (default 4000) |

Optional (for on-chain features):

| Variable | Description |
|---|---|
| `ADMIN_PRIVATE_KEY` | Ethereum admin key for contract interactions |
| `L2_RPC_URL` | SovraChain RPC endpoint |
| `DID_REGISTRY_ADDRESS` | Deployed DID registry contract address |
| `ISSUER_REGISTRY_ADDRESS` | Deployed issuer registry contract address |

## Local Testing

Build and run the production release locally:

```bash
make deploy.local       # Build + start (backend :4000, issuer :3000)
make deploy.local.stop  # Stop both
make deploy.build       # Build only (no start)
```

This uses your local dev database and placeholder secrets. OAuth won't work but the server will start and serve API requests.

## Nix Packages

| Package | Build command | Description |
|---|---|---|
| `sovra-backend` | `nix build .#sovra-backend` | Elixir Mix release |
| `sovra-issuer` | `nix build .#sovra-issuer` | Vite/React static build |

Defined in [`nix/packages.nix`](../nix/packages.nix), exposed via [`flake.nix`](../flake.nix).

## File Reference

| File | Purpose |
|---|---|
| `.github/workflows/cd.yml` | CD workflow (workflow_dispatch) |
| `nix/packages.nix` | Nix derivations for backend + issuer |
| `nix/nixos-module.nix` | NixOS service module (systemd, nginx, postgres, redis) |
| `nix/server-example.nix` | Reference server configuration |
| `flake.nix` | Flake outputs (packages, devShell, nixosModule) |
