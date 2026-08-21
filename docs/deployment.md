# Deployment

> **Note:** Production now runs on the multi-host **fleet** (Terraform + Ansible)
> — see [`../infra/README.md`](../infra/README.md) and
> [`../infra/CICD.md`](../infra/CICD.md). This document describes the older
> **single-host NixOS** path, kept for a single-box or dev deploy. Its automated
> CD workflow (`.github/workflows/cd.yml`) has been **retired**, so single-host
> deploys are now manual (build artifacts → copy → `systemctl restart`).

## Overview

Sovra deploys to a **NixOS** server. The first deploy sets up the server infrastructure (Nginx, PostgreSQL, systemd services). Subsequent deploys update application code (backend release + issuer static files).

| | First deploy | Code deploy |
|---|---|---|
| **What** | NixOS config + server infrastructure | Backend release + issuer static files |
| **How** | `nixos-rebuild switch` on server | copy artifacts + `systemctl restart` |
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
  └── PostgreSQL
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

### 4. KMS signer service (SIGNER_URL / SIGNER_TOKEN)

Cryptographic signing of the P-256 workspace/issuer keys is delegated to AWS
KMS through a dedicated **signer service** (`SERVICE=signer`, the same release
run in a slim tree). The API host holds **no AWS credentials** — it makes an
authenticated RPC to the signer over the network:

- `SIGNER_URL` — the signer's base URL (e.g. `http://sovra-signer:4001`)
- `SIGNER_TOKEN` — a shared bearer token, identical on the API host and the signer

The signer is the sole KMS caller. On AWS it obtains credentials from its EC2
**instance role via IMDS** (no static keys); its IAM policy grants
`kms:CreateKey` / `kms:Sign` / `kms:GetPublicKey` / `kms:ScheduleKeyDeletion` on
the P-256 workspace keys and `kms:Sign` / `kms:GetPublicKey` on the secp256k1
**relayer** key (on-chain signing, `RELAYER_KMS_KEY_ID`). Provisioning the
signer host itself is handled by the infrastructure fleet (Terraform/Ansible)
and is out of scope for this single-host guide — here you only need a reachable
`SIGNER_URL` and a matching `SIGNER_TOKEN`.

> The webhook HMAC secret is **not** in KMS: it must be revealed to the customer
> once (to verify our signatures) and KMS HMAC keys are non-exportable, so it is
> stored in the database and HMAC'd locally.

### 5. Create the env file

Create `/etc/sovra/env` with all required secrets:

```bash
sudo mkdir -p /etc/sovra
sudo tee /etc/sovra/env > /dev/null <<EOF
DATABASE_URL=ecto://sovra:sovra@localhost/sovra
SECRET_KEY_BASE=$(openssl rand -base64 64 | tr -d '\n')
GUARDIAN_SESSION_SECRET=$(openssl rand -base64 64 | tr -d '\n')
STORED_KEYS_ENCRYPTION_KEY=$(openssl rand -base64 32)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/wallet/auth/callback
SIGNER_URL=http://sovra-signer:4001
SIGNER_TOKEN=<shared bearer token, identical on the signer service>
POSTMARK_API_KEY=<Postmark server API token>
EMAIL_FROM_ADDRESS=no-reply@yourdomain.com
EOF
sudo chmod 600 /etc/sovra/env
sudo chown sovra:sovra /etc/sovra/env
```

Set a password for the PostgreSQL `sovra` user (NixOS creates it with peer auth only):

```bash
sudo -u postgres psql -c "ALTER USER sovra PASSWORD 'sovra';"
```

Optionally, add on-chain config to `/etc/sovra/env` (the backend starts without these, but on-chain features won't work). The relayer that signs on-chain writes has two backends:

- **Production (KMS):** omit `ADMIN_PRIVATE_KEY`; on-chain writes are signed by the signer service's secp256k1 relayer key (`RELAYER_KMS_KEY_ID`, set on the signer node). The API node only needs `SIGNER_URL`/`SIGNER_TOKEN` (already set above) plus the registry addresses.
- **Local (in-process key):** set `ADMIN_PRIVATE_KEY` to sign locally — for dev or a single-host box without a signer.

```bash
# Append to /etc/sovra/env
# ADMIN_PRIVATE_KEY=0x...            # only for the local relayer backend; omit in prod (KMS)
L2_RPC_URL=https://your-l2-rpc-endpoint
DID_REGISTRY_ADDRESS=0x...
ISSUER_REGISTRY_ADDRESS=0x...
REVOCATION_REGISTRY_ADDRESS=0x...
```

# Apply the configuration
nixos-rebuild switch --flake /etc/nixos#sovra-server
```

This sets up PostgreSQL, Nginx (with Let's Encrypt TLS), the systemd service, and firewall rules.

### 6. Connect Tailscale

```bash
tailscale up
```

Note the Tailscale hostname (`$DEPLOY_HOST` below).

## Code deploy (manual)

The automated CD workflow (`.github/workflows/cd.yml`) has been **retired** in favour of the fleet (`infra/`). For a single-host box, deploy application code manually from a machine with Nix + Tailscale SSH to the server (`$DEPLOY_HOST` = the server's Tailscale hostname):

```bash
# Build the backend release + issuer static bundle
nix build .#sovra-backend
nix build .#sovra-issuer

# Copy closures to the server and repoint the deploy symlinks
nix copy --to "ssh://admin@$DEPLOY_HOST" .#sovra-backend .#sovra-issuer
ssh "admin@$DEPLOY_HOST" \
  "sudo ln -sfn $(nix path-info .#sovra-backend) /opt/sovra/backend && \
   sudo ln -sfn $(nix path-info .#sovra-issuer) /opt/sovra/issuer"

# Migrate + restart
ssh "admin@$DEPLOY_HOST" 'set -a; source /etc/sovra/env; /opt/sovra/backend/bin/sovra eval Sovra.Release.migrate'
ssh "admin@$DEPLOY_HOST" "sudo systemctl restart sovra"
```

### When to re-run `nixos-rebuild`

Code deploys only update application code. You need to SSH into the server and run `nixos-rebuild switch` if you change:

- The NixOS module (`nix/nixos-module.nix`) -- e.g. new env vars, nginx config, systemd settings
- The server's `configuration.nix` -- e.g. new users, firewall rules, packages
- The flake input version of Sovra on the server

## Environment Variables

All runtime config lives in `/etc/sovra/env` on the server. This file is loaded by both the systemd service and the migration command.

Required:

| Variable | Description |
|---|---|
| `DATABASE_URL` | Ecto database URL (e.g. `ecto://sovra:sovra@localhost/sovra`) |
| `SECRET_KEY_BASE` | Cookie/session signing key (64+ chars) |
| `GUARDIAN_SESSION_SECRET` | Session signing secret |
| `STORED_KEYS_ENCRYPTION_KEY` | At-rest encryption key for webhook HMAC secrets (base64 of 32 bytes) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID (wallet auth) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | OAuth callback URL |
| `SIGNER_URL` | KMS signer service base URL (e.g. `http://sovra-signer:4001`) |
| `SIGNER_TOKEN` | Shared bearer token for the signer RPC (matches the signer service) |
| `POSTMARK_API_KEY` | Postmark server API token for transactional email |
| `EMAIL_FROM_ADDRESS` | Sender address, must be verified on the Postmark account (e.g. `no-reply@sovra.io`) |

Set automatically by the NixOS module (not in env file):

| Variable | Description |
|---|---|
| `PHX_HOST` | Public domain name (from `services.sovra.domain`) |
| `PHX_SERVER` | Always `true` |
| `PORT` | Phoenix listen port (default 4000) |
| `ISSUER_BASE_URL` | Public issuer URL (`https://<domain>`) |
| `ISSUER_FRONTEND_URL` | Frontend URL for CORS + origin allow-list (`https://<domain>`) |

Optional (on-chain features -- set the registry addresses to enable; the relayer signs via KMS in prod or `ADMIN_PRIVATE_KEY` locally):

| Variable | Description |
|---|---|
| `ADMIN_PRIVATE_KEY` | Local relayer key for signing on-chain writes (dev/local only; omit in prod to use the KMS relayer) |
| `L2_RPC_URL` | SovraChain RPC endpoint (default: `http://127.0.0.1:1729`) |
| `DID_REGISTRY_ADDRESS` | Deployed DID registry contract address |
| `ISSUER_REGISTRY_ADDRESS` | Deployed issuer registry contract address |
| `REVOCATION_REGISTRY_ADDRESS` | Deployed revocation registry contract address |

Optional (tuning):

| Variable | Description |
|---|---|
| `POOL_SIZE` | Database connection pool size (default: 10) |
| `ECTO_IPV6` | Enable IPv6 for database connections (`true`/`1`) |
| `DNS_CLUSTER_QUERY` | DNS query for clustering multiple nodes |
| `EMAIL_FROM_NAME` | Display name on transactional email (default: `Sovra`) |

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
| `nix/packages.nix` | Nix derivations for backend + issuer |
| `nix/nixos-module.nix` | NixOS service module (systemd, nginx, postgres) |
| `nix/server-example.nix` | Reference server configuration |
| `flake.nix` | Flake outputs (packages, devShell, nixosModule) |
