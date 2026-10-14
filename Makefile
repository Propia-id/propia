# --no-warn-dirty: an uncommitted working tree is the normal state here, and
# nix would otherwise prefix every single target's output with a warning.
NIX := nix develop --no-warn-dirty --command bash -c

# Backend commands read backend/.env themselves, so `make backend.*` works from
# a bare shell with nothing exported first. The file is dev-only and optional:
# CI and the nix release build have none and take their values from the real
# environment.
BACKEND_ENV := set -a; [ -f .env ] && . ./.env; set +a;

# The inverse, for the test suite: unset exactly the names backend/.env
# declares, so the suite cannot inherit them from the caller's shell.
BACKEND_ENV_CLEAR := [ -f .env ] && for v in $$(sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' .env); do unset $$v; done;

# ── Services ─────────────────────────────────────────────────────────

.PHONY: services.start services.stop services.status pg.start pg.stop pg.status

services.start: pg.start

services.stop: pg.stop

services.status: pg.status

pg.start:
	$(NIX) "mkdir -p .pg-socket && pg_ctl status -D .pg-data >/dev/null 2>&1 || pg_ctl start -D .pg-data -l .pg-data/postgres.log -o \"-k $$PWD/.pg-socket -c listen_addresses=\""

pg.stop:
	$(NIX) "pg_ctl stop -D .pg-data 2>/dev/null || true"

pg.status:
	$(NIX) "pg_ctl status -D .pg-data || true"

# ── Top-level ────────────────────────────────────────────────────────
# NOTE: `make setup` requires PostgreSQL running (`make services.start`) and a
# local chain listening (see README).

.PHONY: setup format lint build check test

setup: backend.setup backend.db.create contracts.setup contracts.deploy frontend.setup

format: backend.format

lint: backend.lint contracts.lint

build: backend.build contracts.build

check: frontend.packages.check

test: backend.test contracts.test frontend.packages.test

# ── Dev ──────────────────────────────────────────────────────────────

.PHONY: shell backend.start

shell:
	nix develop

backend.start:
	$(NIX) "cd backend && $(BACKEND_ENV) mix deps.get && iex -S mix phx.server"

# ── Setup ────────────────────────────────────────────────────────────

.PHONY: backend.setup backend.db.create contracts.setup contracts.deploy frontend.setup

backend.setup:
	$(NIX) "cd backend && $(BACKEND_ENV) mix local.hex --force && mix local.rebar --force && mix deps.get"

backend.db.create:
	$(NIX) "cd backend && $(BACKEND_ENV) mix ecto.setup"

contracts.setup:
	$(NIX) "cd contracts && npm ci"

# Target network: a key of contracts/chain/config.json, which decides who gets
# the on-chain roles. Defaults to a local Anvil node on 127.0.0.1:8545 — see
# the README. `ethrex` targets a local ethrex L2 on 127.0.0.1:1729 instead.
NETWORK ?= anvil

# contracts/.openzeppelin is keyed by chain ID alone, so a wiped and restarted
# local chain reuses its id and inherits records for implementations that no
# longer exist, aborting the deploy on the first one it looks up. It is
# untracked state and a local deploy always starts from scratch, so drop it.
contracts.deploy:
	$(NIX) "cd contracts && case $(NETWORK) in ethrex|anvil) rm -rf .openzeppelin;; esac && npx hardhat run scripts/deploy.ts --network $(NETWORK)"

frontend.setup:
	$(NIX) "cd frontend && pnpm install --frozen-lockfile"

# ── Backend ──────────────────────────────────────────────────────────

.PHONY: backend.format backend.lint backend.build backend.test backend.db.setup backend.db.migrate backend.db.reset

backend.format:
	$(NIX) "cd backend && $(BACKEND_ENV) mix format"

backend.lint:
	$(NIX) "cd backend && $(BACKEND_ENV) mix format --check-formatted"

backend.build:
	$(NIX) "cd backend && $(BACKEND_ENV) mix compile"

# $(BACKEND_ENV_CLEAR), not $(BACKEND_ENV): config/runtime.exs reads registry
# addresses and the identity source in every env, test included. Left in place
# they would hand the suite a developer's real configuration, so a green run
# here would say nothing. The suite's config lives in config/test.exs.
backend.test:
	$(NIX) "cd backend && $(BACKEND_ENV_CLEAR) mix test"

backend.db.setup:
	$(NIX) "cd backend && $(BACKEND_ENV) mix ecto.setup"

backend.db.migrate:
	$(NIX) "cd backend && $(BACKEND_ENV) mix ecto.migrate"

backend.db.reset:
	$(NIX) "cd backend && $(BACKEND_ENV) mix ecto.reset"

# ── Contracts ────────────────────────────────────────────────────────

.PHONY: contracts.lint contracts.build contracts.test

contracts.lint:
	$(NIX) "cd contracts && npx hardhat check"

contracts.build:
	$(NIX) "cd contracts && npx hardhat compile"

contracts.test:
	$(NIX) "cd contracts && npx hardhat test"

# ── SDKs ─────────────────────────────────────────────────────────────

.PHONY: frontend.packages.check frontend.packages.test \
        frontend.packages.holder-core.check frontend.packages.holder-core.test \
        frontend.packages.verification-sdk.check frontend.packages.verification-sdk.test

frontend.packages.check: frontend.packages.holder-core.check frontend.packages.verification-sdk.check

frontend.packages.test: frontend.packages.holder-core.test frontend.packages.verification-sdk.test

frontend.packages.holder-core.check:
	$(NIX) "cd frontend && pnpm --filter @sovrahq/holder-core typecheck"

frontend.packages.holder-core.test:
	$(NIX) "cd frontend && pnpm --filter @sovrahq/holder-core test"

frontend.packages.verification-sdk.check:
	$(NIX) "cd frontend && pnpm --filter @sovrahq/verification-sdk typecheck"

frontend.packages.verification-sdk.test:
	$(NIX) "cd frontend && pnpm --filter @sovrahq/verification-sdk test"
