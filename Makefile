# --no-warn-dirty: an uncommitted working tree is the normal state here, and
# nix would otherwise prefix every single target's output with a warning.
NIX := nix develop --no-warn-dirty --command bash -c

# Backend commands read backend/.env themselves, so `make backend.*` works from
# a bare shell with nothing exported first. The file is dev-only and optional:
# CI, the nix release build and the deployed nodes have none and take their
# values from the real environment.
BACKEND_ENV := set -a; [ -f .env ] && . ./.env; set +a;

# The inverse, for the test suite: unset exactly the names backend/.env
# declares. direnv exports that file repo-wide, so the suite would otherwise
# inherit it from the caller's shell no matter what this Makefile sources.
# Derived from the file rather than a hand-kept list, so a new key there can't
# silently leak into a test run.
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
# NOTE: `make setup` requires services running (`make services.start`)

.PHONY: setup format lint build check test

setup: backend.setup backend.db.create contracts.setup contracts.deploy frontend.setup

format: backend.format

lint: backend.lint contracts.lint frontend.issuer.lint

build: backend.build contracts.build frontend.issuer.build

check: frontend.packages.check frontend.wallet.check frontend.verifier.check frontend.e2e.check

test: backend.test contracts.test frontend.packages.test frontend.verifier.test frontend.e2e.test

# ── Dev ──────────────────────────────────────────────────────────────

.PHONY: shell backend.start wallet.start verifier.start issuer.start

shell:
	nix develop

backend.start:
	$(NIX) "cd backend && $(BACKEND_ENV) mix deps.get && iex -S mix phx.server"

wallet.start:
	$(NIX) "cd frontend && pnpm --filter @sovra/wallet start"

verifier.start:
	$(NIX) "cd frontend && pnpm --filter @sovra/verifier start"

issuer.start:
	$(NIX) "cd frontend && pnpm --filter @sovra/issuer dev"

# ── Setup ────────────────────────────────────────────────────────────

.PHONY: backend.setup backend.db.create contracts.setup contracts.deploy frontend.setup

backend.setup:
	$(NIX) "cd backend && $(BACKEND_ENV) mix local.hex --force && mix local.rebar --force && mix deps.get"

backend.db.create:
	$(NIX) "cd backend && $(BACKEND_ENV) mix ecto.setup"

contracts.setup:
	$(NIX) "cd contracts && npm ci"

# Target network: a key of contracts/chain/config.json, which decides who gets
# the on-chain roles. Defaults to the local ethrex L2; the shared chains are
# `make contracts.deploy NETWORK=sovrachain[-sepolia]` and need RPC_URL set,
# since they grant their roles to the shared chain's addresses rather than to
# the local node's genesis account.
NETWORK ?= ethrex

# contracts/.openzeppelin is keyed by chain ID alone, so a wiped and restarted
# local chain reuses 65536999 and inherits records for implementations that no
# longer exist, aborting the deploy on the first one it looks up. It is
# untracked state and a local deploy always starts from scratch, so drop it —
# but only for the local networks: on the shared chains that manifest is the
# upgrade history of a chain nobody can restart.
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

# $(BACKEND_ENV_CLEAR), not $(BACKEND_ENV): CI runs the suite with no .env, and
# config/runtime.exs reads ADMIN_PRIVATE_KEY, SOVRA_IDENTITY_SOURCE and the
# registry addresses in every env, test included. Left in place they hand the
# suite the real relayer key and `identity_source: :aligned`, so a green run
# here would say nothing about CI. The suite's config lives in config/test.exs.
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

# ── Frontend Packages ────────────────────────────────────────────────

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

# ── Frontend E2E ─────────────────────────────────────────────────────

.PHONY: frontend.e2e.check frontend.e2e.test frontend.e2e.test.live

frontend.e2e.check:
	$(NIX) "cd frontend && pnpm --filter @sovra/e2e typecheck"

# Offline: no secrets, no network.
frontend.e2e.test:
	$(NIX) "cd frontend && pnpm --filter @sovra/e2e test"

# Live: runs against a DEPLOYED environment. Kept out of `make test` so no
# routine run can reach test or prod.
frontend.e2e.test.live:
	$(NIX) "cd frontend && pnpm --filter @sovra/e2e test:live"

# ── Frontend Issuer ──────────────────────────────────────────────────

.PHONY: frontend.issuer.lint frontend.issuer.build

frontend.issuer.lint:
	$(NIX) "cd frontend && pnpm --filter @sovra/issuer lint"

frontend.issuer.build:
	$(NIX) "cd frontend && pnpm --filter @sovra/issuer build"

# ── Frontend Wallet ──────────────────────────────────────────────────

.PHONY: frontend.wallet.check frontend.wallet.bundle \
	wallet.build.android wallet.build.ios

frontend.wallet.check:
	$(NIX) "cd frontend && pnpm --filter @sovra/wallet typecheck"

# Bundle the wallet through Metro, which typecheck does not exercise.
#
# The @sovrahq/* packages are consumed from TypeScript source and carry the
# explicit `./x/index.js` specifiers NodeNext requires, so tsc resolves them
# happily while Metro does not — a mismatch that otherwise surfaces for the
# first time inside gradle/xcodebuild on release day. BRAND/ENV are read by
# brands/resolve.js, so this picks an app without writing brands/.active.
frontend.wallet.bundle:
	$(NIX) "cd frontend/wallet && BRAND=sovra ENV=prod pnpm exec expo export --platform android --output-dir \$$(mktemp -d)"

wallet.build.android:
	cd frontend/wallet && pnpm run build:android

wallet.build.ios:
	cd frontend/wallet && pnpm run build:ios

# ── Frontend Verifier ────────────────────────────────────────────────

.PHONY: frontend.verifier.check frontend.verifier.test \
	verifier.build.android verifier.build.ios

frontend.verifier.check:
	$(NIX) "cd frontend && pnpm --filter @sovra/verifier typecheck"

frontend.verifier.test:
	$(NIX) "cd frontend && pnpm --filter @sovra/verifier test"

# Native builds must NOT run inside the nix shell: its clang rejects the
# -index-store-path flag Xcode passes, failing every Pod compile.
verifier.build.android:
	cd frontend/verifier && pnpm run build:android

verifier.build.ios:
	cd frontend/verifier && pnpm run build:ios

# ── Deploy ──────────────────────────────────────────────────────────

.PHONY: deploy.build deploy.local deploy.local.stop

deploy.build:
	nix build .#sovra-backend --print-build-logs
	nix build .#sovra-issuer --print-build-logs

deploy.local: deploy.build
	@echo "Starting Sovra locally from release builds..."
	@echo ""
	@echo "  Backend: http://localhost:4000/api"
	@echo "  Issuer:  http://localhost:3000"
	@echo ""
	@# Serve the issuer frontend in the background
	@$(NIX) "npx serve $$(nix path-info .#sovra-issuer) -l 3000 &"
	@# Start the backend release
	SECRET_KEY_BASE=$$($(NIX) "cd backend && mix phx.gen.secret") \
	DATABASE_URL="ecto://postgres:postgres@localhost/sovra_dev" \
	GUARDIAN_SESSION_SECRET="local-dev-secret-min-64-chars-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	GOOGLE_CLIENT_ID="fake" \
	GOOGLE_CLIENT_SECRET="fake" \
	GOOGLE_REDIRECT_URI="http://localhost:4000/auth/google/callback" \
	PHX_HOST="localhost" \
	PHX_SERVER="true" \
	PORT=4000 \
		$$(nix path-info .#sovra-backend)/bin/sovra start

deploy.local.stop:
	@$$(nix path-info .#sovra-backend)/bin/sovra stop 2>/dev/null || true
	@pkill -f "serve.*sovra-issuer" 2>/dev/null || true
	@echo "Stopped."
