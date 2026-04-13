NIX := nix develop --command bash -c

# ── Top-level ────────────────────────────────────────────────────────
# NOTE: `make setup` requires:
#   - PostgreSQL running on port 5432
#   - Ethereum local node (e.g. hardhat node) running on port 8545

.PHONY: setup format lint build check test

setup: backend.setup backend.db.create contracts.setup contracts.deploy frontend.setup

format: backend.format

lint: backend.lint contracts.lint frontend.issuer.lint

build: backend.build contracts.build frontend.issuer.build

check: frontend.packages.check frontend.wallet.check frontend.verifier.check

test: backend.test contracts.test frontend.packages.test

# ── Dev ──────────────────────────────────────────────────────────────

.PHONY: shell backend.start wallet.start verifier.start issuer.start

shell:
	nix develop

backend.start:
	$(NIX) "cd backend && mix deps.get && iex -S mix phx.server"

wallet.start:
	$(NIX) "cd frontend && pnpm --filter @sovra/wallet start"

verifier.start:
	$(NIX) "cd frontend && pnpm --filter @sovra/verifier start"

issuer.start:
	$(NIX) "cd frontend && pnpm --filter @sovra/issuer dev"

# ── Setup ────────────────────────────────────────────────────────────

.PHONY: backend.setup backend.db.create contracts.setup contracts.deploy frontend.setup

backend.setup:
	$(NIX) "cd backend && mix local.hex --force && mix local.rebar --force && mix deps.get"

backend.db.create:
	$(NIX) "cd backend && mix ecto.setup"

contracts.setup:
	$(NIX) "cd contracts && npm ci"

contracts.deploy:
	$(NIX) "cd contracts && npx hardhat run scripts/deploy.ts"

frontend.setup:
	$(NIX) "cd frontend && pnpm install --frozen-lockfile"

# ── Backend ──────────────────────────────────────────────────────────

.PHONY: backend.format backend.lint backend.build backend.test backend.db.setup backend.db.migrate backend.db.reset

backend.format:
	$(NIX) "cd backend && mix format"

backend.lint:
	$(NIX) "cd backend && mix format --check-formatted"

backend.build:
	$(NIX) "cd backend && mix compile"

backend.test:
	$(NIX) "cd backend && mix test"

backend.db.setup:
	$(NIX) "cd backend && mix ecto.setup"

backend.db.migrate:
	$(NIX) "cd backend && mix ecto.migrate"

backend.db.reset:
	$(NIX) "cd backend && mix ecto.reset"

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
        frontend.packages.wallet-core.check frontend.packages.wallet-core.test \
        frontend.packages.verification-sdk.check frontend.packages.verification-sdk.test

frontend.packages.check: frontend.packages.wallet-core.check frontend.packages.verification-sdk.check

frontend.packages.test: frontend.packages.wallet-core.test frontend.packages.verification-sdk.test

frontend.packages.wallet-core.check:
	$(NIX) "cd frontend && pnpm --filter @sovra/wallet-core typecheck"

frontend.packages.wallet-core.test:
	$(NIX) "cd frontend && pnpm --filter @sovra/wallet-core test"

frontend.packages.verification-sdk.check:
	$(NIX) "cd frontend && pnpm --filter @sovra/verification-sdk typecheck"

frontend.packages.verification-sdk.test:
	$(NIX) "cd frontend && pnpm --filter @sovra/verification-sdk test"

# ── Frontend Issuer ──────────────────────────────────────────────────

.PHONY: frontend.issuer.lint frontend.issuer.build

frontend.issuer.lint:
	$(NIX) "cd frontend && pnpm --filter @sovra/issuer lint"

frontend.issuer.build:
	$(NIX) "cd frontend && pnpm --filter @sovra/issuer build"

# ── Frontend Wallet ──────────────────────────────────────────────────

.PHONY: frontend.wallet.check wallet.build.android wallet.build.ios

frontend.wallet.check:
	$(NIX) "cd frontend && pnpm --filter @sovra/wallet typecheck"

wallet.build.android:
	cd frontend/wallet && pnpm run build:android

wallet.build.ios:
	cd frontend/wallet && pnpm run build:ios

# ── Frontend Verifier ────────────────────────────────────────────────

.PHONY: frontend.verifier.check verifier.build.android verifier.build.ios

frontend.verifier.check:
	$(NIX) "cd frontend && pnpm --filter @sovra/verifier typecheck"

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
