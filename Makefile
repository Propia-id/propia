NIX_SHELL := nix develop --command

.PHONY: shell backend db.migrate db.reset wallet verifier issuer contracts test test-backend test-contracts test-frontend

# Nix dev shell
shell:
	nix develop

# Backend (Elixir/Phoenix)
backend:
	$(NIX_SHELL) bash -c "cd backend && mix deps.get && mix phx.server"

db.migrate:
	$(NIX_SHELL) bash -c "cd backend && mix ecto.migrate"

db.reset:
	$(NIX_SHELL) bash -c "cd backend && mix ecto.drop && mix ecto.create && mix ecto.migrate"

# Mobile — Wallet (React Native / Expo)
wallet:
	$(NIX_SHELL) bash -c "cd frontend/wallet && pnpm start"

# Mobile — Verifier (React Native / Expo)
verifier:
	$(NIX_SHELL) bash -c "cd frontend/verifier && pnpm start"

# Web — Issuer Portal (Vite)
issuer:
	$(NIX_SHELL) bash -c "cd frontend/issuer && pnpm dev"

# Smart Contracts (Foundry)
contracts:
	$(NIX_SHELL) bash -c "cd contracts && forge build"

# Run all tests
test: test-backend test-contracts test-frontend

test-backend:
	$(NIX_SHELL) bash -c "cd backend && mix test"

test-contracts:
	$(NIX_SHELL) bash -c "cd contracts && forge test"

test-frontend:
	$(NIX_SHELL) bash -c "cd frontend && pnpm --filter @sovra/wallet-core tsc --noEmit"
