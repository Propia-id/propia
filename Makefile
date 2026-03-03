.PHONY: backend wallet verifier issuer-web contracts test

# Backend (Elixir/Phoenix)
backend:
	cd backend && mix deps.get && mix phx.server

db.migrate:
	cd backend && mix ecto.migrate

db.reset:
	cd backend && mix ecto.drop && mix ecto.create && ecto.migrate

# Mobile — Wallet (React Native / Expo)
wallet:
	cd frontend/wallet && pnpm start

# Mobile — Verifier (React Native / Expo)
verifier:
	cd frontend/verifier && pnpm start

# Web — Issuer Portal (Vite)
issuer:
	cd frontend/issuer && pnpm dev

# Smart Contracts (Foundry)
contracts:
	cd contracts && forge build

# Run all tests
test: test-backend test-contracts test-frontend

test-backend:
	cd backend && mix test

test-contracts:
	cd contracts && forge test

test-frontend:
	cd frontend && pnpm --filter @sovra/wallet-core tsc --noEmit
