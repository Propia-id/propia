# backend

The Propia issuance and verification server — Elixir/Phoenix, PostgreSQL.

It issues credentials over OpenID4VCI, verifies presentations over OpenID4VP,
publishes revocation status as a W3C Bitstring Status List, and reads and
writes the on-chain registries. It is multi-tenant: organizations contain
workspaces, and each workspace has its own signing identity and API keys.

See the [repository README](../README.md) for the quickstart — this server does
not run on its own, it needs PostgreSQL and a chain with the registries
deployed.

## Running it

From the repository root:

```bash
make services.start   # PostgreSQL
make backend.setup
make backend.db.create
make backend.start    # http://localhost:4000
```

## Tests

```bash
make backend.test
```

The suite runs with the environment cleared, so a developer's local `.env`
cannot leak into it — see the comment on that target in the `Makefile`.

## API reference

With the server running, three OpenAPI documents are served live:

| Surface | Spec | SwaggerUI |
|---|---|---|
| Integration (API key) | `/openapi/api` | `/api/dev/swaggerui/api` |
| Dashboard (session) | `/openapi/dashboard` | `/api/dev/swaggerui/dashboard` |
| Wallet (OID4VCI / OID4VP) | `/openapi/wallet` | `/api/dev/swaggerui/wallet` |

## Layout

`lib/sovra/` holds the domain contexts — `issuer`, `verification`,
`credentials`, `workspaces`, `organizations`, `did`, `mdoc`, `mdl`, `crypto`,
`webhooks`. `lib/sovra_web/` holds the HTTP layer: router, controllers and the
authorization plugs.
