# Propia

Propia is an open platform for the issuance, custody and verification of
government-issued digital credentials. It is built on the W3C Verifiable
Credentials data model, the OpenID for Verifiable Credentials protocols and
the ISO/IEC 18013-5 mobile document standard.

An issuing authority grants a credential to a citizen, who holds it on a
personal device. When that credential is presented to a service, the holder
discloses only the attributes that the service requires. The verifying party
establishes the credential's authenticity cryptographically, consulting
registries anchored on a public ledger, without contacting the issuing
authority and without the issuing authority learning where the credential was
used.

This repository contains the platform itself: the issuance and verification
server, the registry contracts, the software development kits and the written
specification. The full system can be run locally, and applications may be
built on it.

## Propia and Sovra

Propia designates the protocol. Sovra designates the reference implementation
of that protocol, which is the software contained in this repository.

Both names appear throughout, and they are not interchangeable. The
specification, the data model and the guarantees belong to Propia. The Elixir
server, the `Sovra*` registry contracts, the `@sovrahq/*` packages distributed
on npm and the `did:sovra:` method identifier belong to Sovra.

The protocol is described in the [Propia whitepaper](https://propia.id/whitepaper/).
A credential issued by this implementation is a Propia credential, and any
other conforming implementation is able to verify it.

## Contents

| Directory | Description |
|---|---|
| `backend/` | Issuance and verification server, written in Elixir. Multi-tenant: organizations contain workspaces, and each workspace holds its own signing identity |
| `contracts/` | Four registry contracts (decentralized identifiers, issuing authorities, revocation and signatures) together with the smart-account contracts |
| `frontend/packages/holder-core` | TypeScript library for the holder role: credential storage, selective disclosure, mobile documents and identifier resolution |
| `frontend/packages/verification-sdk` | TypeScript library for the verifying role: presentation verification, issuer resolution and revocation status |
| `sovraspec/` | The written specification covering identity, issuance, presentation and credential formats |
| `docs/` | Protocol whitepaper, core flows, and the formats and protocols in use |

Every interface required to build issuance systems, wallet applications and
verification software is documented below, and the libraries that implement
the holder and verifying roles are included.

## Running the platform locally

The platform runs in full on a single machine, including a local ledger with
the registry contracts deployed to it. No account registration and no hosted
environment are required.

The toolchain is provided by [Nix](https://nixos.org/download), which supplies
Elixir, Node and the remaining dependencies. PostgreSQL is also required.

First, start a local ledger. Any Ethereum JSON-RPC implementation is suitable;
[Anvil](https://book.getfoundry.sh/anvil/) is the most direct option. In a
separate terminal:

```bash
anvil
```

Then install the dependencies, prepare the database and deploy the registries:

```bash
git clone https://github.com/Propia-id/propia.git
cd propia
make services.start
make setup
```

Finally, start the server:

```bash
make backend.start
```

The server listens on `http://localhost:4000`. Its availability can be
confirmed with `curl localhost:4000/health`, and the test suites are run with
`make test`.

### Interface documentation

Three OpenAPI documents are served by the running instance:

| Interface | Specification | Interactive reference |
|---|---|---|
| Integration | `/openapi/api` | `/api/dev/swaggerui/api` |
| Console | `/openapi/dashboard` | `/api/dev/swaggerui/dashboard` |
| Wallet | `/openapi/wallet` | `/api/dev/swaggerui/wallet` |

## Structure of the system

The platform serves three roles, each through its own interface.

```
   ISSUING AUTHORITY           HOLDER                    VERIFYING PARTY
          │                       │                            │
          │ /api/v1/issuer        │ /wallet/*                  │ /api/v1/verifier
          │ API key               │ OID4VCI, OID4VP            │ API key
          │                       │                            │
          │                 holder-core                verification-sdk
          │                       │                            │
          └───────────────────────┴────────────────────────────┘
                                  │
                           ledger registries
                  issuer authorization, revocation, identifiers
```

Issuance systems are built against the integration interface. Wallet
applications are built with `holder-core`, and verification applications with
`verification-sdk`. Both roles may equally be implemented without these
libraries, since each side of the exchange conforms to the OpenID for
Verifiable Credentials specifications.

## Issuance

The integration interface is authenticated with a workspace API key, supplied
as `Authorization: Bearer <key>`.

**Defining a credential type.** A schema declares the credential type and the
claims it carries.

```http
POST /api/v1/issuer/schemas
```

Schemas are revised through `PUT /api/v1/issuer/schemas/:schema_id`.
Credentials already issued retain the version under which they were granted.

**Creating an offer.**

```http
POST /api/v1/issuer/credential-offer
```

The response contains an `openid-credential-offer://` identifier carrying a
pre-authorized code, which may be rendered as a QR code or distributed as a
deep link. The credential is not contained in the offer; the offer carries only
a reference to the issuer and a single-use code.

**Redemption by the wallet.** The wallet discovers the issuing authority at
`/:workspace_did/.well-known/openid-credential-issuer` and completes the
standard OID4VCI exchange against `/wallet/issuer/token` and
`/wallet/issuer/credential`. Any conforming wallet is able to complete this
exchange.

**Issuance records and revocation.**

```http
GET /api/v1/issuer/credentials
GET /api/v1/issuer/credentials/:id
PUT /api/v1/issuer/credentials/:id/status/:status
```

These endpoints operate on issuance records, not on credentials. The server
does not retain the credential it issued: the signed document is delivered to
the holder's device and is not stored. What persists is the record of the
issuance, comprising the holder's identifier, the schema, the issuance and
expiry times, and the position assigned to the credential in the status list.
That record is sufficient to revoke the credential and to demonstrate that it
was issued, and insufficient to reconstruct it or to read the attributes it
carries.

Revocation is published to a W3C Bitstring Status List, served at
`/api/v1/status/:issuer_did/:purpose`, and recorded in the revocation registry
on the ledger. Verifying parties consult this status without contacting the
issuing authority, which is therefore not informed of where a credential is
presented.

## Verification

Verification may be performed through the integration interface or directly in
the verifying application.

Through the interface, a session is created and its outcome retrieved:

```http
POST /api/v1/verifier/verifications
GET  /api/v1/verifier/verifications/:id
```

The wallet retrieves the request from `/wallet/verifier/request/:session_id`
and submits the presentation to `/wallet/verifier/direct_post/:session_id`.
Requests are signed, and the wallet resolves the signing key through the
identifier registry on the ledger, which prevents a verifying party from
presenting itself as an authority other than its own.

Within an application, the verification library performs the same checks:

```ts
import { verifyPresentation } from "@sovrahq/verification-sdk";
```

The library validates the issuer's signature, resolves the issuer against the
registry, confirms that the issuer is authorized for the credential type in
question, verifies the binding to the holder, and consults the revocation
status. No communication with the issuing authority takes place.

## Libraries

Both libraries are distributed on npm under the MIT licence.

`@sovrahq/holder-core` provides the functions required by a wallet
application: credential storage, selective disclosure, SD-JWT and mobile
document handling, identifier resolution, and the issuance and presentation
protocols. Platform-dependent operations are declared as interfaces
(`SecureStorage`, `CameraScanner`, `PasskeyProvider`) which the host
application implements, so that the library is not bound to a particular
runtime.

`@sovrahq/verification-sdk` provides the verifying side: presentation parsing,
signature verification, issuer resolution, authorization checks, revocation
status, and X.509 path validation for mobile documents.

```bash
pnpm add @sovrahq/holder-core @sovrahq/verification-sdk
```

## Standards

| Area | Specification |
|---|---|
| Credential formats | W3C Verifiable Credentials, SD-JWT VC, ISO/IEC 18013-5 mobile documents |
| Issuance | OpenID for Verifiable Credential Issuance |
| Presentation | OpenID for Verifiable Presentations, with DCQL |
| Revocation | W3C Bitstring Status List v1.0 |
| Holder binding | WebAuthn and P-256 passkeys, key-bound JWT |

The platform implements published standards rather than a proprietary
protocol. A wallet developed independently interoperates with this issuance
service, and a credential issued by this platform is verifiable by independent
verification software. This property is what allows an organization to replace
any single component, including this implementation.

## Registry contracts

Four contracts provide the trust anchors for the system. They record public
keys, authorization assignments and revocation state. No personal data is
written to the ledger.

| Contract | Function |
|---|---|
| Identifier registry | Resolves a decentralized identifier to the keys authorized to act for it |
| Issuer registry | Records which authority is authorized to issue which credential type |
| Revocation registry | Records credential status as a bitmap providing herd privacy |
| Signature registry | Records signatures |

The contracts and their test suite are run with `make contracts.test`. Role
assignment for a deployment is described in
[`contracts/chain/README.md`](contracts/chain/README.md).

## Further reading

| Document | Contents |
|---|---|
| [Propia whitepaper](https://propia.id/whitepaper/) | The protocol: design, guarantees and threat model |
| [`docs/`](docs/) | Core flows, formats and protocols, deployment |
| [`sovraspec/`](sovraspec/) | The specification this implementation follows |

## Security

Security issues should be reported privately, following the procedure in
[SECURITY.md](SECURITY.md). Please do not open a public issue.

## Licence

This software is distributed under the
[GNU Affero General Public License, version 3](LICENSE). Operating a modified
version as a network service requires that the modifications be made
available. Enquiries regarding alternative licensing terms are welcome.
