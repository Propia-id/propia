# Design Decisions

## Organizational Model

- **Multi-organization**: Multiple organizations can use the platform independently.
- **Multi-workspace**: Each organization can have multiple workspaces. Each workspace functions as an independent issuer with its own decentralized identifier (DID), API key, webhook configuration, and branding.
- **Tenant isolation**: Each workspace operates as a tenant with full data isolation. Credentials, keys, and configurations are scoped to a single workspace.

## Protocol Strategy

- **Dual protocol support**: Every issuance and verification flow supports both DIDComm/WACI and OpenID4VCI/OpenID4VP. Holders and verifiers choose the protocol that fits their ecosystem.
- **Format flexibility**: Credentials can be issued in W3C VC (JWT), mDoc (CBOR/ISO 18013-5), or SD-JWT format depending on the use case.

## Webhook Architecture

- **Dual delivery**: When a significant event occurs (credential issued, verification completed, DID created), the webhook is sent first to the workspace's webhook endpoints subscribed to that event type. The workspace's response is then included when sending the same event to the central platform. This allows the workspace to process events before the platform and enables the platform to know the workspace's reaction.
- **Multiple endpoints**: A workspace can configure up to ten webhook endpoints. Each subscribes to an explicit list of event types and can be disabled without being removed; every event is delivered independently to each enabled endpoint subscribed to it, with the same payload `id` on every delivery.
- **HMAC-SHA256 signing**: Every webhook payload is signed with the receiving endpoint's own signing secret so the receiver can verify authenticity.

## Credential Lifecycle

- **Status states**: Credentials follow defined states -- ACTIVE, SUSPENDED, REVOKED, EXPIRED.
- **Valid transitions**: ACTIVE can move to SUSPENDED or REVOKED. SUSPENDED can move back to ACTIVE or to REVOKED. REVOKED is terminal (no transitions allowed).
- **Audit trail**: Every status change records who made the change, when, and why. Full history is preserved.
- **Public status publication**: Credential status is published using W3C BitstringStatusListCredential, allowing any verifier to check revocation status without contacting the issuer directly.

## Wallet Design

- **Multi-format storage**: The wallet stores W3C VC, mDoc, and SD-JWT credentials with local encryption.
- **Selective disclosure**: When presenting credentials, holders choose which specific fields to reveal. For mDoc credentials, selective disclosure operates at the element level.
- **Security layers**: PIN encryption for credential storage, optional biometric authentication, secure enclave for cryptographic keys.
- **Protocol auto-detection**: When scanning a QR code, the wallet automatically detects whether it is a DIDComm or OpenID flow and handles it accordingly.

## Key Management

- **KMS-based**: Cryptographic keys are managed in a dedicated Key Management Service. Private keys are never exposed -- all signing and encryption operations happen within the KMS.
- **Per-workspace key rings**: Each workspace has its own set of cryptographic keys, ensuring isolation.
- **Supported algorithms**: Ed25519 (for DIDs and general signing), ES256 (for mDoc/mDL), BBS+ (for selective disclosure in W3C VC).

## Authorization

- **Multiple auth methods**: JWT tokens (email/password login), API keys (per workspace, for programmatic access), and credential-based login (authenticate with a verifiable credential after successful presentation).
- **OAuth2/OIDC authorization server**: Integrated authorization server supporting pre-authorized code grants (for credential issuance), authorization code with PKCE, and Pushed Authorization Requests (PAR).
- **Nonce-based replay protection**: Per-tenant nonces with freshness validation and holder key binding to prevent replay attacks.

## Main Flows

### Workspace Provisioning
1. User creates an account with an organization.
2. User creates a workspace (issuer) -- tenantId and API key are generated. Webhook endpoints, each with its own signing secret, are added afterwards.
3. The tenant is created with cryptographic keys in the KMS.
4. The issuer DID is generated asynchronously.
5. A `{event:identity.did-generated}` event is sent via webhook so the DID can be stored.
6. The workspace is ready to issue credentials.

### Credential Issuance (DIDComm)
1. Create a credential and generate an invitation QR code.
2. Holder scans the QR with their wallet and accepts the offer.
3. The credential is issued to the holder.
4. A `{event:issuance.credential-issued-messaging}` event is sent first to the workspace's subscribed webhook endpoints.
5. The workspace's webhook response is included when sending the event to the central platform.

### Credential Issuance (OpenID4VCI)
1. Create a credential offer with a pre-authorized code and optional txCode (PIN).
2. If txCode is configured, the PIN is sent to the holder via email.
3. Holder requests a token using the pre-authorized code (and txCode if required).
4. Holder presents proof of possession and receives the credential.
5. A `{event:issuance.credential-issued-messaging}` event follows the dual webhook delivery pattern.

### Credential Verification (DIDComm)
1. Create a presentation request defining which credentials are required.
2. Generate a QR code with the request.
3. Holder scans and presents the requested credentials.
4. Credentials are validated (signature, status, schema).
5. Webhook first to workspace, then to platform with workspace's response.

### Credential Verification (OpenID4VP)
1. Create a verification session with DCQL queries specifying required credentials.
2. Generate an authorization request URI (QR code).
3. Holder presents a vp_token via direct_post.
4. The response is parsed, validated (including credential status check).
5. Session result is available for polling.
6. Webhook follows dual delivery pattern.

### Wallet Usage
1. Create wallet: set up PIN, optionally enable biometrics, generate holder DID.
2. Receive credentials: scan QR, auto-detect protocol, accept credential, enter PIN if required.
3. Present credentials: scan verifier QR, select credentials, choose fields for selective disclosure, send presentation.

## Plans

- **Stripe**: Stripe is the payment processor for plans.
- **One plan per workspace**: every workspace has exactly one active plan at any time.
- **Default plan**: when a workspace has no associated plan, it starts on the `free` plan.

## Product Experience (section 09)

Sections 01–08 above describe the **platform contract** — what any implementer must do to be Sovra-compatible. Section 09 (`spec/09-product-experience/`) describes the **Sovra reference operator UI** layered on top of that contract. The two layers are kept separate by design:

- **Why a separate section** -- Implementers who want to build their own operator UI (different visual builders, alternative wizard flows, different billing page) only need to honor sections 01–08. They are not required to mirror section 09.
- **Mode toggle** -- The Sovra UI offers a per-user **Normal** / **Developer** toggle. Normal mode hides all JSON / payload / output-descriptor / protocol-level detail and forces credential creation through the 5-step wizard. Developer mode reveals JSON previews on every relevant surface (schema builder, design builder, credential detail, verification detail) and adds a "Wizard or JSON" dialog before credential creation.
- **Wizard ordering** -- The Sovra wizard enforces the natural product ordering: schema → design → credential. Step 1 selects (or creates) a schema, step 2 selects (or creates) a design bound to that schema, step 3 fills credential data via a table or CSV, step 4 previews each card, step 5 issues and shows per-credential distribution artifacts.
- **Cross-reference discipline** -- Every file in section 09 begins with a blockquote pointing to its platform-contract counterpart. If a section-09 requirement appears to conflict with a section 01–08 requirement, the platform contract wins.
