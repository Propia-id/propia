# Proposal

## Intent

Build a self-sovereign identity (SSI) platform that enables organizations to issue verifiable credentials and people (holders) to store and present them securely. The platform puts individuals in control of their digital identity while giving organizations the tools to issue and verify trusted credentials.

## Scope

The platform covers the full digital identity lifecycle:

- **Registration and identity management** -- Organizations create accounts, configure workspaces (issuers), and manage their identity infrastructure.
- **Credential issuance** -- Organizations define credential schemas, design visual representations, and issue credentials to holders via standardized protocols.
- **Credential verification** -- Verifiers request presentations of specific credentials from holders and validate them cryptographically.
- **Wallet** -- Holders receive, store, manage, and present their credentials from a secure digital wallet.
- **Credential lifecycle** -- Credentials move through defined states (active, suspended, revoked, expired) with full audit history and public status publication.
- **Event system** -- All significant actions produce webhook events with dual delivery (first to the workspace, then to the central platform with the workspace's response).

## Approach

- **Open standards**: W3C Verifiable Credentials, mDoc/mDL (ISO 18013-5), DIDComm/WACI, OpenID4VCI, OpenID4VP, SD-JWT, BitstringStatusList.
- **Protocol-agnostic design**: Every issuance and verification flow is available via both DIDComm and OpenID protocols, allowing implementers and holders to choose the protocol that fits their ecosystem.
- **Multi-format credentials**: Support W3C VC (JSON/JWT), mDoc (CBOR), and SD-JWT formats.
- **Interoperability**: Any company must be able to implement this specification using whatever architecture, language, or infrastructure they prefer. No proprietary dependencies.
- **Security by design**: Cryptographic key management in dedicated KMS, PIN and biometric protection in the wallet, HMAC-signed webhooks, nonce-based replay protection, and OAuth2/OIDC authorization flows.
