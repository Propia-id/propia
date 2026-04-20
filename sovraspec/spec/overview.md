# Platform Overview

## Description

A self-sovereign identity (SSI) platform that enables organizations to issue verifiable credentials and individuals (holders) to store, manage, and present them securely. The platform implements open standards (W3C VC, mDoc/mDL, DIDComm, OpenID4VC) to ensure interoperability across ecosystems.

## Functional Domains

### Identity Management
User accounts, organizations, and workspaces. Each workspace acts as an independent issuer with its own DID, keys, and configuration. Workspace provisioning is an asynchronous process that generates cryptographic keys and a DID before the workspace becomes active.

### Credential Issuance
Organizations define credential schemas and visual designs, then issue credentials to holders via DIDComm/WACI or OpenID4VCI protocols. Supports W3C VC (JWT), mDoc (CBOR/ISO 18013-5), and SD-JWT formats. Issuance can require a transaction code (PIN) for additional security.

### Credential Verification
Verifiers create presentation requests specifying which credentials they need. Holders present credentials via DIDComm or OpenID4VP. The system validates signatures, checks credential status against BitstringStatusList, and delivers results via webhooks and polling.

### Credential Lifecycle
Credentials move through defined states (ACTIVE, SUSPENDED, REVOKED, EXPIRED) with full audit history. Status is published using W3C BitstringStatusListCredential for public verifiability. Optimistic concurrency control ensures consistency under concurrent status updates.

### Wallet
A secure digital wallet for holders to receive, store, and present credentials. Supports multiple credential formats, selective disclosure, protocol auto-detection, and secure key management with PIN and biometric protection.

### Webhook Events
An event system that notifies workspaces and the central platform of significant actions. Uses dual delivery (first to workspace, then to platform with workspace's response) and HMAC-SHA256 signing for authenticity.

### Security
Authentication via JWT, API keys, and credential-based login. Cryptographic key management in a dedicated KMS with per-workspace key rings. OAuth2/OIDC authorization server with support for pre-authorized code grants, authorization codes with PKCE, and PAR. Nonce-based replay protection.
