# Platform Key Management

## Purpose

Cryptographic key management for workspaces and tenants. Each workspace has its own key ring in a dedicated Key Management Service (KMS). Private keys are never exposed outside the KMS -- all signing and encryption operations are performed within the KMS boundary. This ensures that compromise of the application layer does not expose signing keys.

## Requirements

### Requirement: KMS-based key isolation and signing

The system SHALL maintain per-workspace key rings in the KMS, supporting Ed25519 and ES256 key pairs, with all signing operations performed within the KMS boundary and private keys never leaving the KMS.

#### Scenario: Sign a credential with workspace key
- GIVEN a workspace is issuing a credential to a holder
- WHEN the credential needs to be signed
- THEN the system sends the credential payload to the KMS, the KMS signs it with the workspace's private key, and returns the signed JWT without the private key ever leaving the KMS

#### Scenario: Generate mDL signing key
- GIVEN a workspace needs to issue mDL credentials (ISO 18013-5)
- WHEN mDL issuance is configured for the workspace
- THEN an ES256 key pair is generated in the KMS specifically for mDL signing (separate from the general Ed25519 key), and the workspace can sign mDoc credentials with the ES256 key while general W3C VCs use the Ed25519 key

### Requirement: Public key publication via JWKS

The system SHALL publish workspace public keys in JWK format via a JWKS endpoint (/.well-known/jwks.json) for credential signature verification.

#### Scenario: Publish public keys via JWKS
- GIVEN a verifier or holder needs to verify a credential signed by a workspace
- WHEN they query the workspace's JWKS endpoint
- THEN the system returns the workspace's public keys in JWK format, allowing the verifier to validate credential signatures without accessing any private key material
