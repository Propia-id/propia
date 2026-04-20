# Nonce Management

## Purpose

Replay protection through per-tenant nonce management. Nonces (c_nonce values) are issued during the token exchange and must be included in credential request proofs to ensure freshness and prevent replay attacks. Each nonce is scoped to a tenant and has an expiration time. Holder key binding ensures that the entity presenting the proof controls the key associated with the credential.

## Requirements

### Requirement: Per-tenant nonce lifecycle

The system SHALL generate unique nonces (c_nonce) per tenant during token exchange, with expiration times and one-time use enforcement, ensuring per-tenant isolation.

#### Scenario: Nonce issuance during token exchange
- GIVEN a holder's wallet exchanges a pre-authorized code for an access token
- WHEN the token response is generated
- THEN the response includes a c_nonce value and c_nonce_expires_in (seconds until expiry), and the nonce is stored per-tenant for later validation

#### Scenario: Reject expired or reused nonce
- GIVEN a holder attempts to use an expired c_nonce or one that has already been consumed
- WHEN the credential endpoint validates the JWT proof
- THEN the system rejects the request with an error indicating an invalid or expired nonce, and a new c_nonce must be obtained through a fresh token exchange

#### Scenario: Cross-tenant nonce isolation
- GIVEN a nonce was issued for tenant A
- WHEN a request arrives for tenant B using that same nonce
- THEN the system rejects the request because the nonce does not exist in tenant B's scope, preventing cross-tenant replay attacks

### Requirement: Holder key binding verification

The system SHALL verify that the JWT proof signer matches the expected holder key, ensuring proof freshness and key binding during credential requests.

#### Scenario: Validate nonce in credential request proof
- GIVEN a holder sends a credential request with a JWT proof containing a c_nonce
- WHEN the credential endpoint processes the request
- THEN the system validates that the c_nonce exists for the tenant, has not expired, and has not been previously used; then verifies that the JWT proof was signed by the holder's key, ensuring proof freshness and key binding
