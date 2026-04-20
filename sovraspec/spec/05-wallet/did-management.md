# DID Management

## Purpose

Management of Decentralized Identifiers (DIDs) within the holder's wallet. The wallet generates DIDs (did:key by default) for the holder, stores them securely, and allows sharing the DID with issuers and verifiers. DIDs are the holder's cryptographic identity used to receive credentials and create presentations.

## Requirements

### Requirement: DID generation and secure storage

The system SHALL generate DIDs (did:key method by default) from Ed25519 key pairs, store them encrypted with the PIN-derived key, and support extensibility for multiple DID methods.

#### Scenario: Generate a holder DID
- GIVEN a new wallet is being set up for a holder
- WHEN the wallet initialization process runs
- THEN a did:key DID is generated from a newly created Ed25519 key pair, the DID and associated key material are stored encrypted in the wallet, and the DID becomes the holder's primary identifier

#### Scenario: View DID information
- GIVEN a holder wants to see their decentralized identifier
- WHEN they navigate to the DID management section of the wallet
- THEN the wallet displays the full DID string, the DID method (e.g., did:key), and the associated public key in a readable format

### Requirement: DID sharing for credential interactions

The system SHALL share the holder's DID and proof of possession with issuers during credential acquisition and with verifiers during presentation.

#### Scenario: Share DID during credential acquisition
- GIVEN a holder is receiving a credential from an issuer
- WHEN the credential acquisition flow requires the holder's DID for key binding
- THEN the wallet provides the holder's DID and proof of possession (signed with the DID's private key) so the credential can be bound to the holder
