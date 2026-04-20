# Credential Storage

## Purpose

Secure local storage of verifiable credentials in the holder's wallet. Supports multiple credential formats (W3C VC, mDoc, SD-JWT), encrypts stored data, and provides search, filtering, and categorization capabilities. The wallet can also check the revocation status of stored credentials.

## Requirements

### Requirement: Multi-format encrypted credential storage

The system SHALL store credentials in W3C VC (JWT), mDoc (CBOR), and SD-JWT formats, encrypted with the holder's PIN-derived key, with indexing by issuer, type, and issuance date.

#### Scenario: Store a W3C VC credential
- GIVEN a holder has just received a W3C Verifiable Credential in JWT format
- WHEN the credential is accepted
- THEN the credential is encrypted using the holder's PIN-derived key and stored locally, indexed by issuer, type, and issuance date for later retrieval

#### Scenario: Store an mDoc credential
- GIVEN a holder has received an mDL credential in mDoc (CBOR) format
- WHEN the credential is stored
- THEN the mDoc is encrypted and stored locally with its CBOR structure preserved, its namespaced elements are indexed for selective disclosure during presentation, and the credential appears in the wallet alongside W3C VC credentials

### Requirement: Credential search and filtering

The system SHALL provide search by keyword across credential fields and filtering by type, issuer, or status.

#### Scenario: Search and filter credentials
- GIVEN a holder has multiple credentials in their wallet from different issuers
- WHEN they search for "university" or filter by a specific issuer
- THEN the wallet displays only matching credentials, sorted by relevance or date, showing the credential title, issuer name, and visual design

### Requirement: Credential status checking

The system SHALL check the revocation status of stored credentials against the BitstringStatusList, displaying whether each credential is active, suspended, or revoked.

#### Scenario: Check credential revocation status
- GIVEN a holder has a stored credential that contains a BitstringStatusListEntry in its credentialStatus field
- WHEN the holder requests a status check (or the wallet performs periodic checks)
- THEN the wallet reads the credential's statusListCredential URL and statusListIndex, checks the bitstring value at that index, and displays whether the credential is active, suspended, or revoked

### Requirement: Expired credential handling

The system SHALL visually mark expired credentials while keeping them stored in the wallet.

#### Scenario: Credential reaches expiration date
- GIVEN a holder has a stored credential with an expirationDate that has passed
- WHEN the wallet checks credential validity
- THEN the credential is visually marked as expired but remains stored in the wallet for reference
