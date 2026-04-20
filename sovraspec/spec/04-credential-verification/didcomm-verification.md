# DIDComm Credential Verification

## Purpose

Credential verification using the DIDComm/WACI protocol. The verifier creates a presentation request defining which credentials are required (via input descriptors), optionally filtering by issuer. A QR code is generated for the holder to scan, and the holder presents the requested credentials via DIDComm messaging. The system validates the presentation and delivers results via webhook.

## Requirements

### Requirement: DIDComm presentation request and validation

The system SHALL create presentation requests with input descriptors, generate QR codes, validate presented credentials (signature, schema, status), and support selective disclosure and issuer filtering via DIDComm messaging.

#### Scenario: Request a specific credential type
- GIVEN a verifier workspace wants to verify that a person holds a "UniversityDiploma" credential
- WHEN the verifier creates a presentation request with an input descriptor requiring a credential of type "UniversityDiploma" and generates a QR code
- THEN the holder scans the QR, their wallet identifies matching credentials, the holder selects one and presents it, and the verifier validates the credential's signature and status

#### Scenario: Filter by issuer
- GIVEN a verifier only accepts credentials issued by specific trusted issuers
- WHEN the verifier creates a presentation request with an input descriptor that filters by issuer DID (e.g., only credentials issued by a specific university's DID)
- THEN the holder's wallet only shows credentials matching the issuer filter, and the verifier rejects any credential from a non-matching issuer

#### Scenario: Reject expired credential
- GIVEN a holder presents a credential whose expirationDate has passed
- WHEN the system validates the credential
- THEN the verification fails with an error indicating the credential has expired, the session is marked as "failed", and the error details are included in the webhook event

#### Scenario: Credential revoked during verification
- GIVEN a holder initiates a presentation and the credential is valid at the start
- WHEN the system checks the credential's status against the BitstringStatusList at the moment of validation
- THEN if the credential has been revoked between presentation and validation, the verification fails with a "credential revoked" error

### Requirement: DIDComm verification webhook notification

The system SHALL emit a `{event:verification.presentation-completed-messaging}` webhook event upon verification completion, following the dual delivery pattern.

#### Scenario: Webhook notification on verification
- GIVEN a holder has successfully presented a credential to a verifier via DIDComm
- WHEN the verification is complete
- THEN a `{event:verification.presentation-completed-messaging}` event is emitted following the dual delivery pattern, containing the verification result, presented credential data, and holder information
