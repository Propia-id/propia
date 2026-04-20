# OpenID4VP Credential Verification

## Purpose

Credential verification using the OpenID for Verifiable Presentations (OID4VP) protocol. The verifier creates a verification session with DCQL (Digital Credentials Query Language) queries specifying which credentials are required. An authorization request URI is generated (presentable as a QR code). The holder's wallet responds via direct_post with a vp_token. The system parses and validates the presentation, checks credential status, and makes results available via polling and webhooks.

## Requirements

### Requirement: OID4VP session creation and credential validation

The system SHALL create verification sessions with DCQL queries, generate authorization request URIs, receive vp_tokens via direct_post, validate presentations (signature, schema, status via BitstringStatusList), and support both JWT and mDoc credential formats.

#### Scenario: Create a verification session with DCQL
- GIVEN a verifier wants to verify a holder's credential
- WHEN the verifier creates a verification session with a DCQL query specifying: credential id, format (e.g., "jwt_vc_json"), and required claims (e.g., path ["studentName"], path ["degree"])
- THEN a verification session is created with a unique sessionId, an authorization request URI is generated, and the session status is set to "pending" with an expiration time

#### Scenario: Holder presents credentials via direct_post
- GIVEN a verification session exists and the holder has scanned the authorization request QR
- WHEN the holder's wallet sends a direct_post response containing the vp_token and state parameter
- THEN the system looks up the session by state, parses the vp_token, validates the credential signatures, checks credential status against the BitstringStatusList, updates the session to "completed" with the presentation data, and emits a webhook event

#### Scenario: Credential status check during verification
- GIVEN a holder presents a credential that has been revoked or suspended
- WHEN the system extracts the credentialStatus from the vp_token and checks it against the BitstringStatusList
- THEN the verification fails with an error indicating the credential is revoked or suspended, the session is marked as "failed", and the webhook includes the error details

#### Scenario: Reject expired credential
- GIVEN a holder presents a credential whose expirationDate has passed
- WHEN the system validates the credential
- THEN the verification fails with an error indicating the credential has expired, the session is marked as "failed", and the error details are included in the webhook event

#### Scenario: Credential revoked during verification
- GIVEN a holder initiates a presentation and the credential is valid at the start
- WHEN the system checks the credential's status against the BitstringStatusList at the moment of validation
- THEN if the credential has been revoked between presentation and validation, the verification fails with a "credential revoked" error

### Requirement: Verification session polling and webhook notification

The system SHALL support session status polling (pending, completed, failed, expired) and emit `{event:verification.presentation-completed-rest}` webhook events upon verification completion.

#### Scenario: Poll for verification result
- GIVEN a verifier has created a verification session and is waiting for the holder to respond
- WHEN the verifier polls the session status endpoint with the sessionId
- THEN the system returns the current session status (pending, completed, failed, or expired) and, if completed, includes the verified presentation data and holder DID
