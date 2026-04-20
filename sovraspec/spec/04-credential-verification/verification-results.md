# Verification Results

## Purpose

Verification results capture the outcome of each credential verification session. Each result includes the session status, presented credential data (if successful), error details (if failed), and metadata about the verification. Results are queryable for auditing and can be filtered by status and type.

## Requirements

### Requirement: Verification result recording

The system SHALL record verification outcomes including session status (pending, completed, failed, expired), presented credential data, holder DID, and error details, with session expiration management.

#### Scenario: Successful verification result
- GIVEN a holder has successfully presented a valid credential
- WHEN the verification session is completed
- THEN the result includes: sessionId, status "completed", the presented credential data (claims and values), the holder's DID (if provided), the verification timestamp, and the tenantId of the verifier workspace

#### Scenario: Failed verification result
- GIVEN a holder has presented an invalid or revoked credential
- WHEN the verification fails
- THEN the result includes: sessionId, status "failed", an error description (e.g., "Credential is revoked", "Invalid signature"), and the verification timestamp

### Requirement: Verification history querying

The system SHALL support querying verification history with filters by status, date range, and credential type for auditing purposes.

#### Scenario: Expired verification session
- GIVEN a verification session was created but the holder never responded
- WHEN the session's expiration time passes
- THEN the session status transitions to "expired", no credential data is stored, and the verifier can see that the session timed out without a response
