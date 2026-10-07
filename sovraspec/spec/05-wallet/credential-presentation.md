# Credential Presentation

## Purpose

The process by which a holder presents credentials to a verifier. The holder scans a verifier's QR code, the wallet identifies the required credentials, the holder selects which credentials to present and which fields to reveal (selective disclosure), and sends the presentation to the verifier.

## Requirements

### Requirement: Multi-protocol credential presentation with selective disclosure

The system SHALL support credential presentation via both DIDComm and OpenID4VP protocols, matching wallet credentials against verifier requirements (input descriptors or DCQL queries) and enabling selective disclosure of specific fields/claims.

#### Scenario: Present a credential via OpenID4VP
- GIVEN a verifier has displayed a QR code with an OID4VP authorization request
- WHEN the holder scans the QR and the wallet parses the DCQL query
- THEN the wallet identifies matching credentials, displays them to the holder, the holder selects which credential to present and which claims to reveal, and the wallet sends a direct_post response with the vp_token and state parameter

#### Scenario: Show the verifier's verdict
- GIVEN the holder has approved a presentation answered by direct_post
- WHEN the verifier's response carries a verdict
- THEN the wallet shows whether the verifier accepted the credential and, if it did not, why; a verifier that returns no verdict is shown as shared, without claiming it was accepted

#### Scenario: Selective disclosure
- GIVEN a verifier requests a "UniversityDiploma" credential but only needs studentName and degree
- WHEN the holder reviews the presentation request
- THEN the wallet shows which fields are requested, the holder can choose to reveal only studentName and degree (hiding gpa, honors, and other fields), and the presentation contains only the disclosed fields

#### Scenario: Present a credential via DIDComm
- GIVEN a verifier has displayed a QR code with a DIDComm presentation request
- WHEN the holder scans the QR and the wallet identifies the requested credentials
- THEN the wallet establishes a DIDComm connection (or reuses an existing one), the holder selects credentials and fields to disclose, and the verifiable presentation is sent via DIDComm messaging

### Requirement: Credential matching feedback

The system SHALL inform the holder when no credentials in their wallet match a verifier's requirements, preventing presentation attempts without matching credentials.

#### Scenario: No matching credentials
- GIVEN a verifier requests a credential type that the holder does not have in their wallet
- WHEN the holder scans the verifier's QR code
- THEN the wallet informs the holder that no matching credentials were found for the verifier's requirements and cannot proceed with the presentation
