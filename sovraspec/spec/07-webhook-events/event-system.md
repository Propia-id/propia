# Event System

## Purpose

The platform emits webhook events for significant actions across the ecosystem. Each event has a type and a payload containing relevant data. Events enable workspaces and the central platform to react to credential issuance, verification completion, DID creation, and other lifecycle events.

## Requirements

### Requirement: Lifecycle event emission

The system SHALL emit typed webhook events for significant platform actions including credential issuance (`{event:issuance.credential-issued-messaging}`, `{event:issuance.credential-issued-rest}`), verification completion (`{event:verification.presentation-completed-messaging}`, `{event:verification.presentation-completed-rest}`), and DID generation (`{event:identity.did-generated}`), with tenantId in each payload, delivered as JSON over HTTP POST.

#### Scenario: Credential issued event
- GIVEN an issuer workspace has successfully issued a credential to a holder
- WHEN the issuance flow completes (via DIDComm or OpenID4VCI)
- THEN the appropriate event (`{event:issuance.credential-issued-messaging}` or `{event:issuance.credential-issued-rest}`) is emitted with the credentialId, tenantId, and holder information in the payload

#### Scenario: Verification completed event
- GIVEN a verification session has been completed (either successfully or with failure)
- WHEN the verification result is determined
- THEN the appropriate event (`{event:verification.presentation-completed-messaging}` or `{event:verification.presentation-completed-rest}`) is emitted with the sessionId, verification result (true/false), presentation data (if successful), and error details (if failed)

#### Scenario: DID created event
- GIVEN a workspace has completed provisioning and a DID has been generated
- WHEN the DID is ready
- THEN a `{event:identity.did-generated}` event is emitted with the tenantId and the generated DID, enabling the platform to store and associate the DID with the workspace
