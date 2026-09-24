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

#### Scenario: Credential issued with an attached document
- GIVEN the issued credential's schema declares an `attachment` claim
- WHEN the credential-issued event is emitted
- THEN the payload's `credential` is the issued SD-JWT with the attachment's disclosure removed — its digest is still in the signed `_sd` array, so the signature verifies and the claim reads as withheld — and the payload carries an `attachment` object (`claim`, `type: "attachment"`, `media_type`, `bytes`) describing what was removed
- AND the credential delivered to the holder is unchanged, attachment included

> An attachment can be up to 560,000 bytes of `data:` URI. Carrying it would make every
> delivery attempt of a retried payload that size, to hand back a document the workspace
> supplied itself when it created the offer.

#### Scenario: Verification completed event
- GIVEN a verification session has been completed (either successfully or with failure)
- WHEN the verification result is determined
- THEN the appropriate event (`{event:verification.presentation-completed-messaging}` or `{event:verification.presentation-completed-rest}`) is emitted with the sessionId, verification result (true/false), presentation data (if successful), and error details (if failed)

#### Scenario: DID created event
- GIVEN a workspace has completed provisioning and a DID has been generated
- WHEN the DID is ready
- THEN a `{event:identity.did-generated}` event is emitted with the tenantId and the generated DID, enabling the platform to store and associate the DID with the workspace
