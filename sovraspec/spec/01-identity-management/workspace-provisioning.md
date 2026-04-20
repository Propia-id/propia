# Workspace Provisioning

## Purpose

The complete asynchronous flow to provision a new workspace (issuer). When a workspace is created, the system generates cryptographic keys in the KMS, creates a DID for the workspace, and notifies the platform via webhook when the DID is ready. The workspace transitions through defined provisioning states.

## Requirements

### Requirement: Asynchronous workspace provisioning

The system SHALL provision workspaces by generating cryptographic key rings in the KMS and creating a DID, tracking state through PENDING, DONE, and FAILED stages with retry capability.

#### Scenario: Successful workspace provisioning
- GIVEN a user has just created a new workspace
- WHEN the provisioning process runs
- THEN the system generates cryptographic keys in the KMS, creates a DID for the workspace, the provisioning state transitions from PENDING to DONE, and a `{event:identity.did-generated}` webhook event is sent containing the workspace's new DID

#### Scenario: Provisioning failure and retry
- GIVEN a workspace provisioning has failed (e.g., KMS was temporarily unavailable)
- WHEN the system detects the FAILED state or an admin triggers a retry
- THEN the provisioning process restarts, attempts to generate keys and DID again, and transitions to DONE on success or remains FAILED with an error description

### Requirement: Provisioning webhook notification

The system SHALL emit a `{event:identity.did-generated}` webhook event when a workspace DID is successfully created, following the dual delivery pattern.

#### Scenario: DID-created webhook delivery
- GIVEN a workspace has completed provisioning and a DID has been generated
- WHEN the `{event:identity.did-generated}` event is emitted
- THEN the event payload includes the tenantId and the generated DID, and follows the dual delivery pattern (first to workspace webhook, then to central platform with workspace's response)
