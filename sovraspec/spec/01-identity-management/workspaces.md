# Workspaces

## Purpose

Workspaces are the operational units within an organization. Each workspace functions as an independent issuer with its own decentralized identifier (DID), API key, webhook URL, webhook secret, and visual branding. Users can create multiple workspaces within an organization and switch between them.

## Requirements

### Requirement: Workspace creation and configuration

The system SHALL allow creation and configuration of workspaces within an organization, each with a unique tenantId, DID, API key, webhook URL, webhook secret, and branding configuration.

#### Scenario: Create a workspace
- GIVEN an authenticated user belonging to an organization
- WHEN they create a new workspace providing a name and optional webhook URL
- THEN a new workspace is created with a unique tenantId, a generated API key, a generated webhook secret, and the workspace provisioning process is initiated (key generation, DID creation)

#### Scenario: Configure workspace webhook
- GIVEN a workspace that needs to receive event notifications
- WHEN the admin sets the workspace's webhook URL
- THEN all subsequent events ({event:issuance.credential-issued-messaging}, {event:verification.presentation-completed-messaging}, etc.) are delivered to that URL with HMAC-SHA256 signatures using the workspace's webhook secret

#### Scenario: View workspace DID
- GIVEN a workspace that has completed provisioning
- WHEN the admin views the workspace details
- THEN the workspace's DID, public key, and issuance endpoint information are displayed

### Requirement: Multi-workspace navigation

The system SHALL allow users to switch between workspaces within the same organization, with full context isolation per workspace.

#### Scenario: Switch between workspaces
- GIVEN a user who belongs to an organization with multiple workspaces
- WHEN they select a different workspace from the workspace list
- THEN the user interface context switches to the selected workspace, showing its credentials, verifications, and configuration

### Requirement: Workspace roles

The system SHALL support two roles within a workspace: admin and member.

#### Scenario: Admin manages workspace
- GIVEN a user with admin role in a workspace
- WHEN they access workspace settings
- THEN they can modify configuration, manage members, issue and revoke credentials, and configure webhooks

#### Scenario: Member operates within workspace
- GIVEN a user with member role in a workspace
- WHEN they access the workspace
- THEN they can issue credentials and create verifications but cannot modify workspace configuration, manage members, or change webhook settings
