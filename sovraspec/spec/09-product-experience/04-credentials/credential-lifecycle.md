# Credential Lifecycle — Operator UI

> Operator-experience layer over [`03-credential-lifecycle/`](../../03-credential-lifecycle/). The state machine, valid transitions, BitstringStatusList publication, optimistic concurrency, audit-record requirements, and webhook emissions are defined there. This document covers **only** the operator-facing list and detail screens, the action buttons, and the history display.

## Purpose

The operator interacts with already-issued credentials through two surfaces: the **Credentials list** (paginated, filterable) and the **Credential detail** screen (visual card + metadata + status actions + history). Status transitions are triggered by buttons on the detail screen; the underlying state machine and audit recording are contract.

## Requirements

### Requirement: Credentials list page

The system SHALL show all credentials in the workspace in a paginated list with at least: holder identifier, schema, design, status badge, issue date, and quick-action buttons (View, Suspend, Revoke). The list SHALL support filtering by schema and by status.

#### Scenario: Filter the list
- GIVEN a workspace with 1,000 credentials
- WHEN the operator filters by schema "Diploma" and status "ACTIVE"
- THEN the list reflects the filter and the total count updates accordingly

#### Scenario: Quick action from the row
- GIVEN a credential row in the list
- WHEN the operator clicks the "Suspend" quick action
- THEN the same suspend confirmation modal as the detail screen opens (does not navigate)

### Requirement: Credential detail screen

The system SHALL provide a detail screen for each credential showing: the rendered card (front and back using the design's Output Descriptor), the holder identifier, the issuance date and protocol, the current status, and the status history. In Developer mode, a JSON tab SHALL also be available.

#### Scenario: Normal-mode detail
- GIVEN a Normal-mode operator opens a credential
- WHEN they browse the screen
- THEN they see the visual card, holder info, status, and history; no JSON tab is visible

#### Scenario: Developer-mode detail
- GIVEN a Developer-mode operator opens the same credential
- WHEN they browse the screen
- THEN a JSON tab is available showing the full credential payload as issued

### Requirement: Status-change action buttons

The system SHALL render the appropriate action buttons (Suspend, Reactivate, Revoke) on the credential detail screen based on the current status. The button set SHALL follow the contract's allowed transitions defined in [`03-credential-lifecycle/`](../../03-credential-lifecycle/) (ACTIVE shows Suspend/Revoke; SUSPENDED shows Reactivate/Revoke; REVOKED hides all action buttons since the state is terminal).

#### Scenario: Buttons on an ACTIVE credential
- GIVEN an ACTIVE credential
- WHEN the operator opens its detail screen
- THEN they see "Suspend" and "Revoke" buttons in the action bar; no "Reactivate" button

#### Scenario: Buttons on a SUSPENDED credential
- GIVEN a SUSPENDED credential
- WHEN the operator opens its detail screen
- THEN they see "Reactivate" and "Revoke" buttons in the action bar

#### Scenario: No action buttons on REVOKED
- GIVEN a REVOKED credential
- WHEN the operator opens its detail screen
- THEN the action bar is empty (REVOKED is terminal per the contract); only Read access remains

### Requirement: Reason-required confirmation modal

The system SHALL open a confirmation modal for every status-change action, with a required free-text "Reason" field and primary/secondary action buttons.

#### Scenario: Suspend confirmation flow
- GIVEN the operator clicks "Suspend" on an active credential
- WHEN the modal opens
- THEN it shows the action title ("Suspend credential"), a required Reason text area, a primary "Suspend" button (disabled until reason is non-empty), and a secondary "Cancel"

#### Scenario: Revoke confirmation flow
- GIVEN the operator clicks "Revoke"
- WHEN the modal opens
- THEN the modal additionally warns "This action is permanent and cannot be undone" before the Reason field

### Requirement: Status history table

The system SHALL display a chronological status history on the credential detail screen with at least: from status, to status, reason, who changed it, and when. The data shown SHALL match the audit record produced by the contract.

#### Scenario: View history
- GIVEN a credential has been suspended once and reactivated
- WHEN the operator opens the History section
- THEN three rows are visible — issue, suspend, reactivate — each with reason, operator, and timestamp

#### Scenario: Empty history for a freshly issued credential
- GIVEN a credential just issued (no transitions yet)
- WHEN the operator opens the History section
- THEN one row is shown for the issuance with the original status (ACTIVE / draft → active) and no reason
