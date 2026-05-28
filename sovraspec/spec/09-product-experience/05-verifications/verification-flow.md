# Verification Flow — Operator UI

> Operator-experience layer over [`04-credential-verification/`](../../04-credential-verification/). DCQL queries, OpenID4VP / DIDComm protocol details, presentation validation rules, status transition logic, webhook emissions, and the verification-result data model are defined there. Plan-limit enforcement is in [`08-plans-billing/plans.md`](../../08-plans-billing/plans.md). DID provisioning is in [`01-identity-management/`](../../01-identity-management/). This document covers **only** the operator-facing screens: the creation form, the distribution panel, the real-time detail view, the tab layout (gated by [`operator-modes.md`](../01-modes/operator-modes.md)), and the history table.

## Purpose

The operator builds a verification request, distributes it to a holder (typically as a QR or deep link), and watches the result come back in real time on the verification detail screen. In Developer mode the screen exposes additional tabs with the raw request and response payloads.

## Requirements

### Requirement: Verification creation form

The system SHALL render a "New verification" form where the operator names the verification and selects which schemas and which fields are being asked for. The submit action SHALL produce a verification session ready to receive a holder presentation.

#### Scenario: Verify a Diploma
- GIVEN an operator wants to verify a diploma
- WHEN they create a verification named "Onboarding diploma check" requesting schema "Diploma" with fields `fullName` and `graduationDate`
- THEN the verification is created and the operator is redirected to its detail screen

#### Scenario: Verify multiple credential types
- GIVEN a use case that needs both a diploma and an ID
- WHEN the operator creates a verification asking for both schemas in a single request
- THEN the request lists both credential types; the detail screen reflects both required schemas

### Requirement: Distribution panel (QR + deep link)

The system SHALL render, on the verification detail screen, the QR code and a copyable deep link as the primary distribution artifacts. The operator SHALL be able to copy the link, download the QR as an image, and (where applicable) email the link directly to a holder.

#### Scenario: Copy the deep link
- GIVEN a verification has just been created
- WHEN the operator opens its detail screen and clicks the "Copy" icon next to the deep link
- THEN the link is copied to clipboard and a confirmation toast appears

#### Scenario: Download the QR
- GIVEN the operator wants to share the QR on a printed flyer
- WHEN they click "Download QR"
- THEN a PNG of the QR is saved to the operator's device

### Requirement: Real-time status without manual refresh

The system SHALL update the verification status in the UI as the holder interacts (PENDING → SCANNED → SUBMITTED → COMPLETED), without requiring the operator to refresh the page.

#### Scenario: Holder scans the QR
- GIVEN the operator is watching the verification detail screen
- WHEN the holder scans the QR with their wallet
- THEN the status badge updates from PENDING to SCANNED within seconds

#### Scenario: Holder submits the presentation
- GIVEN status SCANNED
- WHEN the holder approves and sends the presentation
- THEN the status moves to SUBMITTED, then to COMPLETED with the outcome (success / failure) — the operator's screen reflects each transition

### Requirement: Result display on completion

The system SHALL show a clear pass/fail visual on the verification detail screen when the verification completes. Successful results SHALL list the presented fields with their values; failed results SHALL show the failure reason returned by the contract.

#### Scenario: Successful verification
- GIVEN a verification has COMPLETED successfully
- WHEN the operator reviews it
- THEN the presented fields are listed (e.g., `fullName: "Daniel Quinteros"`, `graduationDate: "2025-12-15"`) with a green success indicator

#### Scenario: Failed verification — revoked credential
- GIVEN a holder presented a credential that has been revoked
- WHEN the verification completes
- THEN the result panel shows FAILED with reason "Credential is revoked" and the failure timestamp

#### Scenario: Failed verification — invalid signature
- GIVEN a presentation arrives with an invalid signature
- WHEN verification completes
- THEN the result panel shows FAILED with reason "Invalid signature"

### Requirement: Status history table

The system SHALL display the verification's status transitions as a chronological table on the detail screen, with at least: previous status, new status, timestamp.

#### Scenario: View status history
- GIVEN a completed verification
- WHEN the operator opens the History section
- THEN they see rows for PENDING → SCANNED → SUBMITTED → COMPLETED with timestamps

### Requirement: Raw payload tabs (Developer mode)

The system SHALL render additional tabs ("Request" and "Response") on the verification detail screen **only when the user is in Developer mode**. The Request tab SHALL show the full presentation request payload; the Response tab SHALL show the raw vp_token / DIDComm message together with a decoded view.

#### Scenario: Inspect raw request
- GIVEN a Developer-mode operator opens a verification
- WHEN they switch to the "Request" tab
- THEN they see the full presentation request payload (DCQL queries for OpenID4VP, presentation definition for DIDComm)

#### Scenario: Inspect raw response
- GIVEN a Developer-mode operator opens a completed verification
- WHEN they switch to the "Response" tab
- THEN they see the raw vp_token / DIDComm message and a decoded view of the holder-signed presentation

### Requirement: "New verification" disabled while workspace DID provisions

The system SHALL render the "New verification" entry point as disabled, with an explanatory tooltip, while the workspace's DID is not yet provisioned (the underlying contract rule lives in [`01-identity-management/workspace-provisioning.md`](../../01-identity-management/workspace-provisioning.md)).

#### Scenario: New workspace, DID not ready
- GIVEN a workspace where DID generation is in progress
- WHEN the operator clicks "New verification"
- THEN the button is disabled with a tooltip "Waiting for your workspace identity to be ready"

### Requirement: Plan-limit modal on verification creation

When verification creation is blocked by the plan limit (contract in [`08-plans-billing/plans.md`](../../08-plans-billing/plans.md)), the system SHALL show the same plan-limit modal used elsewhere in the product (resource counts + primary "Upgrade plan" CTA).

#### Scenario: Limit reached
- GIVEN a workspace at its verification limit
- WHEN the operator clicks "New verification"
- THEN the plan-limit modal opens with "Verification limit reached. <Plan> allows N verifications." and a primary "Upgrade plan" button
