# JSON-direct Issuance (Developer Mode Only)

> Operator-experience layer over [`02-credential-issuance/`](../../02-credential-issuance/). The credential payload shape, validation against the schema's auto-generated JSON Schema, and issuance protocols are defined there. This document covers the JSON editor entry point (gated by [`operator-modes.md`](../01-modes/operator-modes.md)) and equivalence with the wizard.

## Purpose

JSON-direct issuance is an alternative path to creating a credential, available **only in Developer mode**. It is intended for integrators who already have a backend ready to send the platform a fully-formed credential payload, and who want to verify or experiment with that payload from the same UI that operators use. JSON-direct produces exactly the same credential — at the storage, webhook, and verification level — as a wizard issuance.

## Requirements

### Requirement: Entry point via "Wizard or JSON" dialog

The system SHALL, in Developer mode only, intercept the "New credential" action with a dialog offering two paths: **Wizard** (default) and **JSON direct**. Choosing JSON direct opens the JSON editor; choosing Wizard enters the standard 5-step flow.

#### Scenario: Open the JSON-direct editor
- GIVEN a Developer-mode operator on the Credentials list
- WHEN they click "New credential" and choose "JSON direct"
- THEN the JSON editor opens with a credential payload template populated from the workspace's first schema and design (selectable from dropdowns above the editor)

#### Scenario: JSON direct hidden in Normal mode
- GIVEN a Normal-mode operator on the Credentials list
- WHEN they click "New credential"
- THEN they go straight into the wizard; the JSON direct option is not exposed

### Requirement: Schema and design must be chosen for the payload

The system SHALL require the operator to select a schema and a design at the top of the JSON editor before issuance. The selected design's output descriptor SHALL be applied to the issued credential.

#### Scenario: Change schema mid-edit
- GIVEN the operator is editing JSON for schema "Diploma"
- WHEN they change the schema selector to "Ticket"
- THEN the JSON template is reset to the new schema's template; a confirmation prompt warns the operator they will lose their current edits

#### Scenario: Design must match schema
- GIVEN the operator picks schema "Diploma"
- WHEN the design selector populates
- THEN only designs bound to "Diploma" are listed

### Requirement: JSON validation against the schema

The system SHALL validate the JSON payload against the chosen schema's auto-generated JSON Schema before allowing issuance. Validation errors SHALL be displayed inline next to the editor with line numbers when possible.

#### Scenario: Missing required field
- GIVEN the schema requires `fullName`
- WHEN the operator submits JSON without `fullName`
- THEN issuance is blocked and an inline error reads "Missing required: fullName"

#### Scenario: Wrong type
- GIVEN the schema declares `graduationDate` as Date
- WHEN the operator submits a string `"yesterday"`
- THEN issuance is blocked and an inline error reads "graduationDate must be a date (YYYY-MM-DD)"

### Requirement: Distribution protocol selection

The system SHALL ask the operator to choose a distribution protocol (DIDComm or OpenID4VCI) on issuance, with the same constraints as the wizard (mDoc forces OpenID4VCI).

#### Scenario: Pick DIDComm
- GIVEN a valid W3C payload
- WHEN the operator submits with protocol DIDComm
- THEN a single credential is issued and a DIDComm invitation QR appears in the result panel

#### Scenario: Pick OpenID4VCI with txCode
- GIVEN a valid W3C payload and a workspace configured to require txCode
- WHEN the operator submits with protocol OpenID4VCI and provides a holder email
- THEN a pre-authorized code is generated, a txCode (PIN) is sent by email to the holder, and the credential offer is displayed in the result panel

> **Note on equivalence:** the credentials issued via JSON direct are identical in storage, webhook payload, and verification result to those issued via the wizard — this is a contract guarantee, not a UI affordance. See [`02-credential-issuance/`](../../02-credential-issuance/) for the issuance contract.
