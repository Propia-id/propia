# Credential Issuance Wizard

> Operator-experience layer over [`02-credential-issuance/`](../../02-credential-issuance/). The underlying issuance protocols (DIDComm, OpenID4VCI, mDoc) and plan-limit enforcement are defined there. This document covers the five-step wizard flow, CSV import, and per-credential distribution view.

## Purpose

The credential issuance wizard is a guided, five-step flow for creating and distributing credentials without writing any code. It is the **only** path available in Normal mode and the **default** path in Developer mode. The wizard always ends with credentials issued and a per-credential distribution view (QR codes, links, or pre-authorized codes).

## Requirements

### Requirement: Five-step linear flow

The system SHALL implement credential issuance as a five-step wizard with the following ordered steps: **(1) Select Schema, (2) Select Design, (3) Add Data, (4) Preview, (5) Create & Distribute**. The operator SHALL not be able to advance to the next step until the current step's requirements are met. The operator SHALL be able to return to any previous step without losing data.

#### Scenario: Linear progression
- GIVEN the operator starts the wizard
- WHEN they progress through Steps 1 → 2 → 3 → 4 → 5
- THEN at each transition the wizard validates the current step and persists a local draft so the operator can come back if interrupted

#### Scenario: Go back without losing data
- GIVEN the operator is on Step 4 (Preview)
- WHEN they click "Back" to return to Step 3 (Add Data)
- THEN the data they entered is still there, including any CSV import results

### Requirement: Step 1 — Select Schema

The system SHALL show, on Step 1, the list of schemas available in the workspace, with a preview of each schema's attributes. The operator SHALL be able to pick an existing schema or create a new one inline.

#### Scenario: Pick an existing schema
- GIVEN the workspace has 3 schemas
- WHEN the operator selects "Diploma"
- THEN "Diploma" is highlighted, its attributes are shown as chips, and the Next button is enabled

#### Scenario: Create a schema inline from Step 1
- GIVEN no schema fits the operator's need
- WHEN they click "Create new schema"
- THEN the schema builder opens; on save the new schema is selected and the wizard remains on Step 1 with the new schema highlighted

#### Scenario: No schemas yet
- GIVEN a brand-new workspace with zero schemas
- WHEN the operator opens the wizard
- THEN Step 1 shows an empty state with a primary "Create your first schema" button that opens the schema builder inline

### Requirement: Step 2 — Select Design

The system SHALL show, on Step 2, the list of designs **bound to the schema chosen in Step 1**. The operator SHALL be able to pick an existing design or create one inline; designs bound to other schemas SHALL not appear.

#### Scenario: Designs filtered by schema
- GIVEN schema "Diploma" has 2 designs, schema "Ticket" has 5
- WHEN the operator picks "Diploma" in Step 1 and reaches Step 2
- THEN only the 2 designs bound to "Diploma" are listed

#### Scenario: Create a design inline from Step 2
- GIVEN no design fits the operator's need
- WHEN they click "Create new design"
- THEN the design builder opens with the Step 1 schema pre-selected and locked; on save the new design is selected and Step 2 highlights it

#### Scenario: Preview each design as a card
- GIVEN Step 2 shows multiple designs
- WHEN the operator hovers a design
- THEN the design is rendered as a small credential card showing its front side using a sample of the schema's attributes

### Requirement: Step 3 — Add Data (table)

The system SHALL provide, on Step 3, an editable table whose columns are derived from the schema's properties. The operator SHALL be able to add and remove rows; each row corresponds to one credential to issue.

#### Scenario: Add data row by row
- GIVEN Step 3 is open for schema "Diploma"
- WHEN the operator adds a row and types "Daniel Quinteros", "BS Computer Science", "2025-12-15"
- THEN the row is saved in memory as one credential subject

#### Scenario: Date columns use a date picker
- GIVEN a column corresponds to a property of type Date
- WHEN the operator clicks the cell
- THEN a native date picker opens; the header carries a small "DATE" label so the operator can see the column type

#### Scenario: Bulk paste
- GIVEN the operator pastes multi-line text
- WHEN the paste lands in the table
- THEN tab- and newline-separated values populate cells across rows

#### Scenario: Remove a row
- GIVEN the table has 5 rows
- WHEN the operator removes row 3
- THEN the table re-renders with 4 rows and credentials are renumbered

### Requirement: Step 3 — Add Data (CSV import)

The system SHALL also accept a CSV import on Step 3, with a downloadable template based on the schema's columns. The CSV import SHALL be RFC 4180-compliant (handles quoted fields and embedded commas).

#### Scenario: Download CSV template
- GIVEN Step 3 is open for schema "Diploma"
- WHEN the operator clicks "Download template"
- THEN a CSV with the schema's column headers is downloaded

#### Scenario: Import CSV
- GIVEN a CSV with 100 rows matching the schema
- WHEN the operator uploads it
- THEN the 100 rows are loaded into the editable table; a summary banner shows "100 imported"

#### Scenario: CSV with warnings
- GIVEN a CSV where 95 rows are valid and 5 have missing required fields
- WHEN the operator uploads it
- THEN the 95 valid rows are loaded; an inline warning lists the 5 skipped rows with their line numbers; the operator can fix and re-upload, or proceed to Step 4 with the 95

### Requirement: Step 4 — Preview

The system SHALL render, on Step 4, a card preview of every credential about to be issued, using the chosen design. The operator SHALL be able to return to Step 3 to fix data before committing.

#### Scenario: Preview many credentials
- GIVEN Step 3 contained 100 rows
- WHEN the operator reaches Step 4
- THEN 100 credential cards render in a paginated grid, each one populated with its row's data

#### Scenario: Spot a preview issue
- GIVEN the operator notices "Daneil" instead of "Daniel" on card 7
- WHEN they click the card or go back to Step 3
- THEN they can edit the row and return to Step 4 with the corrected preview

### Requirement: Step 5 — Create & Distribute

The system SHALL, on Step 5, issue every credential in the table, choose or confirm the distribution protocol, and render a list of distribution artifacts (QR codes, deep links, pre-authorized codes) — one per credential. For mDoc credentials, the distribution protocol SHALL be forced to OpenID4VCI.

#### Scenario: Issue and distribute via QR (W3C, DIDComm)
- GIVEN a W3C design and 5 rows ready
- WHEN the operator picks "QR (Sovra Wallet)" and clicks "Create"
- THEN 5 credentials are issued, each one produces a DIDComm invitation QR, and a credential-by-credential list is shown so the operator can share each QR individually

#### Scenario: Issue and distribute via OpenID4VCI
- GIVEN a W3C design and 5 rows ready
- WHEN the operator picks "Credential offer (OpenID4VCI)"
- THEN 5 pre-authorized codes are generated; if the design or workspace requires a txCode, the operator is prompted to send the PIN by email to each holder

#### Scenario: mDoc forces OpenID4VCI
- GIVEN an mDoc design and rows ready
- WHEN the operator reaches Step 5
- THEN the protocol selector shows only OpenID4VCI; DIDComm is hidden

#### Scenario: Partial issuance on row error
- GIVEN 100 rows where row 73 fails validation at the protocol layer
- WHEN the operator clicks "Create"
- THEN the system issues the 99 valid rows, marks row 73 as failed with the reason, and reports "99 created, 1 failed"

### Requirement: Local draft persistence

The system SHALL persist the wizard's state (selected schema, selected design, current step, table data) in local storage, and SHALL offer to restore the draft if the operator returns to the wizard later.

#### Scenario: Restore a draft
- GIVEN the operator left the wizard on Step 3 with 20 rows
- WHEN they reopen "New credential"
- THEN a banner appears: "Continue from where you left off?" with options Restore and Discard

### Requirement: Step 5 plan-limit feedback

When the underlying plan-limit guard blocks part of a batch on Step 5 (contract in [`08-plans-billing/plans.md`](../../08-plans-billing/plans.md)), the system SHALL show a result toast with the per-row outcome (issued vs. blocked) and SHALL link to the Billing page for upgrade. When the workspace is in `PAST_DUE`, Step 5 SHALL block the action with the same banner copy used elsewhere in the product.

#### Scenario: Cap reached mid-batch (UI feedback)
- GIVEN a workspace with 998 credentials issued and a limit of 1,000, and the operator tries to issue 5 credentials
- WHEN the guard blocks the last 3
- THEN the Step 5 result panel reads "2 created, 3 blocked by plan limit" with an "Upgrade plan" link

#### Scenario: Workspace in PAST_DUE
- GIVEN the workspace's subscription status is `PAST_DUE`
- WHEN the operator clicks "Create" on Step 5
- THEN Step 5 displays the standard PAST_DUE modal ("Your subscription is past due — update payment method to continue") and does not call the issuance API

## Wizard Map

| Step | Title | Operator action | Validation to advance |
|---|---|---|---|
| 1 | Select Schema | Pick or create a schema | A schema is selected |
| 2 | Select Design | Pick or create a design bound to the schema | A design is selected |
| 3 | Add Data | Fill table rows or import CSV | At least one valid row |
| 4 | Preview | Visually confirm each credential | None (always advances) |
| 5 | Create & Distribute | Pick protocol, click Create | Issuance completes |
