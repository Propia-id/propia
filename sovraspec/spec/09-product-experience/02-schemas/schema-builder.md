# Schema Builder

> Operator-experience layer over [`02-credential-issuance/credential-schemas.md`](../../02-credential-issuance/credential-schemas.md) and [`02-credential-issuance/schema-extensions.md`](../../02-credential-issuance/schema-extensions.md). The data model, property types, versioning rules, format constraints, JSON Schema generation, and integrity rules are defined there. Plan-limit enforcement is defined in [`08-plans-billing/plans.md`](../../08-plans-billing/plans.md). This document covers **only** the visual builder UX: the editor layout, the live JSON preview gating by mode, and inline-creation flows.

## Purpose

The schema builder is where operators define the shape of a credential type — what fields it contains, what type each field has, whether it is required, and how it is described. The builder is a fully visual editor; in Developer mode it shows a live JSON Schema preview alongside the visual list. The available property types and the W3C/mDoc format selection are part of the contract — this document only describes the operator-facing affordances around them.

## Requirements

### Requirement: Visual schema editor

The system SHALL provide a visual editor that lets the operator define a schema by entering a name, a description, and a list of typed properties, without writing any code.

#### Scenario: Create a schema visually
- GIVEN an operator opens the Schemas section and clicks "New schema"
- WHEN they enter name "Diploma" and description "Bachelor's degree diploma", then add three properties — `fullName` (text, required), `degree` (text, required), `graduationDate` (date, required)
- THEN the schema is saved and appears in the Schemas list with format W3C by default

#### Scenario: Add a property to an existing schema
- GIVEN a schema "Diploma" already exists
- WHEN the operator opens it and adds property `gpa` of type number, marked optional
- THEN the new property is available immediately for new designs and new credentials (version increment is handled per the contract)

#### Scenario: Operator-facing property type labels
- GIVEN the operator opens the property type selector
- WHEN they browse the options
- THEN they see plain-language labels — "Text", "Number", "Integer", "Yes / No", "URL", "Date", "Date & time", "Attachment", "Group" — mapped to the contract types defined in [`schema-extensions.md`](../../02-credential-issuance/schema-extensions.md)

### Requirement: Format toggle UI (W3C / mDoc)

The system SHALL render a format toggle in the schema creation form with two options, defaulted to W3C. The mDoc option SHALL be visually disabled with an explanatory tooltip when the workspace's plan does not include `supportsMdl=true`.

> The contract for format selection, docType, and plan gating lives in [`schema-extensions.md`](../../02-credential-issuance/schema-extensions.md) and [`08-plans-billing/plans.md`](../../08-plans-billing/plans.md). This requirement only covers the toggle UI.

#### Scenario: Default to W3C visually
- GIVEN the operator opens the schema creation form
- WHEN the form first renders
- THEN the W3C option is selected by default and the docType input is hidden

#### Scenario: mDoc disabled on non-Enterprise plan
- GIVEN the workspace is on the Free or Limited plan
- WHEN the operator opens the schema creation form
- THEN the mDoc option is rendered with reduced opacity and a tooltip "Upgrade to Enterprise to issue mDoc credentials"

#### Scenario: docType input appears when mDoc selected
- GIVEN the workspace has `supportsMdl=true` and the operator selects mDoc
- WHEN the toggle moves to mDoc
- THEN the docType input becomes visible with an example placeholder (`org.iso.18013.5.1`)

### Requirement: Live JSON preview in Developer mode

The system SHALL display a live JSON Schema preview next to the visual editor whenever the current user is in Developer mode. The preview SHALL update on every property add, remove, or edit.

#### Scenario: JSON preview updates as the operator edits
- GIVEN a Developer-mode operator is creating a schema
- WHEN they add a property `email` of type Text marked required
- THEN the JSON preview updates within the same render to include `email` in `properties` and in the `required` array

#### Scenario: JSON preview hidden in Normal mode
- GIVEN a Normal-mode operator is creating a schema
- WHEN they open the builder
- THEN no JSON preview panel is rendered

### Requirement: Inline schema creation from other flows

The system SHALL allow the operator to create a schema inline when they are inside the design builder or the credential wizard and no existing schema matches their need.

#### Scenario: Inline creation from design builder
- GIVEN the operator is creating a new design and the schema dropdown shows no suitable option
- WHEN they click "Create new schema" inside the dropdown
- THEN a modal schema builder opens, on save the new schema is selected for the design, and the design builder resumes

#### Scenario: Inline creation from credential wizard
- GIVEN the operator is on Step 1 of the credential wizard with no existing schemas
- WHEN they click "Create new schema"
- THEN the same modal builder appears, and on save the wizard moves to Step 2 with the new schema selected

### Requirement: Plan-limit feedback in the builder

When the schema creation is blocked by the plan limit (see [`08-plans-billing/plans.md`](../../08-plans-billing/plans.md) for the contract), the system SHALL surface a modal — not just an inline error — with the resource counts and a primary "Upgrade plan" action.

#### Scenario: Normal-mode operator hits the limit
- GIVEN a workspace on the Free plan with 2 schemas (the plan limit)
- WHEN the operator clicks "New schema"
- THEN a modal reads "Schema limit reached. Free plan allows 2 schemas." with a primary "Upgrade plan" button and a secondary "Cancel"

#### Scenario: Developer-mode modal includes resource details
- GIVEN a Developer-mode operator hits the same limit
- WHEN the modal appears
- THEN it additionally shows the API resource identifier (`schemas`), current count, and limit, mirroring the 403 body returned by the plan-limit guard
