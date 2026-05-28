# Design Builder

> Operator-experience layer over [`02-credential-issuance/credential-designs.md`](../../02-credential-issuance/credential-designs.md) and [`02-credential-issuance/output-descriptors.md`](../../02-credential-issuance/output-descriptors.md). The Output Descriptor structure, schema binding immutability, image upload sanitization, design lifecycle constraints, and plan-limit enforcement (see [`08-plans-billing/plans.md`](../../08-plans-billing/plans.md)) are defined there. This document covers **only** the visual builder UX: the staged editor (Front / Back / Output Descriptor JSON), drag-ordered attribute list, color pickers, contrast warning, and live previews.

## Purpose

The design builder is the operator-facing UI for composing a credential's visual representation. Each design is bound 1:1 to a schema (the binding contract lives in [`output-descriptors.md`](../../02-credential-issuance/output-descriptors.md)); this document focuses on the staged editor that the operator walks through and the affordances along the way. In Developer mode, the editor exposes a third stage with the resulting Output Descriptor JSON.

## Requirements

### Requirement: Schema picker locks after creation

The system SHALL render the schema picker as the first interactive control of "New design" and SHALL disable it once the design has been saved.

> The contract that the `schemaId` is immutable lives in [`output-descriptors.md`](../../02-credential-issuance/output-descriptors.md). This requirement only describes the UI feedback.

#### Scenario: Pick an existing schema
- GIVEN the operator opens "New design"
- WHEN they pick schema "Diploma" from the dropdown
- THEN the rest of the design form unlocks, the available back-side attributes populate from the schema's properties, and the design name input is focused

#### Scenario: Create a schema inline
- GIVEN the operator opens "New design" and no schema fits
- WHEN they click "Create new schema" inside the schema selector
- THEN the schema builder opens in a modal, on save the new schema is selected, and the design form unlocks

#### Scenario: Schema disabled when editing an existing design
- GIVEN a design "Diploma 2026" has been saved
- WHEN the operator reopens it for editing
- THEN the schema selector is read-only and a tooltip explains "To change the schema, create a new design"

### Requirement: Design naming form field

The system SHALL surface a required text input for the design name in the editor's first stage.

#### Scenario: Name the design
- GIVEN the operator has chosen a schema
- WHEN they enter "University Diploma 2026" in the name field
- THEN the value is persisted as the design's display name, used in lists and in the credential wizard's design picker

### Requirement: Logo upload affordance

The system SHALL provide an "Upload logo" control that triggers a file picker and shows the uploaded thumbnail in the live preview as soon as the upload completes.

> Filename sanitization, storage location, and URL format are contract — see [`output-descriptors.md`](../../02-credential-issuance/output-descriptors.md).

#### Scenario: Upload a logo
- GIVEN the operator is editing a design
- WHEN they click "Upload logo" and select a PNG or SVG file
- THEN the file is uploaded and the front-side preview updates immediately with the logo

#### Scenario: Replace an existing logo
- GIVEN a design already has a logo
- WHEN the operator clicks "Upload logo" again and picks a different file
- THEN the new file replaces the previous URL and both previews refresh

### Requirement: Background image OR color

The system SHALL allow the operator to either upload a background image (hero) OR pick a background color, with the image taking visual precedence in the preview when both are present.

#### Scenario: Pick a background color only
- GIVEN the operator wants a flat-color credential
- WHEN they pick `#1a365d` from the color picker and do not upload a hero image
- THEN the front-side preview renders the card with that solid background

#### Scenario: Upload a background image
- GIVEN the operator wants a branded background
- WHEN they upload a JPG and keep a fallback color picked
- THEN the preview renders the image; the color is preserved as a fallback used by wallets that cannot render the image

#### Scenario: Remove the background image
- GIVEN a design has a hero image uploaded
- WHEN the operator clicks "Remove image"
- THEN the image reference is cleared and the front-side preview falls back to the background color

### Requirement: Text color picker with contrast warning

The system SHALL allow the operator to pick the text color, defaulted to a value that contrasts well with the current background, and SHALL show a non-blocking warning when the chosen text color is hard to read against the background.

#### Scenario: Default text color
- GIVEN a new design with background `#1a365d`
- WHEN the operator does not change the text color
- THEN the text color defaults to white (`#ffffff`) and no warning is shown

#### Scenario: Contrast warning
- GIVEN a design with background `#ffffff`
- WHEN the operator picks text color `#f5f5f5`
- THEN a non-blocking warning appears: "Text may be hard to read on this background"

### Requirement: Front side composition

The system SHALL allow the operator to compose the front side of the credential with four fields: **title**, **subtitle**, **description**, and **issue date label**. Placeholder substitution syntax (e.g., `{fullName}`) SHALL be supported and resolved at issuance time from the credential's data.

#### Scenario: Compose front side
- GIVEN the operator is on the Front side stage of a Diploma design
- WHEN they enter title "University Diploma", subtitle "{fullName}", description "Bachelor of Science", and issue date label "Issued"
- THEN the front-side preview renders with those values; placeholders like `{fullName}` will be substituted at issuance time

#### Scenario: Front side preview updates live
- GIVEN the operator is editing front-side fields
- WHEN they change the title
- THEN the rendered card preview reflects the change without saving

### Requirement: Back side composition (drag-ordered attributes)

The system SHALL allow the operator to compose the back side with a **title**, a **description**, and an **ordered list of displayed attributes** drawn from the schema. The attribute list SHALL be drag-and-drop reorderable. Attachment-type properties SHALL not appear in this list.

#### Scenario: Drag attributes into order
- GIVEN a schema "Diploma" with properties `fullName`, `degree`, `graduationDate`, `gpa`
- WHEN the operator opens the Back side stage and drags `graduationDate` above `degree`
- THEN the back-side preview renders the attributes in the order: fullName, graduationDate, degree, gpa

#### Scenario: Remove an attribute from display
- GIVEN the back-side list shows `gpa`
- WHEN the operator clicks the remove icon on `gpa`
- THEN the attribute is no longer rendered on the back side; the credential still carries the value but the design does not display it

#### Scenario: Attachment fields excluded
- GIVEN a schema "Driver License" with property `portrait` of type Attachment
- WHEN the operator opens the back-side attribute picker
- THEN `portrait` is not listed; only scalar properties are available for the displayed-attributes list

#### Scenario: Override an attribute label
- GIVEN the back side displays `fullName`
- WHEN the operator overrides the label to "Holder name"
- THEN the credential card renders "Holder name: …" instead of "fullName: …"

### Requirement: Output Descriptor stage (Developer mode)

The system SHALL render a third stage labeled "Output Descriptor JSON" after Back side, **only when the user is in Developer mode**. This stage SHALL be read-only and SHALL update live as the operator edits Front and Back.

#### Scenario: Output descriptor visibility
- GIVEN a Developer-mode operator is editing a design
- WHEN they navigate forward from Back side
- THEN they land on the Output Descriptor JSON stage showing the full output descriptor that will be embedded in every credential issued under this design

#### Scenario: Output descriptor hidden in Normal mode
- GIVEN a Normal-mode operator is editing a design
- WHEN they finish the Back side stage
- THEN they reach the design's save button directly; no JSON stage is shown

### Requirement: Live previews on every stage

The system SHALL render live previews of the credential's front side and back side on every editor stage, using sample data from the schema. The preview SHALL respect logo, background image, background color, and text color in real time.

#### Scenario: Live preview during editing
- GIVEN the operator is on the Back side stage
- WHEN they change the text color
- THEN both the front-side and back-side mini-previews update immediately

### Requirement: Plan-limit modal at design creation

When design creation is blocked by the plan limit (contract in [`08-plans-billing/plans.md`](../../08-plans-billing/plans.md)), the system SHALL show a modal — not just an inline error — with the resource counts and a primary "Upgrade plan" action.

#### Scenario: Normal-mode operator hits the limit
- GIVEN a workspace on the Free plan with 2 designs (the plan limit)
- WHEN the operator clicks "New design"
- THEN a modal reads "You've reached your design limit. Free plan allows 2 designs." with a primary "Upgrade plan" button and a secondary "Cancel"

## Editor Stages

| Stage | Normal mode | Developer mode |
|---|---|---|
| 1. Identity | Name + schema picker | Same |
| 2. Front side | Title, subtitle, description, issue date label, logo, background, colors | Same |
| 3. Back side | Title, description, drag-ordered attributes | Same |
| 4. Output Descriptor JSON | Hidden | Read-only JSON preview |
| 5. Save | Save & exit | Save & exit |
