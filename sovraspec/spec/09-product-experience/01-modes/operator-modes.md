# Operator Modes

> Sovra-product layer (no platform-contract counterpart). The mode toggle described here is part of the canonical Sovra operator experience and is not exposed at the API; it gates which UI surfaces render and which credential-creation paths are reachable.

## Purpose

The platform has two modes — **Normal** and **Developer** — that change how much technical detail the operator sees and which paths they can take when creating credentials. Modes exist so that a non-technical operator can run a full issuance workflow without ever seeing a JSON payload, while an integrator working against the API can preview and copy the same payloads from the same screens.

## Requirements

### Requirement: Mode toggle

The system SHALL expose a mode toggle in the application header that switches the current user between Normal mode and Developer mode, persists the choice, and applies it across the entire workspace UI without requiring a reload.

#### Scenario: Default mode for new users
- GIVEN a user signs in for the first time
- WHEN they land on the workspace dashboard
- THEN they are in Normal mode and the toggle reflects that

#### Scenario: Switching to Developer mode
- GIVEN a user is in Normal mode
- WHEN they activate the Developer mode toggle in the header
- THEN every JSON-bearing surface (schema preview, design output descriptor, credential JSON view, verification raw payloads, "Wizard or JSON" dialog) becomes visible immediately, and the choice is remembered across sessions

#### Scenario: Switching back to Normal mode
- GIVEN a user has been working in Developer mode
- WHEN they deactivate the toggle
- THEN JSON panels, JSON-direct credential creation, and raw verification payloads are hidden, and the user is rerouted into the wizard if they were in the middle of a JSON-direct flow

### Requirement: JSON visibility gated by mode

The system SHALL only show JSON, raw payloads, output descriptors, and protocol-level fields when the current user is in Developer mode. In Normal mode, the same surfaces SHALL render only the visual representation.

#### Scenario: Schema builder in Normal mode
- GIVEN a user in Normal mode opens the schema builder
- WHEN they add and remove properties
- THEN they see only the visual property list with name, type, required flag, and description — no JSON Schema panel, no `@context`, no docType field

#### Scenario: Schema builder in Developer mode
- GIVEN a user in Developer mode opens the schema builder
- WHEN they add a property
- THEN the visual list updates AND a side-by-side JSON Schema preview updates live, showing `$schema`, `type: "object"`, `properties`, and `required`

#### Scenario: Design builder in Normal mode
- GIVEN a user in Normal mode opens the design builder
- WHEN they navigate the design steps
- THEN they only see Front side and Back side; there is no third "Output Descriptor JSON" stage

#### Scenario: Design builder in Developer mode
- GIVEN a user in Developer mode opens the design builder
- WHEN they navigate the design steps
- THEN a third stage labeled "Output Descriptor JSON" is visible after Back side, showing the read-only output descriptor that will be embedded in every issued credential

#### Scenario: Credential detail in Normal mode
- GIVEN a user in Normal mode opens a credential's detail screen
- WHEN they browse the screen
- THEN they see the visual card, holder information, status, and history — but no JSON view of the credential

#### Scenario: Credential detail in Developer mode
- GIVEN a user in Developer mode opens a credential's detail screen
- WHEN they browse the screen
- THEN a JSON tab is available showing the full credential payload as it was issued (proof block, signed envelope when applicable)

#### Scenario: Verification detail in Developer mode
- GIVEN a user in Developer mode opens a verification's detail screen
- WHEN they inspect a completed verification
- THEN the raw presentation request, the presentation response, and the verification result are visible as JSON, in addition to the visual summary

### Requirement: Credential creation path depends on mode

The system SHALL route credential creation differently based on the user's current mode.

#### Scenario: Normal mode — wizard only
- GIVEN a user in Normal mode is on the Credentials list
- WHEN they click "New credential"
- THEN the system navigates directly into the 5-step wizard (Step 1: Select Schema), with no intermediate dialog

#### Scenario: Developer mode — Wizard or JSON dialog
- GIVEN a user in Developer mode is on the Credentials list
- WHEN they click "New credential"
- THEN a dialog appears with two options: "Wizard" and "JSON direct". Choosing Wizard enters the same 5-step flow; choosing JSON direct opens a JSON editor pre-populated with a template for the selected schema and design

### Requirement: Mode does not change data semantics

The system SHALL ensure that resources created in either mode are identical in storage and behavior. A schema, design, credential, or verification created in Normal mode SHALL be indistinguishable from one created in Developer mode at the API and webhook level.

#### Scenario: Cross-mode editing
- GIVEN a schema created in Normal mode
- WHEN a Developer-mode user opens it
- THEN the JSON preview renders correctly and editing it (visually) produces the same output as if the schema had been created in Developer mode

### Requirement: Mode-aware help and labels

The system SHOULD adapt copy, tooltips, and error messages to the current mode — surfacing API hints, payload examples, and webhook event names in Developer mode while keeping copy plain and product-focused in Normal mode.

#### Scenario: Plan limit error in Normal mode
- GIVEN a Normal-mode operator hits the design limit
- WHEN they try to create another design
- THEN the message reads: "You've reached your design limit. Upgrade your plan to create more."

#### Scenario: Plan limit error in Developer mode
- GIVEN a Developer-mode operator hits the design limit
- WHEN they try to create another design (via UI or API)
- THEN the message reads: "Design limit reached. Resource: credentialDesigns. Current: 2. Limit: 2. Upgrade your plan."

## UI Surfaces Affected by Mode

| Surface | Normal Mode | Developer Mode |
|---|---|---|
| Schema builder | Visual editor only | + Live JSON Schema preview |
| Design builder | Front + Back | Front + Back + Output Descriptor JSON |
| New credential entry | Direct to wizard | "Wizard or JSON" dialog |
| Credential detail | Visual card + history | + JSON tab |
| Verification detail | Result + status history | + Raw request/response JSON |
| Webhook settings | URL + secret | + Event payload examples |
| API keys | Hidden | Visible (create, rotate, revoke) |
| Errors | Plain language | Plain language + technical detail |
