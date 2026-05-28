# Schema Formats — Operator-facing Labels

> Operator-experience layer over [`02-credential-issuance/schema-extensions.md`](../../02-credential-issuance/schema-extensions.md). The format selection contract (W3C vs mDoc default, docType requirement, `supportsMdl` gating, format inheritance into designs and credentials) lives there. This document covers **only** the labels and reference info shown to the operator in each mode. The format toggle UI itself is described in [`schema-builder.md`](./schema-builder.md).

## Purpose

How the W3C and mDoc options are presented to the operator in the format toggle, with different labels per mode (Normal hides protocol acronyms; Developer surfaces them), and a side-by-side reference comparison for documentation purposes.

## Requirements

### Requirement: Operator-facing format labels by mode

The system SHALL show different labels for the format options depending on the active mode, hiding protocol acronyms in Normal mode and surfacing them in Developer mode.

#### Scenario: Normal-mode labels
- GIVEN a Normal-mode operator opens the format toggle
- WHEN they read the options
- THEN they see "Standard (recommended)" for W3C and "Mobile driving license (mDoc, Enterprise)" for mDoc — no "VCDM", "CBOR", or "JWT" terms

#### Scenario: Developer-mode labels
- GIVEN a Developer-mode operator opens the format toggle
- WHEN they read the options
- THEN they see "W3C Verifiable Credential (JSON / JWT)" and "mDoc (CBOR, ISO 18013-5)" with the docType input next to the mDoc option

## Reference — Format Comparison

| Aspect | W3C | mDoc |
|---|---|---|
| Encoding | JSON / JWT | CBOR |
| Plan requirement | Any plan | Enterprise |
| Issuance protocols | DIDComm + OpenID4VCI | OpenID4VCI only |
| Wallet support | Sovra Wallet, browser wallets | Sovra Wallet, mobile wallets |
| Typical use | Diplomas, memberships, tickets | Driving licenses, government IDs |
| docType required | No | Yes (e.g., `org.iso.18013.5.1`) |
