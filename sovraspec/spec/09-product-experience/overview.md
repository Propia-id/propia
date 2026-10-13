# Product Experience — Overview

## Purpose

This section describes Sovra's reference operator experience layered on top of the product-agnostic platform contract defined in sections 01–08. Every requirement here references its underlying platform contract; implementers who follow this section adopt the canonical Sovra UX, while implementers who only follow sections 01–08 are free to build a different operator interface as long as they honor the platform contract.

## Two operator modes

The product experience is gated by a per-user **mode toggle**: **Normal** and **Developer**. Mode determines how much technical detail is visible (JSON previews, raw payloads, output descriptors) and which credential-creation paths are reachable (5-step wizard only vs. wizard + JSON-direct). All sub-pages in this section honor the mode. See [`01-modes/operator-modes.md`](./01-modes/operator-modes.md).

## Layout

Sub-domains mirror the platform-contract sections, so the same domain is easy to find on both sides:

```
09-product-experience/
├── overview.md
├── 01-modes/
│   └── operator-modes.md
├── 02-schemas/
│   ├── schema-builder.md
│   └── schema-formats.md
├── 03-designs/
│   └── design-builder.md
├── 04-credentials/
│   ├── issuance-wizard.md
│   ├── json-direct-issuance.md
│   └── credential-lifecycle.md
├── 05-verifications/
│   └── verification-flow.md
├── 06-webhooks/
│   └── webhook-configuration.md
└── 07-billing/
    └── billing-page.md
```

## Files in this section

| Sub-folder | File | Maps to | What it covers |
|---|---|---|---|
| `01-modes/` | [`operator-modes.md`](./01-modes/operator-modes.md) | (no platform counterpart) | Normal vs Developer mode toggle, JSON visibility gating, mode-aware copy |
| `02-schemas/` | [`schema-builder.md`](./02-schemas/schema-builder.md) | [`02/credential-schemas.md`](../02-credential-issuance/credential-schemas.md) + [`02/schema-extensions.md`](../02-credential-issuance/schema-extensions.md) | Visual schema editor UX, format toggle UI, live JSON preview (Dev), inline creation, plan-limit modal |
| `02-schemas/` | [`schema-formats.md`](./02-schemas/schema-formats.md) | [`02/schema-extensions.md`](../02-credential-issuance/schema-extensions.md) | Operator-facing labels per mode, reference comparison table |
| `03-designs/` | [`design-builder.md`](./03-designs/design-builder.md) | [`02/credential-designs.md`](../02-credential-issuance/credential-designs.md) + [`02/output-descriptors.md`](../02-credential-issuance/output-descriptors.md) | Front / Back / Output Descriptor staged editor, drag-ordered attributes, live preview, plan-limit modal |
| `04-credentials/` | [`issuance-wizard.md`](./04-credentials/issuance-wizard.md) | [`02/`](../02-credential-issuance/) | 5-step wizard (schema → design → data → preview → create & distribute), CSV import |
| `04-credentials/` | [`json-direct-issuance.md`](./04-credentials/json-direct-issuance.md) | [`02/`](../02-credential-issuance/) | Developer-mode-only direct JSON path; equivalent output to wizard |
| `04-credentials/` | [`credential-lifecycle.md`](./04-credentials/credential-lifecycle.md) | [`03-credential-lifecycle/`](../03-credential-lifecycle/) | Credentials list, detail screen, status-change actions, history table |
| `05-verifications/` | [`verification-flow.md`](./05-verifications/verification-flow.md) | [`04-credential-verification/`](../04-credential-verification/) | Verification creation, distribution artifacts, real-time status, raw payloads (Dev) |
| `06-webhooks/` | [`webhook-configuration.md`](./06-webhooks/webhook-configuration.md) | [`07-webhook-events/`](../07-webhook-events/) | Webhook endpoints, event subscriptions, secret rotation, test delivery, delivery history (Dev) |
| `07-billing/` | [`billing-page.md`](./07-billing/billing-page.md) | [`08-plans-billing/`](../08-plans-billing/) | Plan cards, usage bars, customer portal, invoice history, PAST_DUE banner |

## Relationship to sections 01–08

The sections 01–08 are intentionally **product-agnostic** — they define the platform contract that any implementer can fulfill. This section 09 is **Sovra-specific** — it describes the canonical operator UI as built by Sovra. None of the requirements in 09 alter or override the platform contract; they only describe how that contract surfaces to a human operator.

If a requirement in this section appears to conflict with a section 01–08 requirement, the 01–08 requirement takes precedence (it is the contract).

## What is NOT in this section

- Protocol-level flows (DIDComm, OpenID4VCI, OpenID4VP) — see sections 02, 04
- Cryptographic key management, KMS, DID generation — see sections 01, 06
- Wallet behavior (holder-side) — see section 05
- Webhook delivery semantics and signing — see section 07
- Plan / subscription / Stripe data model — see section 08
- API contracts and endpoint routes — see the relevant functional section
