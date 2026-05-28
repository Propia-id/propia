# Plans

> Platform contract. For the operator-facing Billing page UX (plan cards, usage bars, the `PAST_DUE` banner, the plan-limit modal), see [`09-product-experience/07-billing/billing-page.md`](../09-product-experience/07-billing/billing-page.md).

## Purpose

Plans define the feature limits and capabilities available to each workspace. The platform offers tiered plans (Free, Limited, Enterprise) that control how many credentials, schemas, designs, and verifications a workspace can use, and whether advanced features like mDoc/mDL issuance are available.

## Requirements

### Requirement: Plan definition and seeding

The system SHALL support predefined plans with configurable resource limits, feature flags, and pricing, seeded via an admin endpoint that is idempotent (safe to run multiple times without creating duplicates).

#### Scenario: Seed plans into a new environment
- GIVEN a newly deployed environment with an empty plans table
- WHEN an administrator calls `POST /plans/setup-environment` with a valid admin API key
- THEN the system creates all predefined plans (Free, Limited, Enterprise) from the seed file, and returns the list of created plans

#### Scenario: Re-run plan seeding on existing environment
- GIVEN plans already exist in the database
- WHEN `POST /plans/setup-environment` is called again
- THEN existing plans are updated by slug (not duplicated), and Stripe product/price IDs are preserved if not provided in the seed data

### Requirement: Plan resource limits

Each plan SHALL define numeric limits (or null for unlimited) for the following resources:
- `maxCredentialsIssued` -- Maximum credentials issued per workspace
- `maxCredentialDesigns` -- Maximum credential designs per workspace
- `maxSchemas` -- Maximum schemas per workspace
- `maxVerifications` -- Maximum verifications per workspace

#### Scenario: Free plan limits
- GIVEN a workspace on the Free plan
- WHEN the workspace has issued 1,000 credentials (the plan limit)
- THEN the system rejects further credential issuance with a 403 error indicating the plan limit has been reached, including the resource name, current count, and limit

#### Scenario: Enterprise plan unlimited resources
- GIVEN a workspace on the Enterprise plan (all limits are null)
- WHEN the workspace issues any number of credentials
- THEN the system allows the operation without limit checks

### Requirement: Feature gating

Plans SHALL support boolean feature flags that gate access to specific capabilities.

#### Scenario: mDoc/mDL feature gate
- GIVEN a workspace on a plan where `supportsMdl` is false
- WHEN a user attempts to create a schema with format "mdoc"
- THEN the system rejects the request indicating that mDoc support requires a plan upgrade

#### Scenario: Enterprise mDoc access
- GIVEN a workspace on the Enterprise plan where `supportsMdl` is true
- WHEN a user creates a schema with format "mdoc" and docType "org.iso.18013.5.1"
- THEN the schema is created successfully

### Requirement: Plan limit enforcement

The system SHALL enforce plan limits on all resource-creating endpoints via a guard that checks the workspace's active subscription before allowing the operation.

#### Scenario: Plan limit guard blocks creation
- GIVEN a workspace on the Free plan with 2 designs (the plan limit for `maxCredentialDesigns`)
- WHEN the user attempts to create a third design
- THEN the system returns 403 with: `{ "resource": "credentialDesigns", "current": 2, "limit": 2 }`

#### Scenario: PAST_DUE subscription blocks all creation
- GIVEN a workspace whose subscription status is PAST_DUE
- WHEN the user attempts to create any resource (credential, schema, design, verification)
- THEN the system returns 403 indicating payment is overdue and the workspace is in read-only mode

## Data Model

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary key |
| name | string | Plan display name |
| slug | string (unique) | Machine identifier (free, limited, enterprise) |
| description | string | Plan description |
| maxCredentialsIssued | integer or null | null = unlimited |
| maxCredentialDesigns | integer or null | null = unlimited |
| maxSchemas | integer or null | null = unlimited |
| maxVerifications | integer or null | null = unlimited |
| supportsMdl | boolean | Whether mDoc/mDL issuance is available |
| isContactSales | boolean | Whether the plan requires sales contact |
| priceMonthly | decimal | Monthly price in USD (0 for free) |
| priceAnnual | decimal | Annual price in USD (0 for free) |
| stripeProductId | string or null | Stripe product ID |
| stripePriceIdMonthly | string or null | Stripe monthly price ID |
| stripePriceIdAnnual | string or null | Stripe annual price ID |
| sortOrder | integer | Display order in UI |
| status | boolean | Active/inactive flag |

## Predefined Plans

| Plan | Credentials | Designs | Schemas | Verifications | mDL | Price |
|------|------------|---------|---------|---------------|-----|-------|
| Free | 1,000 | 2 | 2 | 1,000 | No | $0 |
| Limited | 5,000 | 10 | 10 | 5,000 | No | $49/mo or $470/yr |
| Enterprise | Unlimited | Unlimited | Unlimited | Unlimited | Yes | Contact sales |
