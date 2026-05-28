# Subscriptions

> Platform contract. For the operator-facing subscription summary, cancellation UX, and reactivation flow, see [`09-product-experience/07-billing/billing-page.md`](../09-product-experience/07-billing/billing-page.md).

## Purpose

Subscriptions link a workspace to a plan, tracking billing cycle, payment status, and usage. The relationship is strictly 1:1 -- each workspace has exactly one subscription at any time. Plan changes update the existing subscription in place rather than creating new records.

## Requirements

### Requirement: One subscription per workspace

The system SHALL maintain a 1:1 relationship between workspaces and subscriptions. Each workspace has exactly one active subscription.

#### Scenario: Auto-provision subscription on workspace access
- GIVEN a workspace that has no subscription record
- WHEN any API endpoint accesses that workspace's subscription (e.g., checking plan limits)
- THEN the system automatically creates a subscription with the environment's default plan (Enterprise for production environments, Free for development) with billingCycle=LIFETIME and status=ACTIVE

#### Scenario: Bulk provision orphan workspaces
- GIVEN an environment with workspaces that have no subscriptions (e.g., after migration)
- WHEN `POST /plans/setup-environment` is called
- THEN all workspaces without subscriptions receive the environment's default plan subscription

### Requirement: Environment-aware default plan

The system SHALL provision different default plans based on the deployment environment:
- **development/develop**: Free plan (with Stripe sync)
- **All other environments** (sandbox, staging, production): Enterprise plan (Stripe skipped)

#### Scenario: Production environment setup
- GIVEN `NODE_ENV=production`
- WHEN `POST /plans/setup-environment` is called
- THEN plans are seeded, Stripe sync is skipped, and orphan workspaces receive Enterprise plan

#### Scenario: Development environment setup
- GIVEN `NODE_ENV=development`
- WHEN `POST /plans/setup-environment` is called
- THEN plans are seeded, Stripe products/prices are synced, and orphan workspaces receive Free plan

### Requirement: Subscription lifecycle management

The system SHALL support subscription status transitions and billing cycle management.

#### Scenario: Upgrade from Free to paid plan
- GIVEN a workspace on the Free plan
- WHEN the admin initiates a plan change to Limited with monthly billing
- THEN the system creates a Stripe checkout session and redirects the user to complete payment

#### Scenario: Stripe checkout completed
- GIVEN a user completed Stripe checkout for the Limited plan
- WHEN Stripe sends the `checkout.session.completed` webhook
- THEN the subscription is updated: planId=Limited, stripeSubscriptionId is set, billingCycle=MONTHLY, status=ACTIVE

#### Scenario: Payment fails
- GIVEN a workspace with an active paid subscription
- WHEN Stripe sends `invoice.payment_failed` webhook
- THEN the subscription status changes to PAST_DUE, and the workspace enters read-only mode (all resource creation is blocked)

#### Scenario: Cancel subscription
- GIVEN a workspace with an active paid subscription
- WHEN the admin cancels the subscription
- THEN the subscription is marked `cancelAtPeriodEnd=true`; the workspace retains access until `currentPeriodEnd`

#### Scenario: Reactivate after cancellation
- GIVEN a subscription marked for cancellation at period end
- WHEN the admin reactivates before the period ends
- THEN `cancelAtPeriodEnd` is set to false and the subscription continues normally

### Requirement: Subscription audit log

The system SHALL maintain a full audit trail of all subscription state changes.

#### Scenario: Log subscription change
- GIVEN any subscription state change (plan change, status change, cancellation)
- WHEN the change is persisted
- THEN a SubscriptionLog record is created with: subscriptionId, action, fromPlan, toPlan, fromStatus, toStatus, metadata, timestamp

## Data Model

### Subscription

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary key |
| workspaceId | UUID (unique) | One subscription per workspace |
| planId | UUID | Current plan |
| organizationId | UUID | Owning organization |
| stripeSubscriptionId | string or null | Stripe subscription ID (null for free/enterprise) |
| stripeCustomerId | string or null | Stripe customer ID |
| stripePriceId | string or null | Active Stripe price ID |
| billingCycle | enum | LIFETIME, MONTHLY, ANNUAL |
| status | enum | ACTIVE, PAST_DUE, CANCELED, TRIALING, INCOMPLETE, PAUSED |
| currentPeriodStart | timestamp | Billing period start |
| currentPeriodEnd | timestamp or null | null for LIFETIME |
| cancelAtPeriodEnd | boolean | Pending cancellation flag |
| canceledAt | timestamp or null | When cancellation was requested |

### SubscriptionLog

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary key |
| subscriptionId | UUID | Related subscription |
| action | string | Action performed (e.g., "plan_changed", "status_updated") |
| fromPlan | string or null | Previous plan name |
| toPlan | string or null | New plan name |
| fromStatus | string or null | Previous status |
| toStatus | string or null | New status |
| metadata | JSON or null | Additional context |
| createdAt | timestamp | When the change occurred |
