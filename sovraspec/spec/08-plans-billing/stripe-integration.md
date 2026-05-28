# Stripe Integration

> Platform contract. For the operator-facing upgrade flow (plan cards, monthly/annual toggle, "Manage payment & invoices" action, invoice list), see [`09-product-experience/07-billing/billing-page.md`](../09-product-experience/07-billing/billing-page.md).

## Purpose

Stripe provides payment processing for paid plans. The integration is optional -- environments without Stripe credentials operate normally with plan limits enforced but no payment collection. Stripe is only active in development environments; all other environments skip Stripe operations.

## Requirements

### Requirement: Conditional Stripe initialization

The system SHALL initialize the Stripe SDK only when `STRIPE_SECRET_KEY` is configured. All Stripe-dependent methods SHALL fail with a clear error if Stripe is not configured, rather than crashing at boot.

#### Scenario: Boot without Stripe credentials
- GIVEN an environment where STRIPE_SECRET_KEY is not set
- WHEN the application starts
- THEN the application boots successfully; Stripe-dependent endpoints return a clear error if called

#### Scenario: Boot with Stripe credentials
- GIVEN an environment where STRIPE_SECRET_KEY is set
- WHEN the application starts
- THEN the Stripe SDK is initialized and all payment features are available

### Requirement: Product and price synchronization

The system SHALL synchronize plans with Stripe products and prices when triggered by the admin setup endpoint (development environments only).

#### Scenario: Sync plans to Stripe
- GIVEN plans exist in the database and Stripe is configured
- WHEN `POST /plans/setup-environment` is called in a development environment
- THEN for each non-free, non-contact-sales plan: a Stripe product is created (or updated), monthly and annual prices are created if not already present, and the plan record is updated with Stripe IDs

#### Scenario: Skip Stripe sync in production
- GIVEN a production environment
- WHEN `POST /plans/setup-environment` is called
- THEN Stripe sync is skipped entirely; plans are seeded but no Stripe API calls are made

### Requirement: Checkout session creation

The system SHALL create Stripe checkout sessions for plan upgrades, embedding workspace and plan metadata for webhook reconciliation.

#### Scenario: Create checkout session
- GIVEN a workspace wants to upgrade to the Limited plan with monthly billing
- WHEN `POST /subscriptions/checkout` is called with planId, billingCycle, successUrl, cancelUrl
- THEN a Stripe checkout session is created with the correct price, customer, and metadata (workspaceId, organizationId, planId, billingCycle), and the checkout URL is returned

### Requirement: Customer portal

The system SHALL provide access to Stripe's customer portal for subscription management, payment method updates, and invoice viewing.

#### Scenario: Access customer portal
- GIVEN a workspace with an active Stripe subscription
- WHEN `POST /subscriptions/portal` is called with a returnUrl
- THEN a Stripe customer portal session is created and the portal URL is returned

### Requirement: Webhook event handling

The system SHALL process Stripe webhook events to keep subscription state synchronized.

#### Scenario: Checkout completed
- GIVEN a customer completes Stripe checkout
- WHEN `checkout.session.completed` webhook arrives
- THEN the subscription record is created/updated with stripeSubscriptionId, status=ACTIVE, and the selected plan

#### Scenario: Payment failed
- GIVEN a recurring payment fails
- WHEN `invoice.payment_failed` webhook arrives
- THEN the subscription status is set to PAST_DUE

#### Scenario: Subscription canceled by Stripe
- GIVEN a subscription is canceled (end of period or immediate)
- WHEN `customer.subscription.deleted` webhook arrives
- THEN the subscription status is set to CANCELED

### Requirement: Webhook idempotency

The system SHALL prevent duplicate webhook processing using Stripe's event ID as a unique constraint.

#### Scenario: Duplicate webhook delivery
- GIVEN a Stripe webhook event has already been processed
- WHEN the same event is delivered again (Stripe retry)
- THEN the system detects the duplicate via stripeEventId and skips processing

## Environment Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| STRIPE_SECRET_KEY | No (only for dev) | Stripe API secret key |
| STRIPE_WEBHOOK_SECRET | No (only for dev) | Stripe webhook signing secret |
| ADMIN_API_KEY | Yes (all envs) | Admin endpoint authentication |
