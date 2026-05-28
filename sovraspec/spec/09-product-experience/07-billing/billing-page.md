# Billing Page

> Operator-experience layer over [`08-plans-billing/`](../../08-plans-billing/). The plan tiers, subscription state machine, Stripe integration, usage tracking, and `PAST_DUE` read-only mode are defined there. This document covers what the operator sees on the Billing page: plan cards, usage bars, upgrade flow, customer portal access, invoice history, and the persistent payment-failed banner.

## Purpose

The Billing page is the single screen where an operator reviews their workspace's plan, monitors usage against limits, upgrades or downgrades, manages payment methods, and accesses invoices. It is also where the platform surfaces payment problems (`PAST_DUE`) and the read-only mode they trigger.

## Requirements

### Requirement: Plan selection screen

The system SHALL present plans on a Billing → Plans screen with three cards in the order **Free, Limited, Enterprise**, marking the workspace's current plan and showing a clear comparison of limits and features.

#### Scenario: View plan options
- GIVEN the operator opens Billing → Plans
- WHEN the page loads
- THEN three plan cards are displayed in order, the current plan is marked (e.g., "Current"), and each card lists the credential / design / schema / verification limits and the mDoc feature flag

#### Scenario: Monthly vs annual toggle
- GIVEN the Plans screen is open
- WHEN the operator toggles "Save 20%" / Annual
- THEN the prices on each paid card update to the annual rate, and "Upgrade" launches checkout with the annual price ID

#### Scenario: Click-through to upgrade
- GIVEN a Free-plan operator clicks "Upgrade" on the Limited card
- WHEN they choose a billing cycle
- THEN a Stripe checkout session is created (development environments only) and the checkout opens in a new tab

### Requirement: Usage visualization

The system SHALL display, on the Billing page, the workspace's current usage versus the plan limit for each governed resource (credentials issued, schemas, designs, verifications) using a usage bar.

#### Scenario: Usage bars on Billing
- GIVEN a Free-plan workspace with 750 credentials, 1 schema, 1 design, 200 verifications
- WHEN the operator opens Billing
- THEN four usage bars are visible: "Credentials: 750 / 1,000", "Schemas: 1 / 2", "Designs: 1 / 2", "Verifications: 200 / 1,000"

#### Scenario: Unlimited resources show no bar
- GIVEN an Enterprise workspace (all limits null)
- WHEN the operator opens Billing
- THEN usage counts are shown but no progress bars (since there is no limit to compare against)

#### Scenario: Inline usage indicators on resource lists
- GIVEN a Free-plan workspace with 1 schema
- WHEN the operator opens the Schemas list
- THEN a small "1 / 2" indicator is rendered near the "New schema" button

### Requirement: Customer portal access

The system SHALL surface a "Manage payment & invoices" action on the Billing page that opens a Stripe customer portal session in a new tab, where the operator can update the payment method, view invoices, and cancel.

#### Scenario: Open the customer portal
- GIVEN an active paid subscription
- WHEN the operator clicks "Manage payment & invoices"
- THEN the platform creates a customer portal session (see [`08-plans-billing/stripe-integration.md`](../../08-plans-billing/stripe-integration.md)) and opens the portal URL in a new tab

#### Scenario: Customer portal hidden for non-paid plans
- GIVEN the workspace is on Free or Enterprise (LIFETIME)
- WHEN the operator opens Billing
- THEN the customer portal action is hidden (there is no Stripe subscription to manage)

### Requirement: Invoice history

The system SHALL list past invoices for the workspace's subscription on the Billing page, with date, amount, status, and a link to download the Stripe-hosted PDF.

#### Scenario: View past invoices
- GIVEN a workspace with 6 months of Limited monthly billing
- WHEN the operator scrolls to "Invoices"
- THEN 6 rows are visible, each linking to its PDF on Stripe

#### Scenario: No invoices to show
- GIVEN a Free-plan workspace
- WHEN the operator opens Billing
- THEN the Invoices section shows an empty state ("No invoices yet") with no rows

### Requirement: Subscription summary

The system SHALL display, on the Billing page, the current plan, billing cycle, current period start/end, next charge date (if applicable), and cancel-at-period-end flag.

#### Scenario: Active subscription summary
- GIVEN an active Limited annual subscription
- WHEN the operator opens Billing → Subscription
- THEN the summary shows "Plan: Limited (Annual)", "Started: 2026-01-15", "Renews: 2027-01-15", "Cancel at period end: No"

#### Scenario: LIFETIME subscription omits renewal
- GIVEN an Enterprise LIFETIME subscription (non-development environments)
- WHEN the operator opens Billing
- THEN the summary shows "Plan: Enterprise" with no renewal date and no Stripe-related controls

#### Scenario: Cancellation pending
- GIVEN a Limited subscription with `cancelAtPeriodEnd=true`
- WHEN the operator opens Billing
- THEN a banner explains "Your plan will downgrade to Free on YYYY-MM-DD" and a "Reactivate" button is offered

### Requirement: Payment-failed banner and read-only mode

The system SHALL display a persistent payment-failed banner on every page (not just Billing) when the workspace's subscription is in `PAST_DUE`, and SHALL block all resource creation while in that state. The underlying enforcement is defined in [`08-plans-billing/plans.md`](../../08-plans-billing/plans.md).

#### Scenario: Banner on every page
- GIVEN the workspace's subscription moves to `PAST_DUE` (Stripe `invoice.payment_failed`)
- WHEN the operator opens any page in the workspace
- THEN a persistent red banner reads "Your payment failed. Update your payment method to continue creating credentials." with a button linking to the customer portal

#### Scenario: Creation blocked while PAST_DUE
- GIVEN the workspace is `PAST_DUE`
- WHEN the operator clicks "New credential", "New schema", "New design", or "New verification"
- THEN creation is blocked with a modal explaining the payment is overdue and offering "Update payment method"

#### Scenario: Banner clears after payment succeeds
- GIVEN the workspace is `PAST_DUE`
- WHEN the operator updates the card in the customer portal and Stripe processes a successful payment
- THEN Stripe emits the corresponding webhook (see [`08-plans-billing/stripe-integration.md`](../../08-plans-billing/stripe-integration.md)), the subscription returns to `ACTIVE`, the banner disappears, and creation is unblocked

### Requirement: Plan-limit modal at point of action

The system SHALL show a focused modal — not just an inline error — when a creation action is blocked by a plan limit, with the relevant resource name, current count, and limit, plus a primary "Upgrade plan" button.

#### Scenario: Hit a limit during creation
- GIVEN a Free-plan workspace with 2 designs (limit = 2)
- WHEN the operator clicks "New design"
- THEN a modal appears: "You've reached your design limit. Free plan allows 2 designs." with primary action "Upgrade plan" and a secondary "Cancel"

#### Scenario: Developer-mode modal includes resource details
- GIVEN a Developer-mode operator hits the same limit
- WHEN the modal appears
- THEN it additionally shows the resource identifier (`credentialDesigns`), current count, and limit, mirroring the 403 response body from the plan-limit guard
