# Usage Tracking

> Platform contract. For the operator-facing usage bars on the Billing page and the inline `current / limit` indicators on resource lists, see [`09-product-experience/07-billing/billing-page.md`](../09-product-experience/07-billing/billing-page.md).

## Purpose

Usage tracking monitors resource consumption per workspace to enforce plan limits and provide billing data. Usage is tracked in real-time against plan limits (for enforcement) and in periodic records (for billing and analytics).

## Requirements

### Requirement: Real-time usage enforcement

The system SHALL count active resources in the workspace at the time of each create request and compare against the plan's limits.

#### Scenario: Check credential issuance limit
- GIVEN a workspace on the Free plan (maxCredentialsIssued=1000) with 999 issued credentials
- WHEN the user issues one more credential
- THEN the system allows it (999 < 1000); on the next attempt (1000 >= 1000) the system blocks with 403

#### Scenario: Count only active resources for designs and schemas
- GIVEN a workspace with 2 active designs and 1 deleted (soft-deleted) design
- WHEN the plan limit check runs for designs
- THEN only the 2 active designs are counted; the deleted design does not count against the limit

### Requirement: Usage records for billing

The system SHALL maintain usage records per subscription period for billing reporting.

#### Scenario: Track credential issuance in usage record
- GIVEN a workspace with an active subscription
- WHEN a credential is issued (webhook: credential-issued)
- THEN the usage record for the current period is updated with the new credential count

### Requirement: Usage summary API

The system SHALL provide usage summary data per workspace and per organization.

#### Scenario: Get workspace usage
- GIVEN a workspace with active subscription
- WHEN `GET /subscriptions/usage/:workspaceId` is called
- THEN the response includes: plan details, current usage counts for all tracked resources, plan limits (null = unlimited), billing cycle, and period dates

#### Scenario: Get organization usage overview
- GIVEN an organization with multiple workspaces
- WHEN `GET /subscriptions/usage` is called
- THEN the response includes usage summaries for all workspaces in the organization

### Requirement: Billing analytics

The system SHALL provide billing data endpoints for cost visualization and invoice history.

#### Scenario: View billing table
- GIVEN a workspace with usage history
- WHEN `GET /billing/table?from=2026-01-01&to=2026-05-01` is called
- THEN the response includes itemized billing entries with: date, service type, units consumed, cost per unit, total cost

#### Scenario: View billing chart
- GIVEN a workspace with historical usage
- WHEN `GET /billing/chart` is called
- THEN the response includes time-series data suitable for cost-over-time visualization

## Data Model

### UsageRecord

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary key |
| subscriptionId | UUID | Related subscription |
| workspaceId | UUID | Workspace being tracked |
| organizationId | UUID | Organization |
| credentialsIssued | integer | Credentials issued in period |
| credentialDesignsCreated | integer | Designs created in period |
| schemasCreated | integer | Schemas created in period |
| verificationsPerformed | integer | Verifications in period |
| periodStart | timestamp | Period start |
| periodEnd | timestamp or null | null for LIFETIME billing |
