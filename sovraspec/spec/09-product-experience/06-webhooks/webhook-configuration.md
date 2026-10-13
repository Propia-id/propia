# Webhook Configuration

> Operator-experience layer over [`07-webhook-events/`](../../07-webhook-events/). HMAC-SHA256 signing, dual delivery semantics, and the event catalog are defined there. This document covers the operator-facing settings page (endpoints, event subscriptions, secret rotation, test delivery, delivery history).

## Purpose

Every workspace can declare up to ten webhook endpoints where the platform delivers lifecycle events: identity events (DID generation), issuance events (credential issued), verification events (presentation verified or failed), and lifecycle events (credential revoked, suspended, unsuspended). Each endpoint has a URL, the list of event types it subscribes to, an enabled flag, and its own signing secret used to verify webhook authenticity. This page describes how the operator configures these — actual delivery semantics are described in [`07-webhook-events/dual-delivery.md`](../../07-webhook-events/dual-delivery.md) and individual event payloads in [`07-webhook-events/event-system.md`](../../07-webhook-events/event-system.md). The HMAC-SHA256 signing contract lives in [`07-webhook-events/webhook-security.md`](../../07-webhook-events/webhook-security.md).

## Current Requirements

### Requirement: Webhook endpoint management

The system SHALL render a Settings → Webhooks section listing the workspace's webhook endpoints — each with its URL, subscribed event types, and enabled state — where a workspace admin can add, edit, enable, disable, and delete endpoints. A workspace SHALL have at most 10 endpoints. Workspace members without the admin role SHALL NOT be able to change them.

#### Scenario: No endpoints configured
- GIVEN a newly created workspace
- WHEN an admin opens Settings → Webhooks
- THEN the endpoint list is empty; events are recorded server-side but not delivered anywhere until an endpoint is added

#### Scenario: Endpoint limit reached
- GIVEN the workspace already has 10 endpoints
- WHEN the admin tries to add another
- THEN the addition is rejected with an error stating the limit

#### Scenario: Delete an endpoint
- GIVEN the workspace has an endpoint the operator no longer needs
- WHEN they delete it
- THEN the endpoint and its signing secret are removed; no further deliveries are made to it

### Requirement: Webhook endpoint form

The system SHALL render an endpoint form that accepts a URL and a set of event types, and enforces protocol constraints based on environment.

#### Scenario: Add an endpoint
- GIVEN an admin opens Settings → Webhooks
- WHEN they add `https://api.example.com/sovra-webhook`, keep the default event selection, and save
- THEN the endpoint is persisted, enabled, and subscribed to every event type; its signing secret is revealed once

#### Scenario: Default event selection
- GIVEN an admin opens the form to add an endpoint
- WHEN the form renders
- THEN every event type is selected; the admin unchecks the ones the endpoint should not receive

#### Scenario: At least one event type required
- GIVEN an admin has unchecked every event type
- WHEN they try to save
- THEN saving is blocked: an endpoint must subscribe to at least one event type

#### Scenario: HTTPS required in production
- GIVEN the workspace is in a production environment
- WHEN the operator enters an `http://` URL
- THEN the form blocks saving with "Webhook URL must use HTTPS"

#### Scenario: Localhost allowed in development
- GIVEN the workspace is in development
- WHEN the operator enters `http://localhost:3000/webhook`
- THEN the URL is accepted (no TLD requirement)

### Requirement: Event-type subscriptions

The system SHALL deliver to each endpoint only the event types it subscribes to. A subscription SHALL be an explicit, non-empty list drawn from the event catalog — `identity.did-generated`, `credential.issued`, `credential.revoked`, `credential.suspended`, `credential.unsuspended`, `credential.status-change-failed`, `document.status-changed`, `presentation.verified`, `presentation.failed` — with no wildcard.

#### Scenario: Subscribe to issuance events only
- GIVEN an endpoint subscribed only to `credential.issued`
- WHEN one credential is issued and another is revoked
- THEN only the `credential.issued` event is delivered to that endpoint; the revocation is still recorded server-side but not pushed to it

#### Scenario: New event type added to the catalog
- GIVEN an endpoint subscribed to every event type in the catalog
- WHEN the platform adds a new event type
- THEN the endpoint does not receive it until an operator adds it to the endpoint's subscription

### Requirement: Multiple webhook endpoints per workspace

The system SHALL deliver each event independently to every enabled endpoint subscribed to its type: each endpoint is retried on its own, and a failing endpoint SHALL NOT block delivery to the others. Every delivery of the same event SHALL carry the same payload `id`, so a receiver behind several endpoints can de-duplicate.

#### Scenario: Add a second endpoint
- GIVEN the workspace has one endpoint at `https://prod.example.com/sovra-webhook` subscribed to every event type
- WHEN the operator adds a second endpoint `https://audit.example.com/sovra-webhook` subscribed to `credential.revoked`, `credential.suspended`, and `credential.unsuspended`
- THEN both endpoints receive events according to their subscriptions; each endpoint signs with its own secret

#### Scenario: One endpoint failing
- GIVEN two endpoints are subscribed to `credential.issued` and one of them responds with 503
- WHEN a credential is issued
- THEN the healthy endpoint receives the event; the failing one is retried on its own, without delaying or repeating the delivery to the other

#### Scenario: Disable an endpoint without removing it
- GIVEN the workspace has two endpoints configured
- WHEN the operator toggles one off
- THEN that endpoint stops receiving deliveries but remains in the configuration with its URL, subscription, and secret; the operator can re-enable it later

#### Scenario: Endpoint changed while a delivery is pending
- GIVEN an event was emitted and its delivery to an endpoint has not happened yet (queued or awaiting retry)
- WHEN the endpoint is disabled, unsubscribed from that event type, or deleted before the delivery runs
- THEN the delivery is skipped instead of sent

#### Scenario: Single webhook URL carried over
- GIVEN a workspace configured a single webhook URL before multiple endpoints existed
- WHEN the platform moves to multiple endpoints
- THEN that URL becomes one enabled endpoint subscribed to every event type in the catalog at that moment, signing with the secret it already had

### Requirement: Signing secret management UI

The system SHALL give every endpoint its own signing secret and surface it with one-time reveal and copy when the endpoint is created and when its secret is rotated. The secret value SHALL never be displayed a second time.

#### Scenario: View the secret of a new endpoint
- GIVEN an admin just added an endpoint
- WHEN the endpoint is saved
- THEN its secret is shown once with a "Copy" button and a warning "Store this secret safely. You will only see it once."

#### Scenario: Rotate an endpoint's secret
- GIVEN the operator suspects one endpoint's secret leaked
- WHEN they click "Rotate" on that endpoint
- THEN a new secret is generated and shown once; the previous secret stops working immediately; the other endpoints' secrets are unchanged

### Requirement: Test event delivery action

The system SHALL provide a "Send test event" action on each endpoint that delivers a sample payload to that endpoint's URL and shows the receiver's response inline.

#### Scenario: Test the webhook
- GIVEN the operator just configured an endpoint
- WHEN they click "Send test event" on it
- THEN the platform sends a `{event:webhook.test}` payload; the response is shown in a result panel with status, latency, and response body

### Requirement: Delivery history view (Developer mode)

The system SHALL show, in Developer mode, a history of recent webhook deliveries with: event type, target URL, response status, latency, and a button to view the raw request/response payload.

#### Scenario: Browse delivery history
- GIVEN a Developer-mode operator opens Settings → Webhooks
- WHEN they scroll to the "Recent deliveries" section
- THEN they see the last 100 deliveries with the columns above; clicking a row reveals the full payload

### Requirement: Workspace-scoped configuration

The system SHALL enforce that webhook endpoints and their secrets are tied to a single workspace. Switching workspaces SHALL switch the entire webhook configuration in the UI.

#### Scenario: Switch workspaces
- GIVEN the operator is in workspace A
- WHEN they switch to workspace B
- THEN Settings → Webhooks shows B's endpoints; A's configuration is not exposed

---

## Roadmap Requirements

> The following requirements describe operator-facing capabilities that are **planned but not yet implemented**. They are documented here so the operator UI evolves consistently. Each one is mirrored in [`../../../tasks.md`](../../../tasks.md) under "Product Experience (section 09)".

### Roadmap Requirement: Raw delivery body viewer

The system SHALL allow the operator to inspect the full request and response body of any past delivery (not only Developer mode), including failed deliveries with their error messages.

#### Scenario: Inspect a failed delivery
- GIVEN a webhook delivery returned 500 from the receiver
- WHEN the operator opens the delivery in the history list
- THEN the panel shows the full request body sent, the response status, headers, response body, and any error captured client-side (timeout, DNS, TLS)

#### Scenario: Copy a delivery for replay testing
- GIVEN the operator wants to replay a past delivery against a different URL
- WHEN they click "Copy as curl"
- THEN the request is copied to clipboard as a `curl` command, ready to paste into a terminal

### Roadmap Requirement: Manual re-trigger of failed deliveries

The system SHALL allow the operator to manually re-trigger any past delivery (most commonly a failed one) from the history view, without altering the underlying event record.

#### Scenario: Replay a failed delivery
- GIVEN a delivery failed at the receiver's end (5xx)
- WHEN the operator clicks "Retry" on the row
- THEN the same event payload is re-delivered to the same URL; a new entry appears in the history with the retry result; the original entry is preserved with its original failure metadata

#### Scenario: Bulk replay
- GIVEN the operator selects multiple failed deliveries (after a downstream outage)
- WHEN they click "Retry selected"
- THEN each delivery is re-attempted in sequence; the operator sees per-row progress in the history view
