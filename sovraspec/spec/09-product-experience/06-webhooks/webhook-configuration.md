# Webhook Configuration

> Operator-experience layer over [`07-webhook-events/`](../../07-webhook-events/). HMAC-SHA256 signing, dual delivery semantics, and the event catalog are defined there. This document covers the operator-facing settings page (URL, secret rotation, test delivery, delivery history).

## Purpose

Every workspace can declare a single webhook URL where the platform delivers lifecycle events: identity events (DID generation), issuance events (credential issued), verification events (presentation completed), and lifecycle events (credential status changed). The workspace also has a signing secret used to verify webhook authenticity. This page describes how the operator configures these — actual delivery semantics are described in [`07-webhook-events/dual-delivery.md`](../../07-webhook-events/dual-delivery.md) and individual event payloads in [`07-webhook-events/event-system.md`](../../07-webhook-events/event-system.md). The HMAC-SHA256 signing contract lives in [`07-webhook-events/webhook-security.md`](../../07-webhook-events/webhook-security.md).

## Current Requirements

### Requirement: Webhook URL form

The system SHALL render a Settings → Webhooks form that accepts a single URL and enforces protocol constraints based on environment.

#### Scenario: Set the webhook URL
- GIVEN an operator opens Settings → Webhooks
- WHEN they enter `https://api.example.com/sovra-webhook` and save
- THEN the URL is persisted; all future events for this workspace are delivered there

#### Scenario: HTTPS required in production
- GIVEN the workspace is in a production environment
- WHEN the operator enters an `http://` URL
- THEN the form blocks saving with "Webhook URL must use HTTPS"

#### Scenario: Localhost allowed in development
- GIVEN the workspace is in development
- WHEN the operator enters `http://localhost:3000/webhook`
- THEN the URL is accepted (no TLD requirement)

### Requirement: Signing secret management UI

The system SHALL surface the workspace's signing secret with one-time reveal, copy, and rotate actions. The secret value SHALL never be displayed a second time after the initial reveal or after a rotation.

#### Scenario: View the secret for the first time
- GIVEN a newly created workspace
- WHEN the operator opens Settings → Webhooks
- THEN the secret is shown once with a "Copy" button and a warning "Store this secret safely. You will only see it once."

#### Scenario: Rotate the secret
- GIVEN the operator suspects the secret leaked
- WHEN they click "Rotate"
- THEN a new secret is generated and shown once; the previous secret stops working immediately

### Requirement: Test event delivery action

The system SHALL provide a "Send test event" action that delivers a sample payload to the configured URL and shows the receiver's response inline.

#### Scenario: Test the webhook
- GIVEN the operator just configured a URL
- WHEN they click "Send test event"
- THEN the platform sends a `{event:webhook.test}` payload; the response is shown in a result panel with status, latency, and response body

### Requirement: Delivery history view (Developer mode)

The system SHALL show, in Developer mode, a history of recent webhook deliveries with: event type, target URL, response status, latency, and a button to view the raw request/response payload.

#### Scenario: Browse delivery history
- GIVEN a Developer-mode operator opens Settings → Webhooks
- WHEN they scroll to the "Recent deliveries" section
- THEN they see the last 100 deliveries with the columns above; clicking a row reveals the full payload

### Requirement: Workspace-scoped configuration

The system SHALL enforce that webhook URL and secret are tied to a single workspace. Switching workspaces SHALL switch the entire webhook configuration in the UI.

#### Scenario: Switch workspaces
- GIVEN the operator is in workspace A
- WHEN they switch to workspace B
- THEN Settings → Webhooks shows B's URL and B's secret; A's configuration is not exposed

---

## Roadmap Requirements

> The following requirements describe operator-facing capabilities that are **planned but not yet implemented**. They are documented here so the operator UI evolves consistently. Each one is mirrored in [`../../../tasks.md`](../../../tasks.md) under "Product Experience (section 09)".

### Roadmap Requirement: Event-type subscriptions

The system SHALL allow each workspace to subscribe to a subset of event types instead of receiving all events. The settings page SHALL render a checklist of available event types (identity, issuance, verification, credential lifecycle, billing) so the operator opts in.

#### Scenario: Subscribe to issuance events only
- GIVEN the operator wants their webhook to fire only when credentials are issued
- WHEN they uncheck verification, identity, credential-lifecycle, and billing events
- THEN only `{event:issuance.credential-issued-*}` events are delivered to the configured URL; other events are still recorded server-side but not pushed

#### Scenario: Default subscription
- GIVEN a newly created workspace
- WHEN no event filter is configured
- THEN the workspace receives all events (backward compatible with the current behavior)

### Roadmap Requirement: Multiple webhook URLs per workspace

The system SHALL allow the operator to configure more than one webhook URL per workspace, each with its own optional event-type filter and its own signing secret.

#### Scenario: Add a second webhook URL
- GIVEN the workspace has one URL pointed at `https://prod.example.com/sovra-webhook`
- WHEN the operator adds a second URL `https://audit.example.com/sovra-webhook` with event-type filter limited to credential lifecycle
- THEN both URLs receive events according to their filters; each URL has its own signing secret

#### Scenario: Disable a URL without removing it
- GIVEN the workspace has two URLs configured
- WHEN the operator toggles one off
- THEN that URL stops receiving deliveries but remains in the configuration; the operator can re-enable it later

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
