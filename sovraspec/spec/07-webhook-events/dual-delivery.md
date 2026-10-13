# Dual Webhook Delivery

## Purpose

The dual delivery mechanism ensures that webhook events are sent to two destinations in sequence: first to the workspace's configured webhook URL, then to the central platform's webhook URL. The workspace's webhook response (success or failure) is included in the payload sent to the central platform. This allows the workspace to process events first and enables the central platform to know the workspace's reaction.

## Requirements

### Requirement: Sequential dual-destination webhook delivery

The system SHALL deliver webhook events first to the workspace's webhookUrl, capture the response, then deliver to the central platform's webhookUrl with the workspace's response included as `eventWebhookResponse`, with a 5-second timeout per delivery and graceful handling of workspace webhook failures.

#### Scenario: Successful dual delivery
- GIVEN a credential has been issued and both the workspace and platform have webhook URLs configured
- WHEN the `{event:issuance.credential-issued-messaging}` event is emitted
- THEN the event is sent first to the workspace's webhookUrl, the workspace returns HTTP 200 with response data, then the same event is sent to the platform's webhookUrl with the workspace's response included as `eventWebhookResponse` containing `{ok: true, status: 200, statusText: "OK"}`

#### Scenario: Workspace webhook fails, platform still receives
- GIVEN a verification has completed but the workspace's webhook URL is temporarily unreachable
- WHEN the event delivery is attempted
- THEN the workspace webhook delivery fails (timeout or error), the failure is recorded as `eventWebhookResponse: {ok: false, error: "..."}`, and the event is still sent to the platform's webhook URL with the error information included, so the platform knows the workspace did not receive the event

### Requirement: Partial webhook configuration handling

The system SHALL deliver events to whichever webhook URLs are configured, sending to workspace-only, platform-only, or both as applicable.

#### Scenario: Only workspace webhook configured
- GIVEN a workspace has webhook endpoints configured but no central platform webhook is configured
- WHEN an event is emitted
- THEN the event is delivered only to the workspace's enabled endpoints subscribed to it, each signed with that endpoint's signing secret, and no attempt is made to deliver to a platform URL

#### Scenario: Only platform webhook configured
- GIVEN no workspace webhook endpoint is configured but the central platform webhook is configured
- WHEN an event is emitted
- THEN the event is sent directly to the platform's webhook URL with an empty `eventWebhookResponse` (since no workspace webhook was called)
