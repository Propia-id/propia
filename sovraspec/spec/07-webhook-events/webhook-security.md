# Webhook Security

## Purpose

Security mechanisms for webhook delivery. Each webhook payload is signed using HMAC-SHA256 with the workspace's webhookSecret, allowing receivers to verify authenticity and integrity. The system supports automatic retries on delivery failure and maintains a delivery history.

## Requirements

### Requirement: HMAC-SHA256 webhook payload signing

The system SHALL sign all webhook payloads using HMAC-SHA256 with the workspace's webhookSecret, including the signature in the `x-webhook-signature` HTTP header, computed over the complete JSON payload.

#### Scenario: Verify webhook signature
- GIVEN a workspace receives a webhook event at its configured URL
- WHEN the HTTP POST arrives with a JSON body and an `x-webhook-signature` header
- THEN the receiver computes HMAC-SHA256 of the raw request body using their webhookSecret, compares it with the `x-webhook-signature` header value, and accepts the webhook only if the signatures match

### Requirement: Webhook delivery reliability

The system SHALL automatically retry failed webhook deliveries up to 3 times with backoff, support manual redelivery, and maintain a delivery history with HTTP response status and timestamps, using a 5-second delivery timeout.

#### Scenario: Automatic retry on failure
- GIVEN a webhook delivery to a workspace's URL fails (network error, timeout, or 5xx response)
- WHEN the initial delivery attempt fails
- THEN the system retries delivery up to 3 additional times with appropriate backoff, and if all attempts fail, records the final failure status in the delivery history

#### Scenario: Manual redelivery
- GIVEN a webhook event was delivered but the workspace needs to receive it again (e.g., their system was processing incorrectly at the time)
- WHEN an admin triggers manual redelivery for a specific event
- THEN the system re-sends the original event payload to the workspace's current webhookUrl with a fresh HMAC-SHA256 signature, and records the redelivery attempt in the delivery history
