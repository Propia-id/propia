# Notifications

## Purpose

A notification center within the wallet that informs holders of incoming credential offers, presentation requests, and other relevant events. Notifications provide a history of interactions and can be filtered by status (read/unread) and type (offer, request, etc.).

## Requirements

### Requirement: Notification delivery for wallet interactions

The system SHALL deliver notifications for incoming credential offers and presentation requests, with direct navigation to the relevant action.

#### Scenario: Credential offer notification
- GIVEN a holder has an active wallet
- WHEN an issuer creates a credential offer for this holder (e.g., via push notification or in-app detection)
- THEN a notification appears in the wallet's notification center showing the issuer name, credential type, and timestamp, and the holder can tap to view and accept the offer

#### Scenario: Presentation request notification
- GIVEN a holder has an active wallet
- WHEN a verifier sends a presentation request
- THEN a notification appears showing the verifier name, requested credential types, and timestamp, and the holder can tap to review and respond to the request

### Requirement: Notification history and filtering

The system SHALL maintain a notification history with timestamps, supporting filtering by status (read/unread) and type (credential offer, presentation request, status change), with mark-as-read capability.

#### Scenario: Filter notification history
- GIVEN a holder has received many notifications over time
- WHEN they filter by "unread" and type "credential offer"
- THEN the notification center shows only unread credential offer notifications, sorted by most recent, allowing the holder to quickly find pending offers
