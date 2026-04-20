# Status Management

## Purpose

Manages the lifecycle state of issued credentials. Each credential has a status that follows defined transitions: ACTIVE (initial state after issuance), SUSPENDED (temporarily disabled, can be reactivated), REVOKED (permanently disabled, terminal state), and EXPIRED (time-based). Every status change records who made it, when, and an optional reason, creating a complete audit trail.

## Requirements

### Requirement: Credential status transitions with audit trail

The system SHALL enforce valid state transitions (ACTIVE to SUSPENDED or REVOKED, SUSPENDED to ACTIVE or REVOKED, REVOKED as terminal), recording the reason, timestamp, and actor for each change, and updating the BitstringStatusList accordingly.

#### Scenario: Suspend an active credential
- GIVEN a credential with status ACTIVE that needs to be temporarily disabled
- WHEN an authorized user changes the status to "suspended" with reason "Under investigation"
- THEN the credential status changes to SUSPENDED, a history entry is recorded (from: active, to: suspended, reason: "Under investigation", changedBy: user, timestamp), and the BitstringStatusList is updated

#### Scenario: Reactivate a suspended credential
- GIVEN a credential with status SUSPENDED whose investigation is resolved
- WHEN an authorized user changes the status to "active" with reason "Investigation cleared"
- THEN the credential status changes back to ACTIVE, a history entry is recorded, and the BitstringStatusList is updated to reflect the reactivation

#### Scenario: Revoke a credential (terminal)
- GIVEN a credential with status ACTIVE or SUSPENDED that must be permanently invalidated
- WHEN an authorized user changes the status to "revoked" with reason "Fraudulent documentation"
- THEN the credential status changes to REVOKED, a history entry is recorded, and no further status transitions are allowed for this credential

#### Scenario: Reject invalid status transition
- GIVEN a credential with status REVOKED
- WHEN a user attempts to change its status to "active"
- THEN the system rejects the transition with an error "Cannot transition from revoked to active" since REVOKED is a terminal state

### Requirement: Holder status awareness

The system SHALL update credential status in the holder's wallet through periodic status list checks.

#### Scenario: Wallet detects credential revocation
- GIVEN a holder has a stored credential that has been revoked by the issuer
- WHEN the wallet performs a periodic status check against the BitstringStatusList
- THEN the wallet updates the credential's displayed status to "revoked" and visually marks it as inactive

#### Scenario: Wallet detects credential suspension
- GIVEN a holder has a stored credential that has been suspended by the issuer
- WHEN the wallet performs a periodic status check against the BitstringStatusList
- THEN the wallet updates the credential's displayed status to "suspended" and visually indicates the temporary restriction
