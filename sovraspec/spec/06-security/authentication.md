# Authentication

## Purpose

The platform supports multiple authentication methods depending on the context: JWT tokens for user login (email/password), API keys for programmatic workspace access, and credential-based authentication where users log in by presenting a verifiable credential.

## Requirements

### Requirement: Multi-method platform authentication

The system SHALL support authentication via JWT tokens (email/password login), API keys (programmatic workspace access), and verifiable credential presentation, with bearer token validation for protected endpoints and token refresh for expired access tokens.

#### Scenario: Authenticate with email and password
- GIVEN a registered user with valid credentials
- WHEN they submit their email and password to the login endpoint
- THEN the system validates the credentials, generates a JWT access token and refresh token, and returns them to the client

#### Scenario: Authenticate with API key
- GIVEN a workspace with a generated API key
- WHEN a programmatic client sends a request with the workspace's API key in the appropriate header
- THEN the system validates the API key, identifies the associated workspace (tenantId), and authorizes the request within that workspace's scope

#### Scenario: Authenticate with a verifiable credential
- GIVEN a user who holds a credential that the platform accepts for authentication
- WHEN the user initiates credential-based login, scans a verification QR, and successfully presents the required credential
- THEN the system matches the presented credential to an existing user account, generates JWT tokens, and logs the user in without requiring email/password

### Requirement: Session invalidation

The system SHALL invalidate JWT tokens server-side upon logout.

#### Scenario: User logout
- GIVEN an authenticated user with an active JWT token
- WHEN they request logout
- THEN the system adds the token to a server-side blacklist, and any subsequent request using that token is rejected as unauthorized

#### Scenario: Biometric authentication fallback
- GIVEN a holder has biometric authentication enabled on their wallet
- WHEN biometric verification fails (e.g., fingerprint not recognized)
- THEN the wallet immediately falls back to PIN entry without requiring additional steps
