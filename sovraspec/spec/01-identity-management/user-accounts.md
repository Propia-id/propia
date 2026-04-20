# User Accounts

## Purpose

User registration, authentication, and profile management. Users create accounts associated with an organization and can authenticate via email/password or by presenting a verifiable credential. Password recovery is supported via email-based reset flows.

## Requirements

### Requirement: User registration and profile management

The system SHALL allow users to register with email, password, and organization association, and to view and update their profile information.

#### Scenario: User registration
- GIVEN a person wants to create an account on the platform
- WHEN they submit their email, password, and full name
- THEN a user account is created, a default organization is automatically created for the user (with the user as owner/admin), a default workspace is provisioned within that organization, and the user receives authentication tokens

### Requirement: Multi-method authentication

The system SHALL support authentication via email/password (returning JWT tokens) and via verifiable credential presentation.

#### Scenario: Email/password login
- GIVEN a registered user with valid credentials
- WHEN they submit their email and password
- THEN the system validates the credentials and returns a JWT access token and refresh token

#### Scenario: Credential-based login
- GIVEN a user who holds a verifiable credential recognized by the platform for authentication
- WHEN they initiate a credential-based login and successfully present the required credential via a verification flow
- THEN the system validates the presented credential, matches it to an existing user account, and returns authentication tokens

### Requirement: Password recovery

The system SHALL support password recovery via time-limited email reset links.

#### Scenario: Password recovery
- GIVEN a user who has forgotten their password
- WHEN they request a password reset using their registered email
- THEN the system sends a time-limited reset link to their email, and the user can set a new password by following the link
