# Holder Onboarding

## Purpose

The process of setting up a new digital wallet for a holder. The holder creates a wallet by setting up a PIN for security, optionally enabling biometric authentication, and generating a holder DID. The wallet is then associated with a user account.

## Requirements

### Requirement: Wallet creation and initialization

The system SHALL allow holders to create a wallet secured by a 6-digit PIN, generate a holder DID (did:key), and associate the wallet with a user account, with optional biometric authentication as an alternative unlock method.

#### Scenario: Create a wallet with PIN
- GIVEN a new user wants to set up their digital identity wallet
- WHEN they create a wallet and set a 6-digit PIN
- THEN a wallet is created, a holder DID (did:key) is generated, cryptographic keys are generated and stored encrypted with the PIN, and the wallet is associated with the user's account

#### Scenario: Enable biometric authentication
- GIVEN a holder has created a wallet with a PIN
- WHEN they enable biometric authentication on their device
- THEN the wallet can be unlocked using biometrics (fingerprint or face) as an alternative to entering the PIN, while the PIN remains as a fallback

#### Scenario: Wallet already exists for user
- GIVEN a user already has an active wallet
- WHEN they attempt to create another wallet
- THEN the system informs them that a wallet already exists and offers options to access the existing wallet or recover it if needed

### Requirement: PIN recovery

The system SHALL require wallet recreation when the PIN is lost, as credentials and keys cannot be recovered without it.

#### Scenario: Holder forgets wallet PIN
- GIVEN a holder has lost or forgotten their wallet PIN
- WHEN they attempt to access the wallet
- THEN the system informs them that the PIN cannot be recovered, and offers the option to create a new wallet, requiring re-acquisition of all credentials from their issuers

### Requirement: Brute force protection

The system SHALL implement progressive cooldown after failed PIN attempts.

#### Scenario: Multiple failed PIN attempts
- GIVEN a holder enters an incorrect PIN multiple times
- WHEN the number of failed attempts exceeds the threshold
- THEN the wallet locks temporarily with a progressive cooldown (1 minute after 3 failures, 5 minutes after 5, 15 minutes after 7), and the holder must wait before trying again
