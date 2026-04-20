# Wallet Key Management

## Purpose

Generation, storage, and use of cryptographic keys within the holder's wallet. Keys are generated using supported algorithms (Ed25519 for general signing, ES256 for mDoc, BBS+ for selective disclosure), stored securely in the device's secure enclave when available, and encrypted with the holder's PIN. Supports key and credential export/import for wallet migration.

## Requirements

### Requirement: Secure key generation and storage

The system SHALL generate cryptographic key pairs (Ed25519, ES256, BBS+), store private keys in the device's secure enclave when available (or encrypted with PIN-derived key as fallback), and never expose private keys to the application layer.

#### Scenario: Generate an Ed25519 key pair
- GIVEN a holder is setting up their wallet or needs a new key
- WHEN a key generation is triggered (e.g., DID creation)
- THEN an Ed25519 key pair is generated, the private key is stored in the secure enclave (or encrypted with the PIN if no enclave is available), and the public key is associated with the holder's DID

#### Scenario: Sign with a stored key
- GIVEN a holder needs to create a proof of possession for a credential request
- WHEN the wallet creates a JWT proof containing a c_nonce
- THEN the wallet accesses the private key in the secure enclave, signs the JWT, and returns the signed proof without ever exposing the private key to the application layer

### Requirement: Wallet backup and migration

The system SHALL support export and import of all keys and credentials in an encrypted portable format protected by a migration password.

#### Scenario: Export and import wallet
- GIVEN a holder wants to migrate their wallet to a new device
- WHEN they initiate an export from the old device
- THEN all keys and credentials are encrypted with a migration password, packaged into a portable format, and can be imported on the new device by entering the migration password

#### Scenario: Recover wallet from backup after device loss
- GIVEN a holder has previously exported a wallet backup and loses their device
- WHEN they install the wallet on a new device and initiate import
- THEN the system prompts for the migration password, decrypts the backup, restores all keys and credentials, and the holder can resume using their wallet with the same DID and credentials
