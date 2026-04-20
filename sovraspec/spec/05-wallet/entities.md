# Entities

## Purpose

A registry of known issuers and verifiers within the holder's wallet. Entities help holders understand who issued their credentials and who is requesting presentations. Holders can view entity details (name, logo, website) and organize their credentials by entity.

## Requirements

### Requirement: Automatic entity registration

The system SHALL automatically register issuers and verifiers as entities in the wallet upon credential receipt or verifier interaction, storing name, logo, website, and DID.

#### Scenario: Auto-register issuer entity
- GIVEN a holder receives a credential from an issuer they haven't interacted with before
- WHEN the credential is stored in the wallet
- THEN the issuer is automatically registered as an entity in the wallet with available metadata (name, logo from credential design, DID), and the credential is linked to this entity

### Requirement: Entity browsing and credential organization

The system SHALL allow holders to view entity details and browse all credentials received from a specific entity.

#### Scenario: View entity details
- GIVEN a holder has credentials from multiple issuers
- WHEN they tap on an issuer entity in their wallet
- THEN the wallet displays the entity's name, logo, website, DID, and a list of all credentials received from that entity

#### Scenario: Browse credentials by entity
- GIVEN a holder wants to find all credentials from a specific organization
- WHEN they navigate to the entities section and select an entity
- THEN the wallet displays all credentials issued by that entity, showing credential type, issuance date, and current status
