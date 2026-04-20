# OpenID4VCI Credential Issuance

## Purpose

Credential issuance using the OpenID for Verifiable Credential Issuance (OID4VCI) protocol. The issuer creates a credential offer with a pre-authorized code, optionally requiring a transaction code (PIN) for additional security. The holder's wallet resolves the offer, exchanges the pre-authorized code for an access token, presents proof of possession, and receives the signed credential.

## Requirements

### Requirement: Pre-authorized code credential issuance

The system SHALL support credential issuance via OID4VCI with pre-authorized code grants, optional transaction code (txCode/PIN) verification, and proof of possession validation using c_nonce binding.

#### Scenario: Issue a credential with pre-authorized code (no PIN)
- GIVEN an issuer workspace wants to issue a credential to a holder
- WHEN the issuer creates a credential offer with a pre-authorized code and no txCode requirement
- THEN a credential offer URI is generated, the holder's wallet resolves it, exchanges the pre-authorized code for an access token, presents proof of possession with the c_nonce, and receives the signed credential

#### Scenario: Issue a credential with transaction code (PIN)
- GIVEN an issuer workspace wants to issue a credential with additional PIN verification
- WHEN the issuer creates a credential offer with a pre-authorized code and a txCode configuration (numeric, 6 digits)
- THEN a PIN is sent to the holder via email, the holder's wallet must include the txCode when exchanging the pre-authorized code for an access token, and only then can the holder request the credential

#### Scenario: Proof of possession validation
- GIVEN a holder has obtained an access token and a c_nonce from the token endpoint
- WHEN the holder sends a credential request with a JWT proof containing the c_nonce
- THEN the system verifies the JWT proof (signature, nonce binding, expiry), confirms the holder controls the key, and issues the credential bound to the holder's key

### Requirement: Credential configuration auto-registration

The system SHALL auto-register unknown credential configuration IDs as JWT VC entries, allowing credential offers to proceed without manual configuration.

#### Scenario: Unknown credential type auto-registration
- GIVEN an issuer creates an offer for a credential configuration ID not previously registered
- WHEN the offer is created
- THEN the system auto-registers the unknown configuration as a generic JWT VC entry with default settings, allowing the offer to proceed without manual configuration

### Requirement: Credential issuer metadata discovery

The system SHALL expose credential issuer metadata at the well-known endpoint (/.well-known/openid-credential-issuer) and emit `{event:issuance.credential-issued-rest}` webhook events upon successful issuance.

#### Scenario: Webhook notification on OID4VCI issuance
- GIVEN a credential has been successfully issued via OID4VCI
- WHEN the issuance is complete
- THEN a `{event:issuance.credential-issued-rest}` event is emitted following the dual delivery pattern, containing the credentialId, tenantId, and credentialConfigurationId
