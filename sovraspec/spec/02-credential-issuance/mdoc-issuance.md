# mDoc/mDL Issuance

## Purpose

Issuance of mobile document credentials following the ISO 18013-5 standard for Mobile Driver's Licenses (mDL). Credentials are encoded in CBOR format with MSO (Mobile Security Object) signing. The issuance flow uses OID4VCI but delivers the credential in mso_mdoc format instead of JWT.

## Requirements

### Requirement: ISO 18013-5 compliant mDL issuance

The system SHALL issue mDL credentials compliant with ISO 18013-5, encoded in CBOR format with MSO signing using ES256, organized under standard namespaces with per-element signing for selective disclosure.

#### Scenario: Issue an mDL credential
- GIVEN an issuer workspace configured with ES256 signing keys for mDL
- WHEN the issuer creates a credential offer for doctype `org.iso.18013.5.1.mDL` with the holder's driver license data
- THEN the holder's wallet exchanges the pre-authorized code for a token, presents proof of possession via COSE key, and receives an mDL credential in CBOR format signed with MSO

#### Scenario: mDL with namespaced elements
- GIVEN an mDL credential is being issued
- WHEN the issuer provides data elements (given_name, family_name, birth_date, etc.)
- THEN the elements are organized under the `org.iso.18013.5.1` namespace, each element is individually signed in the MSO for selective disclosure, and the complete mDoc is CBOR-encoded

### Requirement: mDL credential metadata discovery

The system SHALL expose credential issuer metadata including mso_mdoc format configuration, supported claims, cryptographic binding methods, and signing algorithms.

#### Scenario: mDL credential metadata discovery
- GIVEN a holder's wallet wants to discover what credential types an issuer supports
- WHEN the wallet queries the credential issuer metadata endpoint
- THEN the metadata includes the `org.iso.18013.5.1.mDL` configuration with format `mso_mdoc`, supported claims, cryptographic binding methods (cose_key), and signing algorithms (ES256)
