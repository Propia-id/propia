# mDoc Presentation

## Purpose

Presentation of mDoc credentials (ISO 18013-5 mDL) via QR code and Bluetooth Low Energy (BLE). Supports device engagement for proximity-based verification where the holder's device communicates directly with the verifier's device over BLE. Selective disclosure operates at the individual data element level within mDoc namespaces.

## Requirements

### Requirement: Multi-channel mDoc presentation

The system SHALL support mDoc credential presentation via both QR code (online OID4VP flow) and BLE (proximity flow with device engagement), including credential status information sent separately from the CBOR payload.

#### Scenario: Present mDL via QR code (online)
- GIVEN a verifier requests an mDL credential via an online verification flow (OID4VP)
- WHEN the holder scans the verifier's QR code
- THEN the wallet identifies the mDL credential, the holder selects which data elements to disclose (e.g., given_name and birth_date but not document_number), and the wallet sends the mDoc presentation via direct_post along with credentialStatus information sent separately

#### Scenario: Present mDL via BLE (proximity)
- GIVEN a verifier wants to verify an mDL in person (e.g., at a checkpoint)
- WHEN the holder initiates device engagement by displaying a QR code that the verifier scans
- THEN a BLE connection is established between the two devices, the verifier sends a request for specific data elements, the holder approves the disclosure, and the mDoc response is transmitted over BLE

### Requirement: Element-level selective disclosure for mDoc

The system SHALL enable selective disclosure at the individual data element level within mDoc namespaces, allowing holders to deselect elements they do not wish to reveal while maintaining valid MSO signatures.

#### Scenario: Element-level selective disclosure
- GIVEN a verifier requests the holder's mDL with multiple data elements from the org.iso.18013.5.1 namespace
- WHEN the holder reviews the request
- THEN the wallet shows each requested element individually (given_name, family_name, birth_date, driving_privileges, etc.), the holder can deselect elements they do not wish to reveal, and only approved elements are included in the mDoc response with valid MSO signatures
