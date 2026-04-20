# Credential Acquisition

## Purpose

The process by which a holder receives credentials into their wallet. The holder scans a QR code, the wallet auto-detects the protocol (DIDComm or OpenID4VCI), processes the credential offer, and the holder accepts the credential. If a transaction code (PIN) is required, the holder enters it during the flow.

## Requirements

### Requirement: Multi-protocol credential acquisition

The system SHALL support credential acquisition via both DIDComm and OID4VCI protocols, with automatic protocol detection from QR code content and credential preview before acceptance.

#### Scenario: Receive credential via DIDComm
- GIVEN a holder has been offered a credential and sees a QR code
- WHEN they scan the QR with their wallet and the wallet detects a DIDComm invitation
- THEN the wallet establishes a DIDComm connection, receives the credential offer, displays a preview to the holder, and upon acceptance, receives and stores the signed credential

#### Scenario: Receive credential via OpenID4VCI
- GIVEN a holder has been offered a credential and sees a QR code
- WHEN they scan the QR with their wallet and the wallet detects an OID4VCI credential offer URI
- THEN the wallet resolves the issuer metadata, exchanges the pre-authorized code for an access token (with c_nonce), sends a credential request with proof of possession, and stores the received credential

#### Scenario: Protocol auto-detection
- GIVEN a holder scans a QR code without knowing which protocol it uses
- WHEN the wallet parses the QR content
- THEN the wallet automatically identifies the protocol (DIDComm if it contains a DIDComm invitation URL, OpenID4VCI if it contains a credential offer URI) and initiates the appropriate flow without user intervention

### Requirement: Transaction code verification during acquisition

The system SHALL prompt the holder for a transaction code (txCode/PIN) when required by the OID4VCI flow, and include it in the token exchange request.

#### Scenario: Credential acquisition with transaction code
- GIVEN a holder has received a PIN via email for a credential that requires txCode verification
- WHEN they scan the credential offer QR and the wallet detects a txCode requirement
- THEN the wallet prompts the holder to enter the PIN, includes it in the token exchange request, and only proceeds with credential acquisition after successful txCode validation
