# DIDComm Credential Issuance

## Purpose

Credential issuance using the DIDComm/WACI (Wallet and Credential Interaction) protocol. The issuer creates a credential, generates an invitation QR code, and the holder scans it with their wallet to receive the credential. The flow uses DIDComm messaging for secure, peer-to-peer communication between issuer and holder.

## Requirements

### Requirement: DIDComm credential offer and delivery

The system SHALL create credential offers using the DIDComm/WACI protocol, generate invitation QR codes, and deliver signed W3C VC credentials to the holder's wallet via DIDComm messaging.

#### Scenario: Issue a credential via DIDComm
- GIVEN an issuer workspace with an active DID and a defined credential schema
- WHEN the issuer creates a credential with holder data and generates a DIDComm invitation QR
- THEN a QR code is generated containing a DIDComm invitation URL that the holder can scan with their wallet

#### Scenario: Holder accepts credential offer
- GIVEN a holder has scanned the DIDComm invitation QR with their wallet
- WHEN the wallet establishes a DIDComm connection and the holder accepts the credential offer
- THEN the issuer signs the credential with the workspace's keys and delivers it to the holder's wallet via DIDComm messaging

### Requirement: DIDComm issuance webhook notification

The system SHALL emit a `{event:issuance.credential-issued-messaging}` webhook event upon successful credential issuance via DIDComm, following the dual delivery pattern.

#### Scenario: Webhook notification on issuance
- GIVEN a credential has been successfully issued to a holder via DIDComm
- WHEN the issuance is complete
- THEN a `{event:issuance.credential-issued-messaging}` event is emitted following the dual delivery pattern -- first to the workspace's subscribed webhook endpoints, then to the central platform including the workspace's webhook response
