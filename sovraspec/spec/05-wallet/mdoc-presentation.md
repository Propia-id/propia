# mDoc Presentation

## Purpose

Presentation of mDoc credentials over OpenID4VP. Selective disclosure operates at the individual data element level within mDoc namespaces.

**Proximity presentment is not implemented.** ISO 18013-5 device engagement — BLE, NFC handover, session encryption — is a separate transport stack rather than a variation on the online flow, and is tracked separately. Everything below is the online profile.

## Requirements

### Requirement: mDoc presentation over OpenID4VP

The system SHALL support mDoc presentation through the same OpenID4VP rail as SD-JWT VC, using `response_mode=direct_post`.

#### Scenario: Present an mDoc online
- GIVEN a verifier requests an mDoc credential over OpenID4VP
- WHEN the holder scans the verifier's QR code
- THEN the wallet matches the credential by docType, the holder selects which data elements to disclose, and the wallet posts a signed `DeviceResponse` to the verifier's `response_uri`

#### Scenario: mDoc requires direct_post
- GIVEN a verification request that carries no `response_uri`
- WHEN the holder tries to present an mDoc
- THEN the wallet refuses with a message explaining that this verifier cannot accept mDoc credentials

> The session transcript that binds a presentation to one verifier hashes the
> `response_uri`. A flow without one — such as the standalone verifier app's
> offline QR exchange, where neither device has network access to the other —
> has nothing to hash, and substituting a placeholder would be a private
> convention only Sovra's own verifier could follow.

### Requirement: Credential status for mDoc

The system SHALL carry revocation status inside the credential, in a Sovra-reserved namespace, since ISO 18013-5 defines no `credentialStatus` field.

#### Scenario: Revoked mDoc is rejected
- GIVEN an mDoc whose status list index is flagged on-chain
- WHEN a holder presents it
- THEN the verifier rejects the presentation as revoked

### Requirement: Element-level selective disclosure for mDoc

The system SHALL enable selective disclosure at the individual data element level within mDoc namespaces, allowing holders to deselect elements they do not wish to reveal while maintaining valid MSO signatures.

#### Scenario: Element-level selective disclosure
- GIVEN a verifier requests several data elements
- WHEN the holder reviews the request
- THEN the wallet shows each requested element individually, the holder can deselect any that are not mandatory, and only approved elements are included in the response with the issuer's signature still valid

#### Scenario: Mandatory elements cannot be withheld
- GIVEN a schema marks an element `disclosable: false`
- WHEN the holder reviews a request for that credential
- THEN the element is shown as required with its toggle disabled, and the wallet includes it regardless of what the holder selected

> The mandatory set is frozen into the credential at issuance and signed by the
> issuer, so a verifier needs no schema lookup and a later schema revision
> cannot retroactively change what an already-issued credential must disclose.
