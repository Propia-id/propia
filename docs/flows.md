# Core flows — sequence diagrams

The five flows that explain the product technically, at the level of *main steps*, not code. Each diagram shows who talks to whom, what gets signed, and with which key. For the trust rationale behind these steps see the [README — How trust works](../README.md#how-trust-works); for formats and protocols see [formats-and-protocols.md](formats-and-protocols.md).

Conventions: **Wallet app** is the holder's mobile app. **Sovra backend** is the Phoenix API. **Signer + KMS** is Sovra's internal signing service, which holds each workspace's P-256 key in AWS KMS. **Aligned** is the wallet-infrastructure backend (co-signer). **Chain** is SovraChain (Ethereum L2).

## 1. Wallet creation (smart account)

The holder's account is an [Aligned](https://github.com/lambdaclass/waas) smart account: an address whose on-chain code enforces **2-of-2** — every account operation needs the user's passkey *and* Aligned's co-signer. Sign-in is passwordless: Aligned emails a one-time code, and a wallet is created only if that user does not have one yet. The key that creates the account is generated in memory, never stored or sent, and thrown away once the account is live.

```
 Citizen                     Wallet app                      Aligned                    Chain
    │                             │                             │                         │
    │  1. Enter email             │                             │                         │
    │ ───────────────────────────>│                             │                         │
    │                             │  2. Ask for a one-time code │                         │
    │                             │     (Aligned emails 6 digits)                         │
    │                             │ ───────────────────────────>│                         │
    │  3. Type the code           │                             │                         │
    │ ───────────────────────────>│                             │                         │
    │                             │  4. Verify code -> session; │                         │
    │                             │     any wallet for this user?                         │
    │                             │ ───────────────────────────>│                         │
    │                             │                             │                         │
    │                             │  5. None yet: create passkey│                         │
    │                             │     (biometric, P-256)      │                         │
    │                             │                             │                         │
    │                             │  6. Generate throwaway EOA  │                         │
    │                             │     key (in memory only) —  │                         │
    │                             │     its address becomes the │                         │
    │                             │     account address         │                         │
    │                             │                             │                         │
    │                             │  7. Throwaway key signs twice:                        │
    │                             │     the EIP-7702 delegation, and                      │
    │                             │     the init payload (passkey                         │
    │                             │     pubkey + recovery timelock)                       │
    │                             │                             │                         │
    │                             │  8. Delegation + init signature + passkey pubkey      │
    │                             │ ───────────────────────────>│                         │
    │                             │                             │  9. One EIP-7702 tx:    │
    │                             │                             │     delegation + init   │
    │                             │                             │     (Aligned pays gas)  │
    │                             │                             │ ───────────────────────>│
    │                             │                             │                         │ 10. Smart account live:
    │                             │                             │                         │      passkey + co-signer,
    │                             │                             │                         │      2-of-2 rule active
    │                             │                             │                         │
    │                             │ 11. Throwaway key discarded │                         │
    │                             │                             │                         │
  Holder identity = did:sovra:0x<account address> — the address the throwaway key had.
  Recovery: guardian + timelock, both fixed at creation — losing the phone is not losing the identity.
```

## 2. Credential issuance (issuer → holder, OID4VCI)

The QR never contains the credential — only an *offer* with a one-time code. The credential is built **after** the wallet proves it controls its passkey, so it is born bound to the holder's account.

```
Operator                        Sovra backend                    Signer + KMS            Wallet app
    │                               │                             │                         │
    │ 1. Create offer (schema + claims)                           │                         │
    │ ─────────────────────────────>│                             │                         │
    │                               │ 2. Reserve a status-list index                        │
    │                               │    for this credential      │                         │
    │ 3. Offer URI / QR: one-time   │                             │                         │
    │    code, no credential inside │                             │                         │
    │ <─────────────────────────────│                             │                         │
    │                               │                             │                         │ 4. Holder scans the QR
    │                               │                             │                         │
    │                               │ 5. Exchange the pre-authorized code -> access token + c_nonce
    │                               │ <─────────────────────────────────────────────────────│
    │                               │ 6. Credential request + proof: a JWS over that c_nonce,
    │                               │    passkey-signed, holder pubkey in its header        │
    │                               │ <─────────────────────────────────────────────────────│
    │                               │ 7. Verify proof (nonce + signature);                  │
    │                               │    build SD-JWT (or mdoc) bound to                    │
    │                               │    did:sovra:0x<account>#2of2 and                     │
    │                               │    the reserved status index│                         │
    │                               │                             │                         │
    │                               │ 8. Sign with the workspace's│                         │
    │                               │    P-256 key (never leaves KMS)                       │
    │                               │ ───────────────────────────>│                         │
    │                               │ 9. Signature                │                         │
    │                               │ <───────────────────────────│                         │
    │                               │10. Credential               │                         │
    │                               │ ─────────────────────────────────────────────────────>│
    │                               │                             │                         │11. Store, scoped to
    │                               │                             │                         │    the wallet address
    │12. Webhook: credential.issued │                             │                         │
    │ <─────────────────────────────│                             │                         │
```

## 3. Holding (wallet)

Between issuance and presentation the credential just sits on the device — encrypted by the OS keystore, branded, and scoped to the wallet that received it. Nothing about holding requires Sovra, or the chain, to be reachable.

```
Wallet app                        OS keystore                       App storage
    │                                 │                                   │
    │ 1. Store the credential         │                                   │
    │    (SD-JWT or mdoc) + metadata, │                                   │
    │    namespaced per wallet address│                                   │
    │ ───────────────────────────────>│                                   │
    │ 2. Issuer card art and logo —   │                                   │
    │    bulk bytes, kept out of the keychain                             │
    │ ───────────────────────────────────────────────────────────────────>│
    │ 3. Render with the issuer's design.                                 │
    │    Badge = active or expired, from `exp` alone                      │
    │                                 │                                   │
  Nothing here talks to the chain. The wallet does not parse status lists yet —
  holder-core has no revocation check — so revoked / suspended are surfaced at
  verification time (diagram 5), not on the card.

  Device lost? Guardian recovery adds a key to the account on chain. Credentials
  stay valid: they bind to did:sovra:0x<account>#2of2, the account itself, not to
  one passkey — and verifiers enumerate the account's active keys at verify time.
```

## 4. Credential presentation (holder → verifier, OID4VP)

Selective disclosure in action: the wallet authenticates the verifier first, the citizen sees exactly what is asked, and the passkey signs a one-time proof that cannot be replayed elsewhere.

```
 Citizen                     Wallet app                      Verifier                 Chain
    │                             │                             │                           │
    │                             │                             │ 1. Build request: which fields
    │                             │                             │    (DCQL) + one-time nonce│
    │                             │                             │                           │
    │                             │ 2. QR (openid4vp://) — a signed request                 │
    │                             │    object, or unsigned from the verifier app            │
    │                             │ <───────────────────────────│                           │
    │                             │ 3. Resolve the request's client_id DID ->               │
    │                             │    its #key-assert key (DID Registry)                   │
    │                             │ ───────────────────────────────────────────────────────>│
    │                             │ 4. Verify the request signature.                        │
    │                             │    Unverified = hard failure; an unsigned               │
    │                             │    request shows no verifier name                       │
    │                             │                             │                           │
    │                             │ 5. Find a matching credential                           │
    │                             │                             │                           │
    │ 6. Approval screen: requested                             │                           │
    │    vs withheld fields       │                             │                           │
    │ <───────────────────────────│                             │                           │
    │ 7. Approve (biometric)      │                             │                           │
    │ ───────────────────────────>│                             │                           │
    │                             │ 8. Passkey signs the KB-JWT: nonce +                    │
    │                             │    aud=client_id + sd_hash of exactly                   │
    │                             │    what is being shared     │                           │
    │                             │                             │                           │
    │                             │ 9. vp_token: credential + approved                      │
    │                             │    disclosures only + that proof                        │
    │                             │ ───────────────────────────>│                           │
    │                             │                             │10. Verify (next diagram)  │
    │                             │                             │                           │
  A signed request is answered by direct_post to its response_uri. An unsigned one
  never is: the wallet shows the response as a QR, since nothing binds that URI to
  the verifier.
```

## 5. Credential verification (verifier ↔ chain)

The verifier needs **nothing from Sovra** — reads against the chain answer everything: who issued it, whether they were allowed to, whether it is still valid, and whether the holder is the real owner.

```
Verifier (app / SDK)                                          Chain
          │                                                   │
          │ 1. Parse the presentation (issuer JWT +           │
          │    disclosures + KB-JWT)                          │
          │                                                   │
          │ 2. Resolve issuer DID -> assertion key            │
          │    (DID Registry)                                 │
          │ ─────────────────────────────────────────────────>│
          │ 3. Verify the issuer's signature                  │
          │                                                   │
          │ 4. Issuer trusted for this credential type?       │
          │    (Issuer Registry)                              │
          │ ─────────────────────────────────────────────────>│
          │ 5. Hash each disclosure against the _sd           │
          │    digests; check iat / exp                       │
          │                                                   │
          │ 6. Read the revocation and suspension bits        │
          │    (Revocation Registry)                          │
          │ ─────────────────────────────────────────────────>│
          │ 7. Resolve the holder account's active keys       │
          │    from cnf.kid — every key with validAt <= now   │
          │ ─────────────────────────────────────────────────>│
          │ 8. Verify the KB-JWT against any one of them,     │
          │    then aud, nonce, iat and sd_hash               │
          │                                                   │
          │ 9. Valid + disclosed claims                       │
          │    (or the precise reason it failed)              │
          │                                                   │
  Every read goes to the chain and is cached per process; Sovra's servers can be
  offline and verification still works. `offlineMode` skips the chain entirely and
  checks only signatures and disclosure digests.

  A relying party that integrates through Sovra's hosted verifier gets the same
  pipeline server-side: the backend validates the vp_token it receives by
  direct_post and emits presentation.verified / presentation.failed.
```

## What changed vs. the pre-Aligned flows

If you saw older diagrams: the wallet no longer talks to a Sovra "Guardian API" for onboarding or recovery. Account creation, co-signing, and guardian recovery are Aligned's job (diagram 1); Sovra's backend only deals in credentials (diagrams 2–5). The passkey is a native WebAuthn key in the Secure Enclave, and its proofs are WebAuthn assertions verified by the backend and the verifier.
