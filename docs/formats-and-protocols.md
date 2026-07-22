# Formats & protocols — a map for new developers

If you are new to the credential space, this is the one document to read before touching issuance, presentation, or wallet code. It answers four questions people always conflate:

1. What is the difference between **W3C VC** and **mDoc**? (formats)
2. What is the difference between **OpenID4VC** and **DIDComm**? (transports)
3. How do QR scanning and the "inbox" relate to all of this?
4. What does Sovra actually **implement today**, and what is planned?

## 1. The two axes: format × transport

The single most useful mental model: a credential system picks one point on **each** of two independent axes.

- **Format** — what the credential *is*: how it is serialized, signed, and selectively disclosed.
- **Transport** — how the credential *moves* between issuer, holder, and verifier.

They compose freely. Choosing OpenID does not choose W3C VC, and choosing mDoc does not rule out OpenID:

| Format ↓ / Transport → | OpenID4VC (VCI + VP) | DIDComm / WACI |
|---|---|---|
| **W3C VC (SD-JWT VC)** | ✅ **Shipped — Sovra's core flow** | 🧪 Experimental (the wallet's agentic rail) |
| **mDoc (ISO 18013-5)** | 🗓 Planned — via ISO 18013-7 Annex B | uncommon; not planned |

Everything below unpacks that table.

## 2. Formats: W3C VC (SD-JWT) vs mDoc

**W3C Verifiable Credentials, serialized as SD-JWT VC** — what Sovra ships.
- JSON/JWT-based. The issuer signs a payload whose disclosable claims are salted hashes (`_sd` digests); the actual values travel as separate *disclosure* strings. The holder chooses which disclosures to reveal at presentation time — that is **selective disclosure**.
- Holder binding: the credential carries the holder's public key in its `cnf` claim; every presentation must be freshly signed by that key (the **KB-JWT**). A stolen credential file is unusable.
- Where in the codebase: issuance in `backend/lib/sovra/issuer/` (SD-JWT built in `sd_jwt.ex`, signed via OpenBao Transit), wallet-side parsing/storage in `frontend/packages/holder-core/src/credentials/`, verification in `backend/lib/sovra/credentials/sd_jwt.ex` and `frontend/packages/verification-sdk/`.

**mDoc / mDL (ISO/IEC 18013-5)** — planned, tracked in #97. **Zero code today.**
- A *different* format: binary **CBOR** encoding, issuer-signed **MSO** (Mobile Security Object), its own selective-disclosure and device-binding mechanics. It is the standard for **mobile driving licences** and the eIDAS 2 / EUDI-wallet ecosystem.
- You add mDoc when a concrete ecosystem requires it (driving licences, ISO verifier hardware, EU interop) — not because the spec lists it.
- **Key strategic fact:** mDocs can be *presented over OpenID4VP*. ISO/IEC TS 18013-7 (Annex B) profiles OID4VP as the standard mechanism for **online/remote** mDoc presentment — the same rail Sovra already runs. Only **proximity** presentment (in-person, BLE/NFC, offline — "show your licence to a police officer") requires the separate 18013-5 device-engagement stack. So the implementation order is: online profile first (reuses our infrastructure), proximity second (the genuinely new, heavy part).

## 3. Transports: OpenID4VC vs DIDComm

**OpenID4VC (OID4VCI for issuance, OID4VP for presentation)** — what Sovra ships. Think *"a web flow started by scanning a QR"*:
- Every interaction is **holder-initiated and synchronous**: scan a QR → HTTP request/response → done. Roles are fixed — issuers and verifiers are servers with public HTTPS endpoints; the wallet is always a client.
- **What is actually in our QRs** (verified against code): never the credential itself.
  - Issuance: the QR encodes `openid-credential-offer://?credential_offer={json}` — issuer URL, credential type, and a pre-authorized code (`Sovra.Issuer.build_offer_uri/4`). The wallet then exchanges the code for a token and downloads the SD-JWT over HTTPS.
  - Presentation: the QR carries the verifier's request URI; the wallet fetches the request, builds the `vp_token` (disclosures + KB-JWT), and POSTs it to the verifier's `response_uri`.

**DIDComm / WACI** — experimental. Think *"encrypted messaging between identities"*:
- Every party has an addressable DID and a **mailbox** (reachable via a *mediator*). Anyone can initiate: a verifier can push a presentation request **to** the wallet's inbox; an issuer can deliver a credential without a live QR ceremony. Asynchronous — receive at 10:00, answer at 18:00.
- Roles are symmetric: a holder can also *issue* (peer-to-peer attestations, delegations) without running a server. Two phones can exchange credentials through mediators — no public HTTPS endpoint needed.
- What it adds over OpenID4VC, capability by capability:

| Capability | OpenID4VC (today) | DIDComm |
|---|---|---|
| Initiate towards the holder | Impossible — holder always scans first | Push a request to the wallet's inbox |
| Asynchronous flows | No — sessions expire, "here and now" | Yes — mailbox holds messages |
| Persistent relationships | Each interaction is a fresh QR ceremony | Reusable connections (renewals, notifications) |
| Symmetric roles | Issuing requires running a server | Any party can issue/request/present |

- The credential format **does not change**: the experimental rail moves the same SD-JWT VCs. DIDComm is a different truck, not different cargo.

### The scanning vs inbox model, in one line

Scanning (OpenID) is the *in-person counter*: you walk up, you start, it ends. The inbox (DIDComm) is *registered mail*: things arrive addressed to you, you answer when you can, the relationship persists.

## 4. What Sovra implements today — precisely

### ✅ Shipped (production core)
SD-JWT VC over OID4VCI/OID4VP, end to end: schemas, branded designs, offer QRs, proof-of-possession, WebAuthn KB-JWT verification, on-chain revocation (Bitstring Status List), chain-only verification SDK. See the [README](../README.md) for the trust model and the code map.

### 🧪 Experimental — the DIDComm "agentic rail" (behind a flag)
A working DIDComm surface in the wallet, gated by `EXPO_PUBLIC_EXPERIMENTAL_AGENTIC`:
- **Inbox tab** (`frontend/wallet/app/(tabs)/inbox.tsx`) — receives `present-proof/3.0` requests over a DIDComm mailbox; one-tap selective presentation; granted credentials land in the wallet.
- **Issue screen** (`frontend/wallet/app/issue.tsx`) — the holder issues SD-JWT credentials under their own DID (self-sovereign issuance).
- **The rail itself** (`frontend/wallet/src/sovra/forum.ts`) — mailbox client, SD-JWT issue/present primitives, identity management. Proven live end-to-end on Android (2026-07-04).

**Why it is experimental — the identity gap.** DIDComm counterparties verify signatures *offline* from the DID itself, using raw Ed25519. Our wallet's real identity can't do that, for three reasons:
1. `did:sovra:0x…` is an Ethereum address — a hash. It does not embed a public key; resolving it requires reading SovraChain, which arbitrary DIDComm agents can't do.
2. The wallet's real key is a WebAuthn P-256 passkey in the Secure Enclave — a different curve, wrapped in WebAuthn envelopes, with a biometric prompt per signature (a background mailbox can't ask for Face ID per message).
3. So the rail mints a **temporary on-device Ed25519 identity** (`did:quarkid` long-form — the key is embedded in the DID string, verifiable offline). It works, but it is not the holder's recoverable account: reinstall the app and it is gone.

Productionizing this is tracked in **#195** (two phases: promote the rail as a beta → wire the real identity). Supporting issues: #186 (tests), #187 (build gating), #95/#101 (spec requirements). Read `frontend/wallet/EXPERIMENTAL.md` — especially its "Rewiring" section, which identifies the single seam (`loadOrCreateForumIdentity()`) everything flows through.

### 🗓 Planned — mDoc (#97)
Nothing implemented. When it lands, the order is: **online profile first** (ISO 18013-7 Annex B over our existing OID4VP rail), **proximity second** (18013-5 BLE/NFC device engagement — the heavy lift). See §2.

## The DID-resolution nuance (worth internalizing)

Two DID styles appear in this codebase, and the difference explains half of §4:

| | `did:sovra:0x…` | `did:quarkid` (long-form) |
|---|---|---|
| Public key location | **On-chain** (wallet contract / DID registry) | **Inside the DID string itself** |
| Resolvable by | Anyone with SovraChain RPC + our resolver | Anyone, offline |
| Recoverable identity | ✅ (Aligned account, guardian) | ❌ device-local |
| Used for | The core credential flows | The experimental rail's temp identity |

A DID is a pointer; each DID *method* is a different recipe for turning the pointer into a key. Our OID4VP verifiers implement the `did:sovra` recipe (we ship them). Arbitrary DIDComm agents don't — which is exactly why the rail needed a self-contained DID.

## Reading list

1. [README](../README.md) — product overview, trust model, repo map
2. `frontend/wallet/EXPERIMENTAL.md` — the agentic rail and its rewiring seam
3. `sovraspec/spec/02-credential-issuance/` + `04-credential-verification/` — the per-protocol specs (openid-*.md and didcomm-*.md variants)
4. `frontend/packages/holder-core/src/protocols/` — the OID4VCI/OID4VP client implementations
5. Issues: [#195](https://github.com/lambdaclass/sovra/issues/195) (DIDComm umbrella), [#97](https://github.com/lambdaclass/sovra/issues/97) (mDoc)
