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
| **mDoc (ISO 18013-5)** | ✅ **Shipped — online profile** | uncommon; not planned |

Everything below unpacks that table.

## 2. Formats: W3C VC (SD-JWT) vs mDoc

**W3C Verifiable Credentials, serialized as SD-JWT VC** — what Sovra ships.
- JSON/JWT-based. The issuer signs a payload whose disclosable claims are salted hashes (`_sd` digests); the actual values travel as separate *disclosure* strings. The holder chooses which disclosures to reveal at presentation time — that is **selective disclosure**.
- Holder binding: the credential carries the holder's public key in its `cnf` claim; every presentation must be freshly signed by that key (the **KB-JWT**). A stolen credential file is unusable.
- Where in the codebase: issuance in `backend/lib/sovra/issuer/` (SD-JWT built in `sd_jwt.ex`, signed via the AWS KMS signer service), wallet-side parsing/storage in `frontend/packages/holder-core/src/credentials/`, verification in `backend/lib/sovra/credentials/sd_jwt.ex` and `frontend/packages/verification-sdk/`.

**mDoc / mDL (ISO/IEC 18013-5)** — **online profile shipped.**
- A *different* format: binary **CBOR** encoding, issuer-signed **MSO** (Mobile Security Object), its own selective-disclosure and device-binding mechanics. It is the standard for **mobile driving licences** and the eIDAS 2 / EUDI-wallet ecosystem.
- Selective disclosure works by digests rather than by hashed disclosures: the issuer signs one digest per data element, so withholding an element simply omits its bytes and the issuer's signature still verifies.
- Where in the codebase: deterministic CBOR/COSE in `backend/lib/sovra/{cbor,cose}/` and `frontend/packages/holder-core/src/{cbor,cose}/`, issuance in `backend/lib/sovra/issuer/mdoc.ex`, verification in `backend/lib/sovra/credentials/mdoc.ex` and `frontend/packages/verification-sdk/src/mdoc/`, wallet handling in `frontend/packages/holder-core/src/mdoc/`.
- **Presented over OpenID4VP**, on the same rail as SD-JWT. Only **proximity** presentment (in-person, BLE/NFC, offline — "show your licence to a police officer") needs the separate 18013-5 device-engagement stack, which is not implemented.

### What ours does and does not do

An mDoc Sovra issues is structurally conformant. Two things about it are still
deliberately Sovra-specific, and they are the difference between "an ISO reader
could verify this" and "our verifiers can":

| | What we do | What ISO expects |
|---|---|---|
| Device auth | a WebAuthn passkey assertion under a private-use COSE algorithm | a raw ES256 signature over the payload |
| Revocation | a status list index in a Sovra-reserved namespace, checked on-chain | short-lived credentials and re-issuance |

Issuer trust used to be a third row. It no longer is: a credential can now be
signed by a Document Signer Certificate and carry an `x5chain`, which is what
ISO expects and what a reader we do not control can check.

**Which of the two routes applies is decided by the docType**, and both sides
read that same signal — `Sovra.Mdoc.IssuerTrust` at issuance through
`issuer_auth_material/2`, and at verification through `resolve/2`. So issuance
and verification cannot disagree about how a given credential is meant to be
trusted:

| docType | Signed by | Attributed through |
|---|---|---|
| `io.sovra.<address>.<schema>.1` (generated) | the workspace's general signing key | the address inside the signed docType, resolved on-chain |
| `org.iso.18013.5.1.mDL` (operator-supplied) | the key its Document Signer Certificate names | the `x5chain` leaf, validated to an admitted IACA root |

Naming your own docType therefore requires a registered document signer, which
is enforced at schema creation, at offer creation, and once more at signing
time — see `Sovra.Mdl`. It is also what makes squatting `org.iso.*` harmless:
an ISO docType with no certificate behind it resolves to nobody.

Two details of the certificate route are worth keeping straight. ISO puts
`x5chain` in the *unprotected* header, which the signature does not cover — and
that is fine, because the chain only says which key to try. Substitute a
different chain and you substitute a different key, and then the signature
fails. The order matters: resolve the key from the chain, *then* verify against
it, never "the chain validated, so the credential is good".

And the chain is re-validated at verification time even though registration
already checked it. Annex B caps a Document Signer Certificate at 457 days, so
the interesting failure is one that did not exist at registration — the
certificate has since expired.

The third detail is what the certificate does *not* say. It names a key and a
subject; a Sovra workspace appears in neither. So the workspace address that
the revocation bitmaps and the Issuer Trust Registry are keyed by travels in
the Sovra meta namespace, where the issuer writes it under its own signature —
which makes it tamper-evident in transit and nothing more. The two verifiers
close that gap differently, because they know different things:

- The **backend** resolves the workspace from the key the `x5chain` leaf
  certifies and then requires the meta namespace's address to be that
  workspace's (`Verifier.check_issuer_address/3`). A workspace holding a valid
  document signer therefore cannot issue credentials attributed to another.
- The **SDK** has no workspace table and no way to check it, so it does not
  claim it. On the certificate route `issuer` is absent and the result carries
  `issuingAuthority` and `documentSigner` — what the chain actually attests —
  alongside `assertedIssuerAddress`, named for exactly what it is worth.
  Revocation is still keyed by that address, because the bitmaps are keyed by
  address and the credential carries no other; that check is only as good as
  the issuer, and is correct for every issuer acting in good faith.

On the generated route an `IssuerAuth` unprotected header still carries a
`did:sovra` reference, as a hint for a reader that would rather not parse a
docType, but no verification path reads it. It adds nothing there, because a
workspace DID is `did:sovra:` plus the same address the docType already carries
under the issuer's signature. That is the contrast worth noticing: the same
unprotected header is load-bearing on the certificate route and decorative on
the generated one, and what makes the difference is whether a wrong value fails
the signature check or merely supplies a weaker answer.

The device key is the remaining sharp edge. `deviceKeyInfo` is covered by the
issuer's signature, so a credential is bound to its key for life — a passkey
today means a WebAuthn envelope forever, and a conformant reader will not
accept it. So an mDL we issue is verifiable by anyone on the *issuer* signature
and only by our verifiers on *device auth*. Changing that is a wallet decision,
not a backend one, and is deliberately not in scope.

### The ISO namespace is a closed set

`Sovra.Mdl.Template` holds ISO's element list, and a schema in the
`org.iso.18013.5.1` namespace may declare **only** those elements, with the
types ISO fixes for them. An issuer carrying something ISO has no opinion about
puts it in a namespace beside the ISO one, which is how the standard intends
documents to be extended and how AAMVA already does it
(`org.iso.18013.5.1.aamva`). So: fixed inside the ISO namespace, extensible
next to it.

The type check is not decoration. Our digests do not care what a value means,
so a `portrait` declared as a `string` issues cleanly and verifies — and is
base64 text sitting exactly where every conformant reader expects a byte
string. That is invisible until a real reader tries to render the photograph,
which is the class of failure this whole section exists to avoid.

Two element types exist for the mDL specifically: `bytes` (a `portrait`, a
`signature_usual_mark`, a biometric template — base64 in, CBOR byte string out)
and `driving_privileges`, which is encoded field by field because its dates are
tagged `full-date` values nested inside the structure. A generic
array-of-objects type would carry them as strings.

### Both verifiers, the same set of credentials

`frontend/packages/verification-sdk` takes the certificate route too. It has its
own X.509 parser and path validation (`src/x509.ts`), scoped to what Annex B
profiles — two levels, P-256, ECDSA-SHA256 — because a general X.509
implementation would need the parts of RFC 5280 this profile does not use, and
each of those is somewhere to be wrong about a certificate a real authority
issued.

Anchors are the caller's: `verifyMdoc` takes `trustAnchors`, as DER or a PEM
bundle, and refuses an ISO docType without them. There is no default and an
empty list is not one — which authorities to trust cannot be inferred from the
credential, because the credential is what is being checked.

The issuer's address moved into the Sovra meta namespace to make this work. The
revocation bitmaps are keyed by it and an ISO docType carries none, so a
chain-only verifier had nowhere to read one from. A generated docType still
embeds it; both are issuer-signed, and the SDK requires them to agree.

### The wallet holds one

Two ISO element types need a renderer to know something about them, and both
are answered in `holder-core` rather than in the wallet, because every question
they raise is about the format: `portraitDataUri` knows which element holds the
photograph, that its bytes live in the credential blob rather than in `claims`
— a portrait is tens of kilobytes and `claims` is re-serialised to secure
storage on every write — and that the media type comes from the magic number,
since issuers ship PNG whatever ISO says. `drivingPrivilegeCategories` answers
whether a value is a privileges array at all. Laying either out is the wallet's
job and stays there.

Selective disclosure across namespaces was the real defect. A DCQL path is
`[namespace, element_identifier]`, and the wallet resolved it by taking the last
segment — which is the right answer only for the credential's own namespace.
For anything beside it, a request for `["org.iso.18013.5.1.aamva",
"document_number"]` produced the bare `document_number`: not a key `claims`
holds, so the claim vanished from the approval screen and was never disclosed —
and had anything matched, it would have been the ISO namespace's
`document_number`, which is a different number. That collision is the whole
reason element identifiers are namespaced.

### The console runs the flow

Becoming an mDL issuer is three steps, and the middle one goes through the
operator's own certification authority and can take days — which is why the
workspace holds a document signer key on its own for a while, and why the page
is a checklist rather than a form: generate the key (in KMS, never exported),
export a PKCS#10 request for it, register the certificate that comes back.

Admitting an IACA root is a separate, platform-admin screen, because it is
Sovra's decision rather than a workspace's: an issuer that could admit its own
root could vouch for itself. Reading the trust list is open to any signed-in
issuer — registering a certificate means naming the root that issued it, and a
trust list is published information by construction.

The schema builder offers ISO's element set as a **checklist rather than a
form**. An mDL's elements are not the operator's to design: the namespace is
closed, ISO fixes each element's type, and the eleven mandatory ones are always
present. The only decision left is which optional elements the licence carries.
The list is served by the backend rather than hardcoded in the console, so a
builder cannot offer an element the schema changeset rejects.

What is left is the device key, which is a wallet decision and deliberately out
of scope: an mDL Sovra issues is verifiable by anyone on the issuer signature,
and only by our verifiers on device auth.

Holding someone else's mDL is out of scope by decision — there is no intake
path for an mDL Sovra did not issue.

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

### ✅ Shipped — mDoc, online profile (#97)
Issuance over OID4VCI, presentation over OID4VP `direct_post`, verification both server-side and chain-only. See §2 for the three deliberate deviations from ISO.

Two things are **not** implemented. **Proximity presentment** — BLE, NFC handover, session encryption — is a separate transport stack, not a variation on the online flow. And the **standalone verifier app cannot verify mDocs**: the session transcript that binds a presentation hashes the `response_uri`, and that app deliberately sends none so the exchange works with neither device having network access to the other. mDoc verification runs through the hosted OID4VP flow.

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
