import type {
  ApiClient,
  IssuerMetadata,
  CredentialMetadata,
  CredentialDisplay,
  ClaimDescription,
} from "../api/index.js";
import { isAttachmentDescriptor } from "../credentials/attachment.js";
import { isEnvelopeClaim } from "../credentials/envelope.js";
import { parseBase64DataUri } from "../utils/data-uri.js";
import {
  buildDeviceResponse,
  holderSignerToDeviceSigner,
  parseIssuerSigned,
  SOVRA_META_NAMESPACE,
} from "../mdoc/index.js";
import { assertionToJwtSegment as toJwtSegment } from "./types.js";
import type { HolderSigner } from "./types.js";
import type { CredentialManager } from "../credentials/index.js";
import type {
  CredentialDisplayMetadata,
  CredentialFormat,
  MdocElementMeta,
  PendingLogo,
  StoredCredential,
  StoredMdocCredential,
  StoredSdJwtCredential,
} from "../state/index.js";
import {
  base64urlDecode,
  base64urlEncode,
  p256Verify,
  sha256,
} from "../utils/index.js";
import { parseDidUrl, resolveAssertionKey } from "../did/index.js";

// ─── Holder signing seam ──────────────────────────────

export { assertionToJwtSegment } from "./types.js";
export type {
  HolderAssertion,
  HolderSigner,
  RawEs256Signature,
  WebAuthnAssertion,
} from "./types.js";

// ─── OID4VCI Types ────────────────────────────────────

export interface CredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": string;
      tx_code?: { input_mode?: string; length?: number; description?: string };
    };
  };
}

// ─── OpenID4VP Types ──────────────────────────────────

export interface DCQLQuery {
  credentials: Array<{
    id: string;
    format: string;
    /** `vct_values` for SD-JWT; `doctype_value` for mdoc. */
    meta?: { vct_values?: string[]; doctype_value?: string };
    claims?: Array<{ path: string[]; id?: string; intent_to_retain?: boolean }>;
  }>;
}

/**
 * One requested claim, resolved against a held credential.
 *
 * A path rather than a bare name because an mdoc claim is
 * `[namespace, element_identifier]`. Encoding that back into a string would
 * push splitting into every consumer and — worse — would keep compiling
 * everywhere, which is exactly the silent breakage this migration exists to
 * surface.
 */
export interface ClaimRef {
  /** Selection key and React key: `"ns/elem"` for mdoc, the claim name for SD-JWT. */
  id: string;
  path: string[];
  /** Last path segment, which the existing label lookup keys on. */
  key: string;
  /** From the schema's `disclosable: false` — the holder may not withhold it. */
  mandatory: boolean;
}

export interface VPRequest {
  clientId: string;
  nonce: string;
  dcqlQuery: DCQLQuery;
  /**
   * The verifier's own name, and only ever from a request whose signature
   * verified. An unsigned request has no attested name, so this stays
   * undefined however loudly its `client_metadata` claims one.
   */
  verifierName?: string;
  state?: string;
  responseUri?: string;
  responseMode?: string;
  /**
   * Whether this request arrived as a signed request object whose signature
   * verified against a key its own `client_id` resolves to. False means the
   * verifier is unauthenticated — not that it is hostile, but nothing it says
   * about itself has been established.
   */
  verified: boolean;
}

/**
 * Why a verifier rejected a presentation, as it tells the wallet. Coarse by
 * design: what the holder can act on, and `invalid_presentation` for every
 * failed check they cannot.
 */
export type RejectionReason =
  | "credential_expired"
  | "credential_revoked"
  | "credential_suspended"
  | "session_expired"
  | "unknown_issuer"
  | "request_not_satisfied"
  | "verifier_error"
  | "invalid_presentation";

const REJECTION_REASONS: ReadonlySet<string> = new Set<RejectionReason>([
  "credential_expired",
  "credential_revoked",
  "credential_suspended",
  "session_expired",
  "unknown_issuer",
  "request_not_satisfied",
  "verifier_error",
  "invalid_presentation",
]);

/**
 * The verifier's answer to a direct_post. Its `verification_result` is a
 * Sovra extension to the OID4VP 1.0 §8.2 response, which the spec permits;
 * a verifier that does not send one yields `submitted` — delivered, verdict
 * unknown. `already_answered` means the request had reached a verdict before
 * this submission, which therefore changed nothing.
 */
export type PresentationOutcome =
  | { result: "verified" }
  | { result: "rejected"; reason?: RejectionReason }
  | { result: "already_answered" }
  | { result: "submitted" };

/**
 * Unknown values read as the nearest thing this release understands: §8.2
 * has the wallet ignore what it does not recognise, so a reason added later is
 * a rejection without a reason, and a result added later is no verdict at all.
 */
export function parsePresentationOutcome(body: unknown): PresentationOutcome {
  if (typeof body !== "object" || body === null) return { result: "submitted" };
  const { verification_result: result, reason } = body as Record<string, unknown>;
  switch (result) {
    case "verified":
    case "already_answered":
      return { result };
    case "rejected":
      return typeof reason === "string" && REJECTION_REASONS.has(reason)
        ? { result, reason: reason as RejectionReason }
        : { result };
    default:
      return { result: "submitted" };
  }
}

export interface ApprovalData {
  /**
   * The attested name, and only from a request whose signature verified.
   * Undefined means the consent screen has nothing to call the verifier — it
   * says so, rather than falling back to anything the request claimed.
   */
  verifierName?: string;
  /** Mirrors `VPRequest.verified` — the consent screen has to say which it is. */
  verified: boolean;
  credentialType: string;
  format: CredentialFormat;
  sharedClaims: ClaimRef[];
  withheldClaims: ClaimRef[];
  credential: StoredCredential;
  /** What the verifier asked for; re-derive against it when the holder switches. */
  requestedClaims: ClaimRef[];
  /** Every credential the request accepts, `credential` among them. */
  matches: StoredCredential[];
}

// ─── Issuer display metadata ──────────────────────────

/** Exact locale match, then same language, then the first entry. */
function pickByLocale<T extends { locale?: string }>(
  entries: T[] | undefined,
  preferredLocale?: string,
): T | undefined {
  if (!entries || entries.length === 0) return undefined;

  if (preferredLocale) {
    const wanted = preferredLocale.toLowerCase();
    const language = wanted.split("-")[0];
    const exact = entries.find((e) => e.locale?.toLowerCase() === wanted);
    if (exact) return exact;
    const sameLanguage = entries.find(
      (e) => e.locale?.toLowerCase().split("-")[0] === language,
    );
    if (sameLanguage) return sameLanguage;
  }

  return entries[0];
}

/** Exact locale match, then same language, then the first entry. */
export function pickCredentialDisplay(
  display: CredentialDisplay[] | undefined,
  preferredLocale?: string,
): CredentialDisplay | undefined {
  return pickByLocale(display, preferredLocale);
}

/**
 * Claim key → the issuer's label, from the configuration's claims descriptions
 * (OID4VCI 1.0 Appendix B.2). Locale resolution matches the card's.
 *
 * Only single-segment paths map to a key: the wallet stores flat claims, so a
 * pointer into a nested structure has nothing to attach a label to. Claims
 * described without a `display` are skipped so the wallet keeps deriving a
 * label from the key rather than showing nothing.
 */
export function pickClaimLabels(
  claims: ClaimDescription[] | undefined,
  preferredLocale?: string,
): Record<string, string> | undefined {
  if (!claims || claims.length === 0) return undefined;

  const labels: Record<string, string> = {};
  for (const claim of claims) {
    if (claim.path?.length !== 1) continue;
    const key = claim.path[0];
    if (typeof key !== "string" || !key) continue;
    const name = pickByLocale(claim.display, preferredLocale)?.name?.trim();
    if (name) labels[key] = name;
  }

  return Object.keys(labels).length > 0 ? labels : undefined;
}

/**
 * The `display` + `claims` for one credential configuration, from wherever the
 * issuer put them.
 *
 * OID4VCI 1.0 nests both under `credential_metadata`; drafts before it place
 * them directly on the configuration, and issuers in the wild still publish
 * that shape. Reading only the 1.0 location yields `undefined` against those
 * issuers, which is silent: the credential stores no display, so the wallet
 * falls back to its own hashed card colour and drops the issuer's claim
 * labels, with nothing anywhere saying why.
 *
 * Standard location first so a 1.0 issuer is never second-guessed.
 */
export function credentialMetadataFor(
  metadata: IssuerMetadata,
  credConfigId: string,
): CredentialMetadata | undefined {
  const configuration = metadata.credential_configurations_supported?.[credConfigId];
  if (!configuration) return undefined;
  return configuration.credential_metadata ?? configuration;
}

/**
 * Media types the wallet can actually draw, mapped to the extension its asset
 * key carries. Anything else (a TIFF, an unknown type) is skipped rather than
 * stored: a file no image view can decode is worse than the brand fallback.
 */
const LOGO_EXTENSIONS: Record<string, string> = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/svg+xml": "svg",
};

/**
 * Cap on the base64 payload accepted from an issuer, ~1.33x the bytes it
 * encodes. The issuer console caps an uploaded logo at 256KB and the backend
 * rejects a `uri` over 256KB, so 512KB of base64 clears both with room to
 * spare while still refusing to write an unbounded blob to disk.
 */
const MAX_LOGO_BASE64_LENGTH = 512 * 1024;

/**
 * Caps on the fields kept whole on the credential. Unlike the `data:` payload
 * these reach the credential index, which is persisted into the platform
 * secure store (2048-byte advisory limit per value). 512 is twice the
 * 255-character column the backend stores an organization's logo URL in; the
 * alt text is one phrase for a screen reader, and the backend bounds it
 * nowhere.
 */
const MAX_LOGO_URL_LENGTH = 512;
const MAX_LOGO_ALT_LENGTH = 128;

/**
 * The card logo off one `display` entry, in the form the wallet can persist.
 *
 * This is the issuer's own artwork — the thumbnail on the design it attached to
 * the schema, or its organization's logo for a schema with no design. Anything
 * unusable (an unsupported format, a malformed URI, a payload or a URL past
 * its cap) comes back undefined and the card falls back to the app's brand
 * mark, which is a worse card but never a wrong one. Every field an issuer
 * controls is bounded, so a credential the holder already accepted is never
 * lost to a value too big to persist.
 */
export function pickLogo(display: CredentialDisplay | undefined): PendingLogo | undefined {
  const uri = display?.logo?.uri?.trim();
  if (!uri) return undefined;
  // Spread rather than assigned, so an issuer that published no alt text does
  // not leave an `alt: undefined` key on the record. An oversize alt costs the
  // label, not the logo — the artwork is the point.
  const trimmedAlt = display?.logo?.alt_text?.trim();
  const alt = trimmedAlt && trimmedAlt.length <= MAX_LOGO_ALT_LENGTH ? { alt: trimmedAlt } : {};

  if (/^https:\/\/\S/i.test(uri)) {
    return uri.length <= MAX_LOGO_URL_LENGTH ? { kind: "url", url: uri, ...alt } : undefined;
  }

  const dataUri = parseBase64DataUri(uri, MAX_LOGO_BASE64_LENGTH);
  if (!dataUri) return undefined;

  const extension = LOGO_EXTENSIONS[dataUri.mediaType.toLowerCase()];
  if (!extension) return undefined;

  return { kind: "data", extension, base64: dataUri.base64, ...alt };
}

/** Narrow to the persisted fields; `logo`/`background_image` are dropped on purpose. */
export function toStoredDisplay(
  display: CredentialDisplay | undefined,
): CredentialDisplayMetadata | undefined {
  if (!display) return undefined;

  const stored: CredentialDisplayMetadata = {};
  if (display.name) stored.name = display.name;
  if (display.locale) stored.locale = display.locale;
  if (display.description) stored.description = display.description;
  if (display.background_color) stored.backgroundColor = display.background_color;
  if (display.text_color) stored.textColor = display.text_color;

  return Object.keys(stored).length > 0 ? stored : undefined;
}

// ─── DCQL matching ────────────────────────────────────

function matchesQueryCredential(
  queryCredential: DCQLQuery["credentials"][number],
  cred: StoredCredential,
): boolean {
  if (queryCredential.format !== cred.format) return false;

  if (cred.format === "mso_mdoc") {
    const doctype = queryCredential.meta?.doctype_value;
    return !doctype || doctype === cred.docType;
  }

  const vctValues = queryCredential.meta?.vct_values ?? [];
  return vctValues.length === 0 || vctValues.includes(cred.credentialType);
}

/**
 * Turn a query's claim paths into refs against a held credential.
 *
 * For mdoc the path is `[namespace, element]`, and `key` has to come out as the
 * credential's own `claimKey` — which `claimKeyFor` leaves unqualified for the
 * credential's own namespace and qualifies for any other. Everything
 * downstream keys off it: `buildApprovalData` matches against
 * `Object.keys(credential.claims)`, and `selectMdocElements` decides what is
 * disclosed.
 *
 * Taking the last path segment instead would be right only for the
 * credential's own namespace. A real mDL pairs `org.iso.18013.5.1` with a
 * domestic one, and then a request for
 * `["org.iso.18013.5.1.aamva", "document_number"]` produces the bare
 * `document_number` — which is not a key `claims` holds, so the claim vanishes
 * from the approval screen and is never disclosed, and which would match the
 * ISO namespace's `document_number` if anything did. That collision is the
 * whole reason element identifiers are namespaced.
 */
function resolveClaimRefs(
  queryCredential: DCQLQuery["credentials"][number],
  cred: StoredCredential,
): ClaimRef[] {
  return (queryCredential.claims ?? []).map((claim) => {
    const element = findElement(cred, claim.path);
    const key = element?.claimKey ?? claim.path[claim.path.length - 1];

    return {
      id: claim.path.join("/"),
      path: claim.path,
      key,
      mandatory: element?.mandatory ?? false,
    };
  });
}

/** The held element a DCQL `[namespace, element_identifier]` path names. */
function findElement(
  cred: StoredCredential,
  path: string[],
): MdocElementMeta | undefined {
  if (cred.format !== "mso_mdoc" || path.length !== 2) return undefined;

  return cred.elements.find(
    (element) => element.namespace === path[0] && element.elementIdentifier === path[1],
  );
}

function claimRefFor(cred: StoredCredential, key: string): ClaimRef {
  const element =
    cred.format === "mso_mdoc" ? cred.elements.find((e) => e.claimKey === key) : undefined;

  return {
    id: element ? `${element.namespace}/${element.elementIdentifier}` : key,
    path: element ? [element.namespace, element.elementIdentifier] : [key],
    key,
    mandatory: element?.mandatory ?? false,
  };
}

function isMandatory(cred: StoredCredential, key: string): boolean {
  if (cred.format !== "mso_mdoc") return false;
  return cred.elements.some((e) => e.claimKey === key && e.mandatory);
}

// ─── OID4VCI Protocol ─────────────────────────────────

export class IssuanceProtocol {
  constructor(
    private api: ApiClient,
    private credentialManager: CredentialManager,
    private signer: HolderSigner,
    private getIdentity: () => {
      did: string;
      passkeyCredentialId: string;
      passkeyPublicKey: Uint8Array;
    },
  ) {}

  /** Check if a QR code contains an OID4VCI credential offer. */
  isCredentialOffer(qrData: string): boolean {
    return qrData.startsWith("openid-credential-offer://");
  }

  /** Parse the credential offer URI. */
  parseCredentialOffer(uri: string): CredentialOffer {
    const url = new URL(uri);
    const offerParam = url.searchParams.get("credential_offer");
    if (offerParam) return JSON.parse(offerParam);

    const offerUri = url.searchParams.get("credential_offer_uri");
    if (offerUri) throw new Error("credential_offer_uri not supported — use inline offer");

    throw new Error("Invalid credential offer URI");
  }

  /** Execute the full OID4VCI issuance flow. */
  async executeIssuance(
    offer: CredentialOffer,
    txCode?: string,
    preferredLocale?: string,
  ): Promise<StoredCredential> {
    const identity = this.getIdentity();

    // 1. Fetch issuer metadata
    const metadata = await this.api.fetchIssuerMetadata(
      offer.credential_issuer,
    );

    // 2. Discover the Authorization Server's token endpoint via AS metadata.
    // Per OID4VCI 1.0, token_endpoint lives on the AS metadata document, not
    // on the issuer document. If authorization_servers is absent, the
    // credential issuer doubles as its own AS.
    const asUrl =
      metadata.authorization_servers?.[0] ?? offer.credential_issuer;
    const asMetadata = await this.api.fetchAuthServerMetadata(asUrl);

    // 3. Exchange pre-authorized code for access token
    const grant =
      offer.grants[
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      ];
    const tokenResponse = await this.api.exchangeToken(
      asMetadata.token_endpoint,
      grant["pre-authorized_code"],
      txCode,
    );

    // 4. Build proof-of-possession JWT
    const proofJwt = await this.buildProofJwt(
      identity,
      offer.credential_issuer,
      tokenResponse.c_nonce,
    );

    // 5. Request credential
    const credConfigId = offer.credential_configuration_ids[0];
    const credential = await this.api.requestCredential(
      metadata.credential_endpoint,
      tokenResponse.access_token,
      { proof_type: "jwt", jwt: proofJwt },
      credConfigId,
    );

    // 6. Extract issuer info from metadata
    const issuerName =
      pickCredentialDisplay(metadata.display, preferredLocale)?.name ??
      offer.credential_issuer;
    const issuerDid = `did:sovra:${new URL(offer.credential_issuer).hostname}`;

    // The metadata was already fetched in step 1, so the format, the card
    // design and the claim labels all come out of a lookup, with no extra
    // round trip.
    const config = metadata.credential_configurations_supported?.[credConfigId];
    const credentialMetadata = credentialMetadataFor(metadata, credConfigId);
    const credentialDisplay = pickCredentialDisplay(
      credentialMetadata?.display,
      preferredLocale,
    );
    const issuerInfo = {
      issuerDid,
      issuerName,
      display: toStoredDisplay(credentialDisplay),
      // The card logo the issuer designed for this credential configuration —
      // the app's own brand mark is only the fallback.
      logo: pickLogo(credentialDisplay),
      claimLabels: pickClaimLabels(credentialMetadata?.claims, preferredLocale),
    };

    // 7. Store it in whichever format the issuer advertised.
    return config?.format === "mso_mdoc"
      ? this.credentialManager.storeMdocCredential(credential, issuerInfo)
      : this.credentialManager.storeCredential(credential, issuerInfo);
  }

  /** Build and sign a proof-of-possession JWT for OID4VCI. */
  private async buildProofJwt(
    identity: {
      did: string;
      passkeyCredentialId: string;
      passkeyPublicKey: Uint8Array;
    },
    audience: string,
    nonce: string,
  ): Promise<string> {
    // Build JWK from public key
    const pubkey = identity.passkeyPublicKey;
    const x = pubkey.length === 65 ? pubkey.slice(1, 33) : pubkey.slice(0, 32);
    const y = pubkey.length === 65 ? pubkey.slice(33, 65) : pubkey.slice(32, 64);

    const header = {
      alg: this.signer.alg,
      typ: "openid4vci-proof+jwt",
      jwk: {
        kty: "EC",
        crv: "P-256",
        x: base64urlEncode(x),
        y: base64urlEncode(y),
      },
    };

    const payload = {
      iss: identity.did,
      aud: audience,
      iat: Math.floor(Date.now() / 1000),
      nonce,
    };

    const headerB64 = base64urlEncode(
      new TextEncoder().encode(JSON.stringify(header)),
    );
    const payloadB64 = base64urlEncode(
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    const signingInput = `${headerB64}.${payloadB64}`;

    // The signer signs sha256(signing_input) and returns the JWT's third
    // segment (a WebAuthn assertion for the Aligned passkey).
    const hash = sha256(new TextEncoder().encode(signingInput));
    const assertion = await this.signer.sign(hash, identity.passkeyCredentialId);
    const sigB64 = toJwtSegment(assertion, base64urlEncode);

    return `${signingInput}.${sigB64}`;
  }
}

// ─── OpenID4VP Protocol ───────────────────────────────

/** OID4VP 1.0 Client Identifier Prefix for a DID-identified verifier. */
const DID_CLIENT_ID_PREFIX = "decentralized_identifier:";

/** RFC 9101 media type, and the `typ` a signed request object must carry. */
const REQUEST_OBJECT_TYP = "oauth-authz-req+jwt";

/**
 * OID4VP 1.0 §5.9: the `aud` of a signed request under static Wallet metadata
 * discovery. This wallet publishes no metadata for a verifier to discover, so
 * every request it accepts is addressed to this fixed value.
 */
const STATIC_WALLET_AUD = "https://self-issued.me/v2";

/** A compact JWS: three base64url segments. JSON can never look like this. */
const JWS_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function decodeJsonSegment(segment: string): Record<string, unknown> {
  return JSON.parse(
    new TextDecoder().decode(base64urlDecode(segment)),
  ) as Record<string, unknown>;
}

export class PresentationProtocol {
  constructor(
    private api: ApiClient,
    private credentialManager: CredentialManager,
    private signer: HolderSigner,
    private getIdentity: () => {
      did: string;
      passkeyCredentialId: string;
      passkeyPublicKey: Uint8Array;
    },
    /**
     * On-chain DID Registry the verifier's `client_id` is resolved against.
     * Without it a signed request cannot be checked at all, so requests that
     * carry a signature are rejected rather than waved through unverified.
     */
    private didRegistryAddress?: string,
  ) {}

  /** Check if a QR code contains an OpenID4VP request. */
  isPresentationRequest(qrData: string): boolean {
    return qrData.startsWith("openid4vp://");
  }

  /**
   * Resolve an OpenID4VP request URI into the request the holder is being
   * asked to answer, authenticating the verifier on the way.
   *
   * Three shapes arrive here:
   *
   *  - `?request=<JWS>` or `?request_uri=<url>` — a signed request object
   *    (JAR, RFC 9101). The signature is verified against a key resolved from
   *    the `client_id`'s own DID document on chain. Everything inside it,
   *    `response_uri` included, is trusted only because of that signature, so
   *    a signature that does not verify is a hard failure: it means someone
   *    built this QR who does not hold the verifier's key.
   *
   *  - `?request=<JSON>` or a flat query — unsigned, as the standalone
   *    verifier app still emits. Accepted only in the shape that app uses: a
   *    bare `did:sovra` client_id, and no `direct_post`. `verified` is false
   *    and any `client_metadata.client_name` is discarded — an unsigned
   *    request is in no position to tell the citizen who is asking — and it
   *    is answered by QR, never by posting the vp_token anywhere.
   */
  async resolveRequest(uri: string): Promise<VPRequest> {
    const params = new URL(uri).searchParams;
    const requestObject = await this.fetchRequestObject(params);

    return requestObject
      ? this.fromSignedRequest(requestObject, params.get("client_id"))
      : this.fromUnsignedRequest(params);
  }

  /** The signed request object, by value or by reference; null when unsigned. */
  private async fetchRequestObject(
    params: URLSearchParams,
  ): Promise<string | null> {
    const inline = params.get("request");
    if (inline) return JWS_SHAPE.test(inline) ? inline : null;

    const requestUri = params.get("request_uri");
    if (!requestUri) return null;

    const fetched = (await this.api.fetchRequestObject(requestUri)).trim();
    if (!JWS_SHAPE.test(fetched)) {
      throw new Error("request_uri did not return a signed request object");
    }
    return fetched;
  }

  private async fromSignedRequest(
    jws: string,
    clientIdFromQuery: string | null,
  ): Promise<VPRequest> {
    const [headerB64, payloadB64, signatureB64] = jws.split(".");
    const header = decodeJsonSegment(headerB64);
    const fields = decodeJsonSegment(payloadB64);

    if (header.typ !== REQUEST_OBJECT_TYP) {
      throw new Error(`Request object is not a ${REQUEST_OBJECT_TYP}`);
    }
    if (header.alg !== "ES256") {
      throw new Error(`Unsupported request object algorithm: ${header.alg}`);
    }
    if (fields.aud !== STATIC_WALLET_AUD) {
      throw new Error("Request object is not addressed to this wallet");
    }

    const clientId = fields.client_id;
    if (typeof clientId !== "string" || !clientId) {
      throw new Error("Request object has no client_id");
    }
    // OID4VP 1.0: client_id travels both as a query parameter and inside the
    // request object, and the two must agree — otherwise the QR could show one
    // verifier while the signature covers another. Absent is not agreement:
    // the parameter is mandatory.
    if (clientIdFromQuery !== clientId) {
      throw new Error("client_id does not match the signed request object");
    }

    if (!this.didRegistryAddress) {
      throw new Error(
        "Cannot verify a signed request: no DID Registry configured",
      );
    }
    if (!clientId.startsWith(DID_CLIENT_ID_PREFIX)) {
      throw new Error(`Unsupported client_id prefix: ${clientId}`);
    }
    const did = clientId.slice(DID_CLIENT_ID_PREFIX.length);

    // The signing key must be a verification method of the client_id's own
    // DID, named by `kid`. A kid pointing anywhere else would let a request
    // be signed by a key the claimed verifier does not control.
    const kid = typeof header.kid === "string" ? header.kid : "";
    const { did: kidDid, fragment } = parseDidUrl(kid);
    if (kidDid !== did || !fragment) {
      throw new Error(`Request object kid is not a key of ${did}`);
    }

    const key = await resolveAssertionKey(
      (to, calldata) => this.api.ethCall(to, calldata),
      this.didRegistryAddress,
      did,
      fragment,
    );

    const signed = p256Verify(
      sha256(new TextEncoder().encode(`${headerB64}.${payloadB64}`)),
      base64urlDecode(signatureB64),
      key.x,
      key.y,
    );
    if (!signed) {
      throw new Error("Request object signature does not verify");
    }

    // A missing or non-numeric `exp` is not "never expires": without one the
    // QR is replayable for as long as the photograph of it survives.
    if (typeof fields.exp !== "number" || fields.exp * 1000 <= Date.now()) {
      throw new Error("Request object has expired or carries no expiry");
    }

    // JSON off the wire: a signature proves who wrote `client_metadata`, not
    // that `client_name` is a string. The consent screen renders it into a
    // React Native <Text>, which throws on anything else — after the signature
    // has already verified.
    const clientMetadata = fields.client_metadata as
      | Record<string, unknown>
      | undefined;
    const clientName = clientMetadata?.client_name;

    return {
      ...this.commonFields(fields),
      clientId,
      verifierName: typeof clientName === "string" ? clientName : undefined,
      verified: true,
    };
  }

  private fromUnsignedRequest(params: URLSearchParams): VPRequest {
    const inline = params.get("request");

    const fields: Record<string, unknown> = inline
      ? (JSON.parse(inline) as Record<string, unknown>)
      : Object.fromEntries(params.entries());

    const clientId = fields.client_id;
    if (typeof clientId !== "string" || !clientId) {
      throw new Error("Missing required OpenID4VP parameters");
    }

    // A `decentralized_identifier:` client_id names a DID the wallet can
    // resolve a key for — that is the entire point of the prefix. Taking one
    // unsigned lets an attacker copy a real verifier's client_id off its QR,
    // drop the `request` parameter, and inherit the identity without the
    // proof. The standalone verifier app carries a bare `did:sovra:0x…`, so
    // this bars the downgrade, not that app.
    if (clientId.startsWith(DID_CLIENT_ID_PREFIX)) {
      throw new Error(
        `A ${DID_CLIENT_ID_PREFIX} client_id must arrive in a signed request object`,
      );
    }

    // No `verifierName`: the name in an unsigned request is exactly the field
    // an impersonator sets, so it never reaches the consent screen.
    const request = { ...this.commonFields(fields), clientId, verified: false };

    // `direct_post` mails the disclosed claims to an address the QR chose, and
    // only a signature binds that address to the verifier. Unsigned it is
    // refused outright: no Sovra verifier asks for it — the standalone app
    // omits `response_uri`/`response_mode` and is answered by QR instead.
    if (request.responseMode === "direct_post" || request.responseUri) {
      throw new Error(
        "An unsigned request cannot use direct_post: nothing binds its response_uri to the verifier",
      );
    }

    return request;
  }

  private commonFields(
    fields: Record<string, unknown>,
  ): Omit<VPRequest, "clientId" | "verified"> {
    const dcqlRaw = fields.dcql_query;
    const dcqlQuery =
      typeof dcqlRaw === "string"
        ? (JSON.parse(dcqlRaw) as DCQLQuery)
        : (dcqlRaw as DCQLQuery);

    if (!fields.nonce || !dcqlQuery) {
      throw new Error("Missing required OpenID4VP parameters");
    }

    return {
      nonce: fields.nonce as string,
      dcqlQuery,
      state: (fields.state as string) ?? undefined,
      responseUri: (fields.response_uri as string) ?? undefined,
      responseMode: (fields.response_mode as string) ?? undefined,
    };
  }

  /**
   * Every credential the query accepts, in wallet order — the holder picks.
   *
   * Matching is on format *and* type. The format check is not cosmetic: without
   * it an mdoc would satisfy a `vc+sd-jwt` query and the presentation would
   * fail much later, in signature verification, with nothing pointing back
   * here. And an empty type list is no longer a wildcard — it used to mean
   * "match anything", so a malformed query silently offered up the first
   * credential in the wallet.
   */
  findMatchingCredentials(
    query: DCQLQuery,
    credentials: StoredCredential[],
  ): { credentials: StoredCredential[]; requestedClaims: ClaimRef[] } | null {
    for (const queryCredential of query.credentials) {
      const matches = credentials.filter((cred) =>
        matchesQueryCredential(queryCredential, cred),
      );
      if (matches.length > 0) {
        return {
          credentials: matches,
          // Resolved against the first match; `buildApprovalData` re-derives
          // the per-credential parts when the holder switches.
          requestedClaims: resolveClaimRefs(queryCredential, matches[0]),
        };
      }
    }
    return null;
  }

  /** First match only, for callers that cannot offer a choice. */
  findMatchingCredential(
    query: DCQLQuery,
    credentials: StoredCredential[],
  ): { credential: StoredCredential; requestedClaims: ClaimRef[] } | null {
    const match = this.findMatchingCredentials(query, credentials);
    if (!match) return null;
    return { credential: match.credentials[0], requestedClaims: match.requestedClaims };
  }

  /** Build data for the approval screen. */
  buildApprovalData(
    request: VPRequest,
    credential: StoredCredential,
    requestedClaims: ClaimRef[],
    matches: StoredCredential[] = [credential],
  ): ApprovalData {
    // An mdoc namespace holds only real data elements — no JWT envelope — so
    // the filter would only ever hide something the operator meant to show.
    const allClaims =
      credential.format === "mso_mdoc"
        ? Object.keys(credential.claims)
        : Object.keys(credential.claims).filter((k) => !isEnvelopeClaim(k));

    const requestedKeys = new Set(requestedClaims.map((c) => c.key));

    // An attached document is never presented — `selectDisclosures` cannot
    // reach it — so a request naming it must not show the holder a toggle for
    // something that will not be sent. It is listed with what stays behind.
    const presentable = allClaims.filter(
      (k) => !isAttachmentDescriptor(credential.claims[k]),
    );

    // `clientId` may stand in for a missing `client_name` only once a
    // signature has bound it to a DID; unsigned, it is whatever the QR said.
    return {
      verifierName: request.verified
        ? (request.verifierName ?? request.clientId)
        : undefined,
      verified: request.verified,
      credentialType: credential.credentialType,
      format: credential.format,
      // `mandatory` belongs to the credential, not the request, so it is
      // re-derived here: the holder may have switched to another card.
      sharedClaims: requestedClaims
        .filter((c) => presentable.includes(c.key))
        .map((c) => ({ ...c, mandatory: isMandatory(credential, c.key) })),
      withheldClaims: allClaims
        .filter((key) => !requestedKeys.has(key) || !presentable.includes(key))
        .map((key) => claimRefFor(credential, key)),
      credential,
      requestedClaims,
      matches,
    };
  }

  /**
   * POST a vp_token to the verifier's response_uri using the OID4VP
   * `direct_post` response mode, and return the verdict it answers with.
   * Throws if the request lacks the required `responseUri` / `state` fields.
   *
   * Per OID4VP, a DCQL request expects the vp_token keyed by the query's
   * credential ids, not the bare presentation. The envelope is added here
   * rather than in `executePresentation` because the QR path (`/response-qr`,
   * read by the standalone verifier app) needs the bare form.
   */
  async executeDirectPost(
    request: VPRequest,
    vpToken: string,
  ): Promise<PresentationOutcome> {
    // `resolveRequest` already refuses an unsigned direct_post, but holder-core
    // is a package: the invariant has to hold at its own boundary too.
    if (!request.verified) {
      throw new Error(
        "direct_post requires a request object whose signature verified",
      );
    }
    if (!request.responseUri || !request.state) {
      throw new Error(
        "direct_post requires response_uri and state in the request",
      );
    }
    const credentialId = request.dcqlQuery.credentials[0]?.id;
    if (!credentialId) {
      throw new Error("direct_post requires a DCQL credential id to key the vp_token");
    }
    const body = await this.api.directPost(
      request.responseUri,
      JSON.stringify({ [credentialId]: vpToken }),
      request.state,
    );
    return parsePresentationOutcome(body);
  }

  /** Execute the full OpenID4VP presentation flow and return the VP token. */
  async executePresentation(
    request: VPRequest,
    credential: StoredCredential,
    approvedClaims: string[],
  ): Promise<string> {
    return credential.format === "mso_mdoc"
      ? this.executeMdocPresentation(request, credential, approvedClaims)
      : this.executeSdJwtPresentation(request, credential, approvedClaims);
  }

  /**
   * Build an mdoc `DeviceResponse`.
   *
   * mdoc is `direct_post` only. The session transcript hashes the
   * `response_uri`, and the QR path deliberately omits one so the two devices
   * need no network path to each other — there is nothing to hash, and
   * substituting an empty string would be inventing a private protocol that
   * only our own verifier could follow.
   */
  private async executeMdocPresentation(
    request: VPRequest,
    credential: StoredMdocCredential,
    approvedClaims: string[],
  ): Promise<string> {
    if (!request.responseUri) {
      throw new Error(
        "This verifier can't accept mDoc credentials — it did not provide a response address.",
      );
    }

    const identity = this.getIdentity();
    const parsed = parseIssuerSigned(credential.issuerSigned);

    // Mandatory elements are unioned in by the manager, not by the caller.
    const selected = this.credentialManager.selectMdocElements(credential, approvedClaims);
    const selectedKeys = new Set(selected.map((e) => `${e.namespace}/${e.elementIdentifier}`));

    const disclosed = parsed.items.filter(
      (item) =>
        // The Sovra metadata is not the holder's to withhold. The verifier
        // requires it whole — it carries the holder DID, the revocation index
        // and the mandatory-element set — and it holds no user data to choose
        // about. It is deliberately absent from `credential.elements`, which
        // exists to describe what a holder can decide on, so it has to be
        // added back here rather than selected.
        item.namespace === SOVRA_META_NAMESPACE ||
        selectedKeys.has(`${item.namespace}/${item.elementIdentifier}`),
    );

    return buildDeviceResponse({
      parsed,
      disclosed,
      handover: {
        clientId: request.clientId,
        nonce: request.nonce,
        responseUri: request.responseUri,
      },
      signer: holderSignerToDeviceSigner(
        this.signer,
        identity.passkeyCredentialId,
        sha256,
      ),
    });
  }

  private async executeSdJwtPresentation(
    request: VPRequest,
    credential: StoredSdJwtCredential,
    approvedClaims: string[],
  ): Promise<string> {
    const identity = this.getIdentity();

    // 1. Select disclosures for approved claims
    const selectedDisclosures = this.credentialManager.selectDisclosures(
      credential,
      approvedClaims,
    );

    // 2. Compute sd_hash
    const issuerJwt = credential.sdJwt.split("~")[0];
    const sdHash = this.credentialManager.computeSdHash(
      issuerJwt,
      selectedDisclosures,
    );

    // 3. Build KB-JWT
    const kbJwt = await this.buildKBJwt(
      identity,
      request.nonce,
      request.clientId,
      sdHash,
    );

    // 4. Assemble final SD-JWT presentation
    return this.credentialManager.buildPresentationSDJwt(
      credential,
      selectedDisclosures,
      kbJwt,
    );
  }

  /** Build and dual-sign a Key Binding JWT. */
  private async buildKBJwt(
    identity: {
      did: string;
      passkeyCredentialId: string;
      passkeyPublicKey: Uint8Array;
    },
    nonce: string,
    audience: string,
    sdHash: Uint8Array,
  ): Promise<string> {
    // Embed the holder's public key in the header so the verifier can
    // recover it without resolving a DID document.
    const pubkey = identity.passkeyPublicKey;
    const x = pubkey.length === 65 ? pubkey.slice(1, 33) : pubkey.slice(0, 32);
    const y = pubkey.length === 65 ? pubkey.slice(33, 65) : pubkey.slice(32, 64);

    const header = {
      alg: this.signer.alg,
      typ: "kb+jwt",
      jwk: {
        kty: "EC",
        crv: "P-256",
        x: base64urlEncode(x),
        y: base64urlEncode(y),
      },
    };
    const payload = {
      iss: identity.did,
      iat: Math.floor(Date.now() / 1000),
      nonce,
      aud: audience,
      sd_hash: base64urlEncode(sdHash),
    };

    const headerB64 = base64urlEncode(
      new TextEncoder().encode(JSON.stringify(header)),
    );
    const payloadB64 = base64urlEncode(
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    const signingInput = `${headerB64}.${payloadB64}`;

    // The signer signs sha256(signing_input) (its WebAuthn challenge) and
    // returns the JWT's third segment.
    const hash = sha256(new TextEncoder().encode(signingInput));
    const assertion = await this.signer.sign(hash, identity.passkeyCredentialId);
    const sigB64 = toJwtSegment(assertion, base64urlEncode);

    return `${signingInput}.${sigB64}`;
  }
}
