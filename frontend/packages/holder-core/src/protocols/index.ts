import type {
  ApiClient,
  IssuerMetadata,
  CredentialMetadata,
  CredentialDisplay,
  ClaimDescription,
} from "../api/index.js";
import type { CredentialManager } from "../credentials/index.js";
import type { StoredCredential, CredentialDisplayMetadata } from "../state/index.js";
import {
  base64urlDecode,
  base64urlEncode,
  p256Verify,
  sha256,
} from "../utils/index.js";
import { parseDidUrl, resolveAssertionKey } from "../did/index.js";

// ─── Holder signing seam ──────────────────────────────

/**
 * Signs the holder proofs (OID4VCI proof-of-possession + OID4VP KB-JWT).
 * The concrete implementation lives in the app — e.g. an Aligned-passkey
 * signer — so holder-core stays agnostic of the wallet SDK.
 */
export interface HolderSigner {
  /** The JWT `alg` header value this signer produces (e.g. "WebAuthn"). */
  readonly alg: string;
  /**
   * Sign `hash` (the 32-byte SHA-256 of the JWT signing input) with the
   * holder's key `credentialId`, returning the JWT's third (signature)
   * segment, base64url-encoded. For WebAuthn that segment is
   * `base64url(JSON{r,s,challenge_index,type_index,authenticator_data,client_data_json})`.
   */
  signToSegment(hash: Uint8Array, credentialId: string): Promise<string>;
}

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
    meta?: { vct_values?: string[] };
    claims?: Array<{ path: string[]; id?: string }>;
  }>;
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
  sharedClaims: string[];
  withheldClaims: string[];
  credential: StoredCredential;
  /** What the verifier asked for; re-derive against it when the holder switches. */
  requestedClaims: string[];
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
    const sdJwtString = await this.api.requestCredential(
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

    const credentialMetadata = credentialMetadataFor(metadata, credConfigId);
    const display = toStoredDisplay(
      pickCredentialDisplay(credentialMetadata?.display, preferredLocale),
    );
    const claimLabels = pickClaimLabels(credentialMetadata?.claims, preferredLocale);

    // 7. Store credential
    return this.credentialManager.storeCredential(sdJwtString, {
      issuerDid,
      issuerName,
      display,
      claimLabels,
    });
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
    const sigB64 = await this.signer.signToSegment(
      hash,
      identity.passkeyCredentialId,
    );

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

  /** Every credential the query accepts, in wallet order — the holder picks. */
  findMatchingCredentials(
    query: DCQLQuery,
    credentials: StoredCredential[],
  ): { credentials: StoredCredential[]; requestedClaims: string[] } | null {
    for (const queryCredential of query.credentials) {
      const vctValues = queryCredential.meta?.vct_values ?? [];
      const requestedClaims =
        queryCredential.claims?.map((c) => c.path[c.path.length - 1]) ?? [];

      const matches = credentials.filter(
        (cred) =>
          vctValues.length === 0 || vctValues.includes(cred.credentialType),
      );
      if (matches.length > 0) {
        return { credentials: matches, requestedClaims };
      }
    }
    return null;
  }

  /** First match only, for callers that cannot offer a choice. */
  findMatchingCredential(
    query: DCQLQuery,
    credentials: StoredCredential[],
  ): { credential: StoredCredential; requestedClaims: string[] } | null {
    const match = this.findMatchingCredentials(query, credentials);
    if (!match) return null;
    return { credential: match.credentials[0], requestedClaims: match.requestedClaims };
  }

  /** Build data for the approval screen. */
  buildApprovalData(
    request: VPRequest,
    credential: StoredCredential,
    requestedClaims: string[],
    matches: StoredCredential[] = [credential],
  ): ApprovalData {
    const allClaims = Object.keys(credential.claims).filter(
      (k) => !k.startsWith("_") && k !== "iss" && k !== "sub" && k !== "iat" && k !== "exp" && k !== "vct" && k !== "cnf" && k !== "credentialStatus",
    );

    // `clientId` may stand in for a missing `client_name` only once a
    // signature has bound it to a DID; unsigned, it is whatever the QR said.
    return {
      verifierName: request.verified
        ? (request.verifierName ?? request.clientId)
        : undefined,
      verified: request.verified,
      credentialType: credential.credentialType,
      sharedClaims: requestedClaims.filter((c) => allClaims.includes(c)),
      withheldClaims: allClaims.filter((c) => !requestedClaims.includes(c)),
      credential,
      requestedClaims,
      matches,
    };
  }

  /**
   * POST a vp_token to the verifier's response_uri using the OID4VP
   * `direct_post` response mode. Throws if the request lacks the
   * required `responseUri` / `state` fields.
   *
   * Per OID4VP, a DCQL request expects the vp_token keyed by the query's
   * credential ids, not the bare presentation. The envelope is added here
   * rather than in `executePresentation` because the QR path (`/response-qr`,
   * read by the standalone verifier app) needs the bare form.
   */
  async executeDirectPost(request: VPRequest, vpToken: string): Promise<void> {
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
    await this.api.directPost(
      request.responseUri,
      JSON.stringify({ [credentialId]: vpToken }),
      request.state,
    );
  }

  /** Execute the full OpenID4VP presentation flow and return the VP token. */
  async executePresentation(
    request: VPRequest,
    credential: StoredCredential,
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
    const sigB64 = await this.signer.signToSegment(
      hash,
      identity.passkeyCredentialId,
    );

    return `${signingInput}.${sigB64}`;
  }
}
