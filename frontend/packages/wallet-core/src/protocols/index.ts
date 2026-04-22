import type { ApiClient, IssuerMetadata } from "../api/index";
import type { CredentialManager } from "../credentials/index";
import type { PasskeyProvider } from "../platform/index";
import type { StoredCredential } from "../state/index";
import {
  base64urlEncode,
  sha256,
} from "../utils/index";

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
  verifierName?: string;
}

export interface ApprovalData {
  verifierName: string;
  credentialType: string;
  sharedClaims: string[];
  withheldClaims: string[];
  credential: StoredCredential;
}

// ─── OID4VCI Protocol ─────────────────────────────────

export class IssuanceProtocol {
  constructor(
    private api: ApiClient,
    private credentialManager: CredentialManager,
    private passkeyProvider: PasskeyProvider,
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
  ): Promise<StoredCredential> {
    const identity = this.getIdentity();

    // 1. Fetch issuer metadata
    const metadata = await this.api.fetchIssuerMetadata(
      offer.credential_issuer,
    );

    // 2. Exchange pre-authorized code for access token
    const grant =
      offer.grants[
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      ];
    const tokenResponse = await this.api.exchangeToken(
      metadata.token_endpoint ?? `${offer.credential_issuer}/api/v1/issuer/token`,
      grant["pre-authorized_code"],
      txCode,
    );

    // 3. Build proof-of-possession JWT
    const proofJwt = await this.buildProofJwt(
      identity,
      offer.credential_issuer,
      tokenResponse.c_nonce,
    );

    // 4. Request credential
    const credConfigId = offer.credential_configuration_ids[0];
    const sdJwtString = await this.api.requestCredential(
      metadata.credential_endpoint ?? `${offer.credential_issuer}/api/v1/issuer/credential`,
      tokenResponse.access_token,
      { proof_type: "jwt", jwt: proofJwt },
      credConfigId,
    );

    // 5. Extract issuer info from metadata
    const issuerName =
      metadata.display?.[0]?.name ?? offer.credential_issuer;
    const issuerDid = `did:sovra:${new URL(offer.credential_issuer).hostname}`;

    // 6. Store credential
    return this.credentialManager.storeCredential(sdJwtString, {
      issuerDid,
      issuerName,
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
      alg: "ES256",
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

    // Hash the signing input (JWT uses SHA-256 for ES256)
    const hash = sha256(new TextEncoder().encode(signingInput));

    // Sign with passkey
    const passkeySig = await this.passkeyProvider.sign(
      identity.passkeyCredentialId,
      hash,
    );

    // Passkey-only 64-byte signature
    const sigB64 = base64urlEncode(passkeySig.signature);

    return `${signingInput}.${sigB64}`;
  }
}

// ─── OpenID4VP Protocol ───────────────────────────────

export class PresentationProtocol {
  constructor(
    private api: ApiClient,
    private credentialManager: CredentialManager,
    private passkeyProvider: PasskeyProvider,
    private getIdentity: () => {
      did: string;
      passkeyCredentialId: string;
    },
  ) {}

  /** Check if a QR code contains an OpenID4VP request. */
  isPresentationRequest(qrData: string): boolean {
    return qrData.startsWith("openid4vp://");
  }

  /** Parse an inline OpenID4VP request from a QR URI. */
  parseRequest(uri: string): VPRequest {
    const url = new URL(uri);
    const requestParam = url.searchParams.get("request");
    if (!requestParam) {
      throw new Error("Missing 'request' parameter in OpenID4VP URI");
    }

    const payload = JSON.parse(requestParam) as Record<string, unknown>;
    return {
      clientId: payload.client_id as string,
      nonce: payload.nonce as string,
      dcqlQuery: payload.dcql_query as DCQLQuery,
      verifierName: (payload.client_metadata as Record<string, string>)?.client_name,
    };
  }

  /** Find a matching credential for the verifier's DCQL query. */
  findMatchingCredential(
    query: DCQLQuery,
    credentials: StoredCredential[],
  ): { credential: StoredCredential; requestedClaims: string[] } | null {
    for (const queryCredential of query.credentials) {
      const vctValues = queryCredential.meta?.vct_values ?? [];
      const requestedClaims =
        queryCredential.claims?.map((c) => c.path[c.path.length - 1]) ?? [];

      for (const cred of credentials) {
        const matches =
          vctValues.length === 0 || vctValues.includes(cred.credentialType);
        if (matches) {
          return { credential: cred, requestedClaims };
        }
      }
    }
    return null;
  }

  /** Build data for the approval screen. */
  buildApprovalData(
    request: VPRequest,
    credential: StoredCredential,
    requestedClaims: string[],
  ): ApprovalData {
    const allClaims = Object.keys(credential.claims).filter(
      (k) => !k.startsWith("_") && k !== "iss" && k !== "sub" && k !== "iat" && k !== "exp" && k !== "vct" && k !== "cnf" && k !== "credentialStatus",
    );

    return {
      verifierName: request.verifierName ?? request.clientId,
      credentialType: credential.credentialType,
      sharedClaims: requestedClaims.filter((c) => allClaims.includes(c)),
      withheldClaims: allClaims.filter((c) => !requestedClaims.includes(c)),
      credential,
    };
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
    identity: { did: string; passkeyCredentialId: string },
    nonce: string,
    audience: string,
    sdHash: Uint8Array,
  ): Promise<string> {
    const header = { alg: "ES256", typ: "kb+jwt" };
    const payload = {
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

    // Hash the signing input
    const hash = sha256(new TextEncoder().encode(signingInput));

    // Sign with passkey (biometric prompt)
    const passkeySig = await this.passkeyProvider.sign(
      identity.passkeyCredentialId,
      hash,
    );

    // Passkey-only 64-byte signature
    const sigB64 = base64urlEncode(passkeySig.signature);

    return `${signingInput}.${sigB64}`;
  }
}
