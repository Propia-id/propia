import axios, { type AxiosInstance } from "axios";

// ─── Types ────────────────────────────────────────────

export interface TokenResponse {
  access_token: string;
  c_nonce: string;
  expires_in: number;
}

export interface DisplayImage {
  uri: string;
  alt_text?: string;
}

/** One `display` entry (OID4VCI 1.0 §11.2.3). Issuers may publish one per locale. */
export interface CredentialDisplay {
  name: string;
  locale?: string;
  description?: string;
  logo?: DisplayImage;
  background_color?: string;
  text_color?: string;
  background_image?: DisplayImage;
}

/** One `display` entry for a single claim (OID4VCI 1.0 Appendix B.2). */
export interface ClaimDisplay {
  name: string;
  locale?: string;
}

/**
 * A claims description object (OID4VCI 1.0 Appendix B.2). `path` is a claims
 * path pointer: a segment per level, so a Sovra credential's flat claims are
 * always a single-element path.
 */
export interface ClaimDescription {
  path: (string | number | null)[];
  mandatory?: boolean;
  display?: ClaimDisplay[];
}

/**
 * A configuration's presentation data (OID4VCI 1.0 §12.2.4). Draft 13 had
 * `display` at the top of the configuration object and `claims` as an object
 * keyed by claim name; 1.0 nests both here and makes `claims` an array keyed
 * by `path`. Only the 1.0 position is read.
 */
export interface CredentialMetadata {
  display?: CredentialDisplay[];
  claims?: ClaimDescription[];
}

export interface IssuerMetadata {
  credential_issuer: string;
  credential_endpoint: string;
  authorization_servers?: string[];
  credential_configurations_supported: Record<
    string,
    {
      format: string;
      credential_definition: {
        type: string[];
      };
      credential_metadata?: CredentialMetadata;
    }
  >;
  display?: CredentialDisplay[];
}

export interface AuthServerMetadata {
  issuer: string;
  token_endpoint: string;
  grant_types_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
}

export interface JsonRpcResponse<T = unknown> {
  jsonrpc: string;
  id: number;
  result?: T;
  error?: { code: number; message: string };
}

// ─── API Client ───────────────────────────────────────

const REQUEST_OBJECT_TIMEOUT_MS = 10_000;
const REQUEST_OBJECT_MAX_BYTES = 128 * 1024;

/** Built by hand: React Native's `URL` does not implement `origin`. */
function originOf(url: URL): string {
  return `${url.protocol}//${url.host}`;
}

export interface ApiClientConfig {
  l2RpcUrl: string;
  /** The wallet's own backend: the one origin allowed to serve http. */
  apiBase?: string;
}

export class ApiClient {
  private l2: AxiosInstance;
  private apiOrigin?: string;

  constructor(config: ApiClientConfig) {
    this.l2 = axios.create({ baseURL: config.l2RpcUrl });
    if (config.apiBase) this.apiOrigin = originOf(new URL(config.apiBase));
  }

  // ─── OID4VCI ──────────────────────────────────────

  async fetchIssuerMetadata(issuerUrl: string): Promise<IssuerMetadata> {
    const { data } = await axios.get<IssuerMetadata>(
      `${issuerUrl}/.well-known/openid-credential-issuer`,
    );
    return data;
  }

  // OID4VCI 1.0 §11.2.3 path-concatenation form. The Credential Issuer is
  // required to also serve the RFC 8414 insertion form, but the wallet picks
  // one — concat keeps the URL rooted at the AS identifier and matches how
  // we discover issuer metadata.
  async fetchAuthServerMetadata(asUrl: string): Promise<AuthServerMetadata> {
    const { data } = await axios.get<AuthServerMetadata>(
      `${asUrl}/.well-known/oauth-authorization-server`,
    );
    return data;
  }

  async exchangeToken(
    tokenEndpoint: string,
    preAuthorizedCode: string,
    txCode?: string,
  ): Promise<TokenResponse> {
    const body: Record<string, string> = {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuthorizedCode,
    };
    if (txCode) body.tx_code = txCode;
    const { data } = await axios.post<TokenResponse>(tokenEndpoint, body);
    return data;
  }

  async requestCredential(
    credentialEndpoint: string,
    accessToken: string,
    proof: { proof_type: string; jwt: string },
    credentialConfigurationId: string,
  ): Promise<string> {
    const { data } = await axios.post(
      credentialEndpoint,
      {
        credential_configuration_id: credentialConfigurationId,
        proof,
      },
      { headers: { Authorization: `Bearer ${accessToken}` } },
    );
    return data.credential;
  }

  // ─── OID4VP ───────────────────────────────────────

  /**
   * Fetch a pass-by-reference authorization request object. Returned as the
   * raw compact JWS: nothing in it can be acted on before its signature has
   * been verified, so it is deliberately not parsed here.
   */
  async fetchRequestObject(requestUri: string): Promise<string> {
    this.assertSafeOrigin(requestUri, "fetch a request object from");

    const { data } = await axios.get<string>(requestUri, {
      responseType: "text",
      transformResponse: [(body) => body as string],
      headers: { Accept: "application/oauth-authz-req+jwt" },
      timeout: REQUEST_OBJECT_TIMEOUT_MS,
      maxContentLength: REQUEST_OBJECT_MAX_BYTES,
    });

    if (data.length > REQUEST_OBJECT_MAX_BYTES) {
      throw new Error("Request object is too large");
    }
    return data;
  }

  /**
   * The QR picks both the `request_uri` and the `response_uri`, so https only
   * — bar our own backend, which is http in dev. Applied to the inbound
   * request-object fetch *and* to the outbound vp_token submission: the second
   * is the one carrying the citizen's claims.
   *
   * This bounds the transport, not the recipient: any https host passes. What
   * binds a `response_uri` to the verifier that asked is the signature over the
   * request object — which is why an unsigned request may not use direct_post
   * at all, see `PresentationProtocol.fromUnsignedRequest`.
   */
  private assertSafeOrigin(raw: string, action: string): void {
    const url = new URL(raw);
    if (url.protocol === "https:") return;
    if (this.apiOrigin && originOf(url) === this.apiOrigin) return;
    throw new Error(`Refusing to ${action} ${originOf(url)}`);
  }

  /**
   * Submit a holder-signed vp_token to the verifier's response_uri (the
   * direct_post target carried in the OID4VP authorization request).
   */
  async directPost(
    responseUri: string,
    vpToken: string,
    state: string,
  ): Promise<void> {
    this.assertSafeOrigin(responseUri, "submit a credential to");
    await axios.post(responseUri, { vp_token: vpToken, state });
  }

  // ─── L2 JSON-RPC ─────────────────────────────────

  private rpcId = 1;

  async sendTransaction(
    signedTx: Record<string, unknown>,
  ): Promise<string> {
    const { data } = await this.l2.post<JsonRpcResponse<string>>("", {
      jsonrpc: "2.0",
      method: "ethrex_sendTransaction",
      params: [signedTx],
      id: this.rpcId++,
    });
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    return data.result!;
  }

  async ethCall(to: string, calldata: string): Promise<string> {
    const { data } = await this.l2.post<JsonRpcResponse<string>>("", {
      jsonrpc: "2.0",
      method: "eth_call",
      params: [{ to, data: calldata }, "latest"],
      id: this.rpcId++,
    });
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    return data.result!;
  }

  async getTransactionReceipt(
    txHash: string,
  ): Promise<Record<string, unknown> | null> {
    const { data } = await this.l2.post<
      JsonRpcResponse<Record<string, unknown> | null>
    >("", {
      jsonrpc: "2.0",
      method: "eth_getTransactionReceipt",
      params: [txHash],
      id: this.rpcId++,
    });
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    return data.result ?? null;
  }

}
