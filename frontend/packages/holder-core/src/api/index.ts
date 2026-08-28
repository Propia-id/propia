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

export interface ApiClientConfig {
  l2RpcUrl: string;
}

export class ApiClient {
  private l2: AxiosInstance;

  constructor(config: ApiClientConfig) {
    this.l2 = axios.create({ baseURL: config.l2RpcUrl });
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
   * Submit a holder-signed vp_token to the verifier's response_uri (the
   * direct_post target carried in the OID4VP authorization request).
   */
  async directPost(
    responseUri: string,
    vpToken: string,
    state: string,
  ): Promise<void> {
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
