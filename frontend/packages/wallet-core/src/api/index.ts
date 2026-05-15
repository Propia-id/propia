import axios, { type AxiosInstance, type AxiosRequestConfig } from "axios";
import { bytesToHex } from "../utils/index";

// ─── Types ────────────────────────────────────────────

export interface OnboardResponse {
  recoveryPublicKey?: { x: string; y: string };
  sovraAddress?: string;
  sessionToken: string;
}

export interface SignResponse {
  signature: { r: string; s: string };
}

export interface RecoverySignatureResponse {
  signature: { r: string; s: string };
  messageHash: string;
}

export interface RotateRecoveryKeyResponse {
  newRecoveryPublicKey: { x: string; y: string };
  rotationSignature: { r: string; s: string };
}

export interface AuthResponse {
  sessionToken: string;
  expiresAt: number;
}

export interface TokenResponse {
  access_token: string;
  c_nonce: string;
  expires_in: number;
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
        credentialSubject?: Record<string, unknown>;
      };
      display?: Array<{ name: string; locale?: string }>;
    }
  >;
  display?: Array<{ name: string; locale?: string }>;
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
  backendUrl: string;
  l2RpcUrl: string;
}

export class ApiClient {
  private backend: AxiosInstance;
  private l2: AxiosInstance;
  private sessionToken: string | null = null;
  private onSessionExpired?: () => Promise<void>;

  constructor(config: ApiClientConfig) {
    this.backend = axios.create({ baseURL: config.backendUrl });
    this.l2 = axios.create({ baseURL: config.l2RpcUrl });

    // Attach session token to authenticated requests
    this.backend.interceptors.request.use((req) => {
      if (this.sessionToken && (req.url?.startsWith("/wallet/auth/") || req.url?.startsWith("/wallet/recovery/"))) {
        req.headers.Authorization = `Bearer ${this.sessionToken}`;
      }
      return req;
    });

    // Handle 401 (expired) and 403 session_not_fresh (step-up auth) responses
    this.backend.interceptors.response.use(undefined, async (error) => {
      const config = error.config as AxiosRequestConfig & { _retried?: boolean };
      const status = error.response?.status;
      const needsRefresh =
        status === 401 || (status === 403 && error.response?.data?.error === "session_not_fresh");

      if (needsRefresh && this.onSessionExpired && !config._retried) {
        config._retried = true;
        await this.onSessionExpired();
        return this.backend.request(config);
      }
      throw error;
    });
  }

  setSessionToken(token: string | null): void {
    this.sessionToken = token;
  }

  setOnSessionExpired(handler: () => Promise<void>): void {
    this.onSessionExpired = handler;
  }

  // ─── Holder Onboarding & Auth ───────────────────────

  async holderOnboard(sovraAddress: string, oauthToken: string): Promise<OnboardResponse> {
    const { data } = await this.backend.post<OnboardResponse>(
      "/wallet/auth/onboard",
      { sovraAddress, oauthToken },
    );
    return data;
  }

  async holderAuth(oauthToken: string): Promise<AuthResponse> {
    const { data } = await this.backend.post<AuthResponse>(
      "/wallet/auth/login",
      { oauth_token: oauthToken },
    );
    return data;
  }

  // ─── Recovery Operations ──────────────────────────

  async recoverySign(hash: Uint8Array): Promise<SignResponse> {
    const { data } = await this.backend.post<SignResponse>(
      "/wallet/recovery/sign",
      { hash: bytesToHex(hash) },
    );
    return data;
  }

  async recoveryInitiate(params: {
    newKeyX: string;
    newKeyY: string;
    keyToReplace: number;
  }): Promise<RecoverySignatureResponse> {
    const { data } = await this.backend.post<RecoverySignatureResponse>(
      "/wallet/recovery/initiate",
      { newKeyX: params.newKeyX, newKeyY: params.newKeyY, keyToReplace: params.keyToReplace },
    );
    return data;
  }

  async recoveryFinalize(): Promise<RecoverySignatureResponse> {
    const { data } = await this.backend.post<RecoverySignatureResponse>(
      "/wallet/recovery/finalize",
      {},
    );
    return data;
  }

  async rotateRecoveryKey(): Promise<RotateRecoveryKeyResponse> {
    const { data } = await this.backend.post<RotateRecoveryKeyResponse>(
      "/wallet/recovery/rotate-key",
      {},
    );
    return data;
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
