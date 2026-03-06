import axios, { type AxiosInstance, type AxiosRequestConfig } from "axios";
import { bytesToHex } from "../utils/index";

// ─── Types ────────────────────────────────────────────

export interface OnboardResponse {
  serverPublicKey: { x: string; y: string };
  sessionToken: string;
}

export interface CosignResponse {
  r: string;
  s: string;
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
  token_endpoint: string;
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

    // Attach session token to co-signer requests
    this.backend.interceptors.request.use((req) => {
      if (this.sessionToken && req.url?.startsWith("/api/v1/cosigner/")) {
        req.headers.Authorization = `Bearer ${this.sessionToken}`;
      }
      return req;
    });

    // Handle 401 responses
    this.backend.interceptors.response.use(undefined, async (error) => {
      if (error.response?.status === 401 && this.onSessionExpired) {
        await this.onSessionExpired();
        return this.backend.request(error.config as AxiosRequestConfig);
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

  // ─── Co-Signer ────────────────────────────────────

  async cosignerOnboard(sovraAddress: string, oauthToken: string): Promise<OnboardResponse> {
    const { data } = await this.backend.post<OnboardResponse>(
      "/api/v1/cosigner/onboard",
      { sovraAddress, oauthToken },
    );
    return data;
  }

  async cosignerSign(hash: Uint8Array): Promise<CosignResponse> {
    const { data } = await this.backend.post<CosignResponse>(
      "/api/v1/cosigner/cosign",
      { hash: bytesToHex(hash) },
    );
    return data;
  }

  async cosignerAuth(oauthToken: string): Promise<AuthResponse> {
    const { data } = await this.backend.post<AuthResponse>(
      "/api/v1/cosigner/auth",
      { oauth_token: oauthToken },
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

  // ─── OpenID4VP ────────────────────────────────────

  async fetchRequestObject(requestUri: string): Promise<string> {
    const { data } = await axios.get<string>(requestUri);
    return data;
  }

  async submitPresentation(
    responseUri: string,
    vpToken: string,
    presentationSubmission?: Record<string, unknown>,
  ): Promise<void> {
    await axios.post(responseUri, {
      vp_token: vpToken,
      ...(presentationSubmission && {
        presentation_submission: presentationSubmission,
      }),
    });
  }
}
