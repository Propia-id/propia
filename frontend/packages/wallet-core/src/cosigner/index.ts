import type { ApiClient } from "../api/index";
import type { IdentityStore } from "../state/index";
import { hexToBytes, base64urlDecode } from "../utils/index";

export class CosignerClient {
  constructor(
    private api: ApiClient,
    private identityStore: ReturnType<
      typeof import("../state/index").createIdentityStore
    >,
  ) {}

  /** Register with recovery server during onboarding. Returns recovery public key. */
  async onboard(
    sovraAddress: string,
    oauthToken: string,
  ): Promise<{
    recoveryPublicKey: { x: Uint8Array; y: Uint8Array };
  }> {
    const response = await this.api.holderOnboard(sovraAddress, oauthToken);

    this.api.setSessionToken(response.sessionToken);

    return {
      recoveryPublicKey: {
        x: base64urlDecode(response.recoveryPublicKey.x),
        y: base64urlDecode(response.recoveryPublicKey.y),
      },
    };
  }

  /** Request recovery key signature on a message hash. Only used for recovery operations. */
  async sign(messageHash: Uint8Array): Promise<{
    r: Uint8Array;
    s: Uint8Array;
  }> {
    const response = await this.api.recoverySign(messageHash);
    return {
      r: hexToBytes(response.signature.r),
      s: hexToBytes(response.signature.s),
    };
  }

  /** Refresh the recovery server session via OAuth. */
  async refreshSession(oauthToken: string): Promise<void> {
    const response = await this.api.holderAuth(oauthToken);
    this.identityStore
      .getState()
      .setSession(response.sessionToken, response.expiresAt);
    this.api.setSessionToken(response.sessionToken);
  }

  /** Ensure a valid session exists, refreshing if needed. */
  async ensureSession(getOAuthToken: () => Promise<string>): Promise<void> {
    const state = this.identityStore.getState();
    if (state.isSessionValid()) return;

    const oauthToken = await getOAuthToken();
    await this.refreshSession(oauthToken);
  }
}
