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

  /** Register with co-signing server during onboarding. Returns server public key. */
  async onboard(
    sovraAddress: string,
    oauthToken: string,
  ): Promise<{
    serverPublicKey: { x: Uint8Array; y: Uint8Array };
  }> {
    const response = await this.api.cosignerOnboard(sovraAddress, oauthToken);

    this.api.setSessionToken(response.sessionToken);

    return {
      serverPublicKey: {
        x: base64urlDecode(response.serverPublicKey.x),
        y: base64urlDecode(response.serverPublicKey.y),
      },
    };
  }

  /** Request co-signature on a message hash. Requires valid session. */
  async cosign(messageHash: Uint8Array): Promise<{
    r: Uint8Array;
    s: Uint8Array;
  }> {
    const response = await this.api.cosignerSign(messageHash);
    return {
      r: hexToBytes(response.r),
      s: hexToBytes(response.s),
    };
  }

  /** Refresh the co-signing server session via OAuth. */
  async refreshSession(oauthToken: string): Promise<void> {
    const response = await this.api.cosignerAuth(oauthToken);
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
