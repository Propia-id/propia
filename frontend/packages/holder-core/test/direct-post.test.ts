/**
 * The direct_post payload is a cross-repo contract: the verifier JSON-decodes
 * `vp_token` and looks up the DCQL credential id inside it.
 *
 * Worth pinning because a mismatch is invisible from the wallet — direct_post
 * answers 200 whatever the outcome, so the app reports success while every
 * verification fails server-side.
 */

import { describe, it, expect } from "vitest";
import { PresentationProtocol, type VPRequest } from "../src/protocols";

const PRESENTATION = "header.payload.sig~disclosure1~kbjwt";

/** Protocol wired to an api that records posts instead of sending them. */
function makeProtocol() {
  const posted: Array<{ uri: string; vpToken: string; state: string }> = [];
  const api = {
    directPost: async (uri: string, vpToken: string, state: string) => {
      posted.push({ uri, vpToken, state });
    },
  };
  const protocol = new PresentationProtocol(
    api as never,
    null as never,
    null as never,
    null as never,
  );
  return { protocol, posted };
}

function request(overrides: Partial<VPRequest> = {}): VPRequest {
  return {
    clientId: "verifier:test-workspace",
    nonce: "test-nonce",
    state: "test-state",
    responseUri: "http://localhost:4000/wallet/verifier/direct_post/test-session",
    responseMode: "direct_post",
    dcqlQuery: {
      credentials: [
        { id: "identity_citizen", format: "vc+sd-jwt", claims: [{ path: ["full_name"] }] },
      ],
    },
    ...overrides,
  };
}

describe("executeDirectPost", () => {
  it("keys the vp_token by the DCQL credential id", async () => {
    const { protocol, posted } = makeProtocol();

    await protocol.executeDirectPost(request(), PRESENTATION);

    expect(posted).toHaveLength(1);
    expect(JSON.parse(posted[0].vpToken)).toEqual({
      identity_citizen: PRESENTATION,
    });
    expect(posted[0].state).toBe("test-state");
  });

  it("throws when the DCQL query carries no credential id to key on", async () => {
    const { protocol, posted } = makeProtocol();
    const req = request({ dcqlQuery: { credentials: [] } });

    await expect(protocol.executeDirectPost(req, PRESENTATION)).rejects.toThrow(
      /DCQL credential id/,
    );
    expect(posted).toHaveLength(0);
  });

  it("throws without response_uri or state, leaving the QR path to handle it", async () => {
    const { protocol } = makeProtocol();

    await expect(
      protocol.executeDirectPost(request({ responseUri: undefined }), PRESENTATION),
    ).rejects.toThrow(/response_uri and state/);
    await expect(
      protocol.executeDirectPost(request({ state: undefined }), PRESENTATION),
    ).rejects.toThrow(/response_uri and state/);
  });
});
