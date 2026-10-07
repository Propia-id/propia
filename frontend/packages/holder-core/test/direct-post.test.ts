/**
 * The direct_post payload is a cross-repo contract: the verifier JSON-decodes
 * `vp_token` and looks up the DCQL credential id inside it, and answers with
 * the verdict the wallet shows.
 *
 * Worth pinning because a payload mismatch only surfaces as a rejection, and
 * a misread answer as the wrong thing told to the holder.
 */

import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it, expect } from "vitest";
import { ApiClient } from "../src/api/index";
import { PresentationProtocol, parsePresentationOutcome, type VPRequest } from "../src/protocols";

const PRESENTATION = "header.payload.sig~disclosure1~kbjwt";

/** Protocol wired to an api that records posts instead of sending them. */
function makeProtocol(answer: unknown = {}) {
  const posted: Array<{ uri: string; vpToken: string; state: string }> = [];
  const api = {
    directPost: async (uri: string, vpToken: string, state: string) => {
      posted.push({ uri, vpToken, state });
      return answer;
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
    clientId: "decentralized_identifier:did:sovra:0x00000000000000000000000000000000000000a1",
    verified: true,
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

  // Unsigned, nothing binds `response_uri` to the verifier that asked.
  // `resolveRequest` refuses this first, but holder-core is a package: the
  // invariant has to hold at its own boundary too.
  it("refuses a request whose signature never verified", async () => {
    const { protocol, posted } = makeProtocol();

    await expect(
      protocol.executeDirectPost(request({ verified: false }), PRESENTATION),
    ).rejects.toThrow(/signature verified/);
    expect(posted).toHaveLength(0);
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

  it("returns the verdict the verifier answered with", async () => {
    const { protocol } = makeProtocol({
      verification_result: "rejected",
      reason: "credential_revoked",
    });

    await expect(protocol.executeDirectPost(request(), PRESENTATION)).resolves.toEqual({
      result: "rejected",
      reason: "credential_revoked",
    });
  });
});

describe("parsePresentationOutcome", () => {
  it("reads each verdict", () => {
    expect(parsePresentationOutcome({ verification_result: "verified" })).toEqual({
      result: "verified",
    });
    expect(
      parsePresentationOutcome({ verification_result: "rejected", reason: "session_expired" }),
    ).toEqual({ result: "rejected", reason: "session_expired" });
    expect(parsePresentationOutcome({ verification_result: "already_answered" })).toEqual({
      result: "already_answered",
    });
  });

  // OID4VP 1.0 §8.2 requires only a JSON object; the verdict is our extension.
  it("reads a verifier that sends no verdict as submitted, not verified", () => {
    expect(parsePresentationOutcome({})).toEqual({ result: "submitted" });
    expect(parsePresentationOutcome({ redirect_uri: "https://rp.example/cb" })).toEqual({
      result: "submitted",
    });
    expect(parsePresentationOutcome("")).toEqual({ result: "submitted" });
    expect(parsePresentationOutcome(null)).toEqual({ result: "submitted" });
  });

  it("ignores values it does not recognise", () => {
    expect(
      parsePresentationOutcome({ verification_result: "rejected", reason: "added_later" }),
    ).toEqual({ result: "rejected" });
    expect(parsePresentationOutcome({ verification_result: "added_later" })).toEqual({
      result: "submitted",
    });
  });
});

describe("directPost — the wire format", () => {
  /** A Response Endpoint that records the request and answers `answer`. */
  async function withEndpoint(
    answer: unknown,
    run: (url: string, seen: Promise<{ contentType?: string; body: string }>) => Promise<void>,
  ) {
    let resolveSeen!: (v: { contentType?: string; body: string }) => void;
    const seen = new Promise<{ contentType?: string; body: string }>((r) => (resolveSeen = r));
    const server = createServer((req: IncomingMessage, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        resolveSeen({ contentType: req.headers["content-type"], body });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(answer));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as AddressInfo;
    try {
      await run(`http://127.0.0.1:${port}`, seen);
    } finally {
      await new Promise((r) => server.close(r));
    }
  }

  // OID4VP 1.0 §8.2: "MUST be encoded in the request body using the format
  // defined by the application/x-www-form-urlencoded HTTP content type".
  it("form-encodes the Authorization Response and returns the parsed answer", async () => {
    await withEndpoint({ verification_result: "verified" }, async (origin, seen) => {
      const api = new ApiClient({ l2RpcUrl: "http://localhost:8545", sovraIssuerUrl: origin });
      const vpToken = JSON.stringify({ identity_citizen: "a.b.c~d=e&f~" });

      const answer = await api.directPost(
        `${origin}/wallet/verifier/direct_post/s-1`,
        vpToken,
        "st+1",
      );

      const { contentType, body } = await seen;
      expect(contentType).toBe("application/x-www-form-urlencoded");
      const params = new URLSearchParams(body);
      expect(params.get("vp_token")).toBe(vpToken);
      expect(params.get("state")).toBe("st+1");
      expect([...params.keys()]).toEqual(["vp_token", "state"]);
      expect(answer).toEqual({ verification_result: "verified" });
    });
  });
});
