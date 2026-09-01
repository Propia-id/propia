/**
 * Verifier authentication on the wallet side.
 *
 * The whole point of a signed request object is that nothing inside it — the
 * verifier's name least of all — is believed before the signature verifies
 * against a key the `client_id` itself resolves to. These cases pin that: what
 * a forged QR can and cannot get past `resolveRequest`, and what an unsigned
 * request is allowed to say about who is asking.
 */

import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/p256";
import { PresentationProtocol } from "../src/protocols";
import { DidResolutionError } from "../src/did/index";
import type { StoredCredential } from "../src/state/index";
import {
  base64urlEncode,
  bytesToHex,
  hexToBytes,
  keccak256,
  sha256,
} from "../src/utils/index";

const REGISTRY = "0x00000000000000000000000000000000000000ff";
const IDENTITY = "0x00000000000000000000000000000000000000a1";
const DID = `did:sovra:${IDENTITY}`;
const CLIENT_ID = `decentralized_identifier:${DID}`;

const PRIVATE_KEY = hexToBytes(
  "0x1c1f1b0e5a3d4c7b8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5",
);
const PUBLIC_KEY = p256.getPublicKey(PRIVATE_KEY, false);
const PUB_X = PUBLIC_KEY.slice(1, 33);
const PUB_Y = PUBLIC_KEY.slice(33, 65);

const DCQL = {
  credentials: [
    {
      id: "identity_citizen",
      format: "vc+sd-jwt",
      meta: { vct_values: ["NationalIdCredential"] },
      claims: [{ path: ["given_name"] }],
    },
  ],
};

const CREDENTIAL: StoredCredential = {
  id: "cred-1",
  sdJwt: "",
  issuerDid: DID,
  credentialType: "NationalIdCredential",
  issuerName: "Registro Nacional",
  issuedAt: 0,
  expiresAt: 0,
  claims: { given_name: "María", family_name: "López" },
};

// ─── On-chain DID document, as `resolve(address)` returns it ─────────

const KEY_ASSERT_ID = bytesToHex(
  keccak256(new TextEncoder().encode("key-assert")),
  false,
);

function word(hex: string): string {
  return hex.replace(/^0x/, "").padStart(64, "0");
}

/**
 * ABI-encode `(VerificationMethod[], ServiceEndpoint[], uint64, uint64,
 * uint32, bool)` with a single P-256 method.
 */
function encodeResolveResult(
  opts: {
    methodId?: string;
    keyType?: number;
    relationships?: number;
    x?: Uint8Array;
    y?: Uint8Array;
    deactivated?: boolean;
    methods?: number;
  } = {},
): string {
  const {
    methodId = KEY_ASSERT_ID,
    keyType = 0,
    relationships = 2,
    x = PUB_X,
    y = PUB_Y,
    deactivated = false,
    methods = 1,
  } = opts;

  // Head is 6 words; the methods array follows, then the (empty) services array.
  const methodsOffset = 6 * 32;
  const servicesOffset = methodsOffset + 32 + methods * 5 * 32;

  const head = [
    word(methodsOffset.toString(16)),
    word(servicesOffset.toString(16)),
    word("1"), // created
    word("2"), // updated
    word("1"), // versionId
    word(deactivated ? "1" : "0"),
  ];

  const method = [
    word(methodId),
    word(keyType.toString(16)),
    word(bytesToHex(x, false)),
    word(bytesToHex(y, false)),
    word(relationships.toString(16)),
  ];

  return (
    "0x" +
    head.join("") +
    word(methods.toString(16)) +
    (methods ? method.join("") : "") +
    word("0")
  );
}

// ─── Signed request objects ─────────────────────────────────────────

function segment(value: unknown): string {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

function signJws(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const signingInput = `${segment(header)}.${segment(payload)}`;
  const sig = p256.sign(
    sha256(new TextEncoder().encode(signingInput)),
    PRIVATE_KEY,
    { lowS: true },
  );
  return `${signingInput}.${base64urlEncode(sig.toCompactRawBytes())}`;
}

function requestObject(overrides: Record<string, unknown> = {}) {
  return {
    iss: CLIENT_ID,
    aud: "https://self-issued.me/v2",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 600,
    client_id: CLIENT_ID,
    response_type: "vp_token",
    response_mode: "direct_post",
    response_uri: "https://api.sovra.test/wallet/verifier/direct_post/s-1",
    nonce: "nonce-abc",
    state: "state-abc",
    dcql_query: DCQL,
    client_metadata: { client_name: "Alcaldía Mayor de Bogotá" },
    ...overrides,
  };
}

function signedUri(
  payload: Record<string, unknown> = requestObject(),
  header: Record<string, unknown> = {
    alg: "ES256",
    typ: "oauth-authz-req+jwt",
    kid: `${DID}#key-assert`,
  },
  clientIdParam: string | null = CLIENT_ID,
): string {
  const params = new URLSearchParams();
  if (clientIdParam !== null) params.set("client_id", clientIdParam);
  params.set("request", signJws(header, payload));
  return `openid4vp://?${params.toString()}`;
}

// ─── Protocol under test ────────────────────────────────────────────

function makeProtocol(
  opts: {
    resolveResult?: string;
    ethCallError?: Error;
    requestObject?: string;
    registry?: string;
  } = {},
) {
  const calls: Array<{ to: string; calldata: string }> = [];

  const api = {
    ethCall: async (to: string, calldata: string) => {
      calls.push({ to, calldata });
      if (opts.ethCallError) throw opts.ethCallError;
      return opts.resolveResult ?? encodeResolveResult();
    },
    fetchRequestObject: async () => {
      if (opts.requestObject === undefined) {
        throw new Error("fetchRequestObject not stubbed");
      }
      return opts.requestObject;
    },
  };

  const protocol = new PresentationProtocol(
    api as never,
    null as never,
    null as never,
    null as never,
    "registry" in opts ? opts.registry : REGISTRY,
  );

  return { protocol, calls };
}

describe("resolveRequest — signed request objects", () => {
  it("accepts a request signed by the client_id's own assertion key", async () => {
    const { protocol, calls } = makeProtocol();

    const request = await protocol.resolveRequest(signedUri());

    expect(request.verified).toBe(true);
    expect(request.clientId).toBe(CLIENT_ID);
    expect(request.verifierName).toBe("Alcaldía Mayor de Bogotá");
    expect(request.nonce).toBe("nonce-abc");
    expect(request.state).toBe("state-abc");
    expect(request.responseMode).toBe("direct_post");
    expect(request.responseUri).toBe(
      "https://api.sovra.test/wallet/verifier/direct_post/s-1",
    );
    expect(request.dcqlQuery.credentials[0].id).toBe("identity_citizen");

    // Resolved against the configured registry, not anything off the QR.
    expect(calls).toHaveLength(1);
    expect(calls[0].to).toBe(REGISTRY);
  });

  it("fetches the request object when the QR only carries a request_uri", async () => {
    const jws = signJws(
      { alg: "ES256", typ: "oauth-authz-req+jwt", kid: `${DID}#key-assert` },
      requestObject(),
    );
    const { protocol } = makeProtocol({ requestObject: `${jws}\n` });

    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      request_uri: "https://api.sovra.test/wallet/verifier/request/s-1",
    });
    const request = await protocol.resolveRequest(`openid4vp://?${params}`);

    expect(request.verified).toBe(true);
    expect(request.verifierName).toBe("Alcaldía Mayor de Bogotá");
  });

  it("rejects a request signed by a key the DID does not publish", async () => {
    // Same DID and the same #key-assert fragment, but the registry hands back
    // a different key — the forged-QR case.
    const other = p256.getPublicKey(
      hexToBytes(
        "0x0f0e0d0c0b0a09080706050403020100f1e2d3c4b5a69788796a5b4c3d2e1f00",
      ),
      false,
    );
    const { protocol } = makeProtocol({
      resolveResult: encodeResolveResult({
        x: other.slice(1, 33),
        y: other.slice(33, 65),
      }),
    });

    await expect(protocol.resolveRequest(signedUri())).rejects.toThrow(
      /signature does not verify/,
    );
  });

  it("rejects a tampered payload under an otherwise valid signature", async () => {
    const { protocol } = makeProtocol();
    const uri = new URL(signedUri());
    const [header, , sig] = uri.searchParams.get("request")!.split(".");

    // Swap in a response_uri the signature never covered.
    const forged = segment(
      requestObject({ response_uri: "https://attacker.example/collect" }),
    );
    uri.searchParams.set("request", `${header}.${forged}.${sig}`);

    await expect(protocol.resolveRequest(uri.toString())).rejects.toThrow(
      /signature does not verify/,
    );
  });

  it("rejects a kid that points at a different DID than the client_id", async () => {
    const { protocol } = makeProtocol();
    const uri = signedUri(requestObject(), {
      alg: "ES256",
      typ: "oauth-authz-req+jwt",
      kid: "did:sovra:0x00000000000000000000000000000000000000b2#key-assert",
    });

    await expect(protocol.resolveRequest(uri)).rejects.toThrow(/not a key of/);
  });

  it("rejects a client_id query parameter that disagrees with the signed one", async () => {
    const { protocol } = makeProtocol();
    const uri = signedUri(
      requestObject(),
      { alg: "ES256", typ: "oauth-authz-req+jwt", kid: `${DID}#key-assert` },
      "decentralized_identifier:did:sovra:0x00000000000000000000000000000000000000b2",
    );

    await expect(protocol.resolveRequest(uri)).rejects.toThrow(
      /does not match the signed request object/,
    );
  });

  // OID4VP makes the query parameter mandatory, so omitting it is not the
  // same as agreeing with the signed value.
  it("rejects a signed request with no client_id query parameter", async () => {
    const { protocol } = makeProtocol();
    const uri = signedUri(
      requestObject(),
      { alg: "ES256", typ: "oauth-authz-req+jwt", kid: `${DID}#key-assert` },
      null,
    );

    await expect(protocol.resolveRequest(uri)).rejects.toThrow(
      /does not match the signed request object/,
    );
  });

  it("rejects a request object that is not typed as one", async () => {
    const { protocol } = makeProtocol();
    const uri = signedUri(requestObject(), {
      alg: "ES256",
      typ: "JWT",
      kid: `${DID}#key-assert`,
    });

    await expect(protocol.resolveRequest(uri)).rejects.toThrow(
      /not a oauth-authz-req\+jwt/,
    );
  });

  it("rejects a request object addressed to someone else", async () => {
    const { protocol } = makeProtocol();
    const uri = signedUri(requestObject({ aud: "https://wallet.attacker.example" }));

    await expect(protocol.resolveRequest(uri)).rejects.toThrow(
      /not addressed to this wallet/,
    );
  });

  it("rejects an expired request object", async () => {
    const { protocol } = makeProtocol();
    const uri = signedUri(
      requestObject({ exp: Math.floor(Date.now() / 1000) - 1 }),
    );

    await expect(protocol.resolveRequest(uri)).rejects.toThrow(/has expired/);
  });

  // No `exp` is not "never expires": the QR would stay replayable for good.
  it("rejects a request object with no exp", async () => {
    const { protocol } = makeProtocol();
    const { exp: _exp, ...noExp } = requestObject();

    await expect(protocol.resolveRequest(signedUri(noExp))).rejects.toThrow(
      /carries no expiry/,
    );
  });

  it("rejects an exp that is not a number", async () => {
    const { protocol } = makeProtocol();
    const uri = signedUri(requestObject({ exp: "1900000000" }));

    await expect(protocol.resolveRequest(uri)).rejects.toThrow(
      /carries no expiry/,
    );
  });

  it("rejects a client_id with no resolvable prefix", async () => {
    const { protocol } = makeProtocol();
    const uri = signedUri(
      requestObject({ client_id: "verifier:some-workspace" }),
      { alg: "ES256", typ: "oauth-authz-req+jwt", kid: `${DID}#key-assert` },
      "verifier:some-workspace",
    );

    await expect(protocol.resolveRequest(uri)).rejects.toThrow(
      /Unsupported client_id prefix/,
    );
  });

  it("rejects rather than downgrades when no DID Registry is configured", async () => {
    const { protocol } = makeProtocol({ registry: undefined });

    await expect(protocol.resolveRequest(signedUri())).rejects.toThrow(
      /no DID Registry configured/,
    );
  });

  it("rejects a deactivated verifier DID", async () => {
    const { protocol } = makeProtocol({
      resolveResult: encodeResolveResult({ deactivated: true }),
    });

    await expect(protocol.resolveRequest(signedUri())).rejects.toThrow(
      /deactivated/,
    );
  });

  it("rejects when the DID publishes no key under the kid's fragment", async () => {
    const { protocol } = makeProtocol({
      resolveResult: encodeResolveResult({
        methodId: bytesToHex(
          keccak256(new TextEncoder().encode("key-auth")),
          false,
        ),
      }),
    });

    await expect(protocol.resolveRequest(signedUri())).rejects.toThrow(
      /no P-256 assertion key #key-assert/,
    );
  });

  it("rejects when the registry is unreachable, rather than trusting the request", async () => {
    const { protocol } = makeProtocol({
      ethCallError: new Error("connect ECONNREFUSED"),
    });

    await expect(protocol.resolveRequest(signedUri())).rejects.toThrow(
      /DID Registry unreachable/,
    );
  });

  // A head short of six words used to slice past the end: `deactivated` read
  // `undefined`, so a live DID came back reported as deactivated.
  it("rejects a result too short to hold a document", async () => {
    const { protocol } = makeProtocol({
      resolveResult: "0x" + "00".repeat(99),
    });

    await expect(protocol.resolveRequest(signedUri())).rejects.toThrow(
      /DID not registered/,
    );
  });

  // Past the trailing (empty) services word, into the method itself.
  it("rejects a result truncated inside the method array", async () => {
    const full = encodeResolveResult();

    const { protocol } = makeProtocol({
      resolveResult: full.slice(0, full.length - 128),
    });

    await expect(protocol.resolveRequest(signedUri())).rejects.toThrow(
      /undecodable document/,
    );
  });

  // An odd-length slice used to escape as a bare Error("Invalid hex string"),
  // which callers discriminating on the error type mishandled.
  it("rejects an odd-length result as a DidResolutionError", async () => {
    const full = encodeResolveResult();

    const { protocol } = makeProtocol({
      resolveResult: full.slice(0, full.length - 129),
    });

    await expect(protocol.resolveRequest(signedUri())).rejects.toThrow(
      DidResolutionError,
    );
  });

  it("rejects a request_uri that answers with something unsigned", async () => {
    const { protocol } = makeProtocol({
      requestObject: JSON.stringify(requestObject()),
    });

    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      request_uri: "https://api.sovra.test/wallet/verifier/request/s-1",
    });

    await expect(
      protocol.resolveRequest(`openid4vp://?${params}`),
    ).rejects.toThrow(/did not return a signed request object/);
  });

  // A signature proves who wrote `client_metadata`, not that `client_name` is
  // a string. The consent screen renders it into a React Native <Text>, which
  // throws on anything else — by here the signature has already verified.
  it("ignores a client_name that is not a string", async () => {
    const { protocol } = makeProtocol();

    const request = await protocol.resolveRequest(
      signedUri(requestObject({ client_metadata: { client_name: { es: "Salta" } } })),
    );

    expect(request.verified).toBe(true);
    expect(request.verifierName).toBeUndefined();
  });
});

describe("resolveRequest — unsigned requests", () => {
  it("keeps working, but discards the name it claims for itself", async () => {
    const { protocol, calls } = makeProtocol();
    const params = new URLSearchParams({
      client_id: DID,
      request: JSON.stringify({
        client_id: DID,
        nonce: "nonce-abc",
        dcql_query: DCQL,
        client_metadata: { client_name: "Alcaldía Mayor de Bogotá" },
      }),
    });

    const request = await protocol.resolveRequest(`openid4vp://?${params}`);

    expect(request.verified).toBe(false);
    expect(request.verifierName).toBeUndefined();
    expect(request.clientId).toBe(DID);
    expect(request.nonce).toBe("nonce-abc");
    // Nothing to resolve: an unsigned request is never authenticated at all.
    expect(calls).toHaveLength(0);
  });

  it("accepts the flat-query form the same way", async () => {
    const { protocol } = makeProtocol();
    const params = new URLSearchParams({
      client_id: DID,
      nonce: "nonce-abc",
      dcql_query: JSON.stringify(DCQL),
    });

    const request = await protocol.resolveRequest(`openid4vp://?${params}`);

    expect(request.verified).toBe(false);
    expect(request.clientId).toBe(DID);
    // The standalone verifier app answers by QR, and that is the only shape of
    // unsigned request the wallet takes.
    expect(request.responseUri).toBeUndefined();
  });

  // `direct_post` mails the disclosed claims to an address the QR chose. Only
  // the signature binds that address to the verifier that asked, so unsigned
  // there is nothing to bind it to — and no Sovra verifier asks for it.
  it("refuses an unsigned request that asks for direct_post", async () => {
    const { protocol } = makeProtocol();
    const params = new URLSearchParams({
      client_id: DID,
      nonce: "nonce-abc",
      response_mode: "direct_post",
      response_uri: "https://attacker.example/collect",
      dcql_query: JSON.stringify(DCQL),
    });

    await expect(
      protocol.resolveRequest(`openid4vp://?${params}`),
    ).rejects.toThrow(/cannot use direct_post/);
  });

  it("refuses an unsigned response_uri even with no response_mode", async () => {
    const { protocol } = makeProtocol();
    const params = new URLSearchParams({
      client_id: DID,
      nonce: "nonce-abc",
      response_uri: "https://attacker.example/collect",
      dcql_query: JSON.stringify(DCQL),
    });

    await expect(
      protocol.resolveRequest(`openid4vp://?${params}`),
    ).rejects.toThrow(/cannot use direct_post/);
  });

  // The downgrade needs no key, only a photograph of a real QR: strip the
  // `request` parameter, keep the verifier's own client_id, point response_uri
  // at yourself. A prefix the wallet can resolve a key for has to be signed.
  it("refuses a prefixed client_id that arrives without a signature", async () => {
    const { protocol, calls } = makeProtocol();
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      nonce: "nonce-abc",
      response_mode: "direct_post",
      response_uri: "https://attacker.example/collect",
      dcql_query: JSON.stringify(DCQL),
    });

    await expect(
      protocol.resolveRequest(`openid4vp://?${params}`),
    ).rejects.toThrow(/must arrive in a signed request object/);
    expect(calls).toHaveLength(0);
  });

  it("refuses it in the JSON-wrapped form too", async () => {
    const { protocol } = makeProtocol();
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      request: JSON.stringify({
        client_id: CLIENT_ID,
        nonce: "nonce-abc",
        dcql_query: DCQL,
      }),
    });

    await expect(
      protocol.resolveRequest(`openid4vp://?${params}`),
    ).rejects.toThrow(/must arrive in a signed request object/);
  });

  it("still rejects a request missing the parameters it needs", async () => {
    const { protocol } = makeProtocol();

    await expect(
      protocol.resolveRequest(`openid4vp://?client_id=${DID}`),
    ).rejects.toThrow(/Missing required OpenID4VP parameters/);
  });

  // Dropping `client_name` is half the job: `client_id` is free text too.
  it("does not offer a free-text client_id as the verifier's name", async () => {
    const { protocol } = makeProtocol();
    const params = new URLSearchParams({
      client_id: "Gobierno de Salta",
      nonce: "nonce-abc",
      dcql_query: JSON.stringify(DCQL),
    });

    const request = await protocol.resolveRequest(`openid4vp://?${params}`);
    const approval = protocol.buildApprovalData(request, CREDENTIAL, [
      "given_name",
    ]);

    expect(approval.verified).toBe(false);
    expect(approval.verifierName).toBeUndefined();
    // Carried on the request for the audit trail, but never offered to the
    // consent screen as a name.
    expect(request.clientId).toBe("Gobierno de Salta");
  });

  it("keeps the attested name for a request whose signature verified", async () => {
    const { protocol } = makeProtocol();

    const request = await protocol.resolveRequest(signedUri());
    const approval = protocol.buildApprovalData(request, CREDENTIAL, [
      "given_name",
    ]);

    expect(approval.verified).toBe(true);
    expect(approval.verifierName).toBe("Alcaldía Mayor de Bogotá");
  });
});
