import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { bytesToHex, keccak256, hexToBytes } from "@sovrahq/holder-core/utils";
import { verify } from "../src/verify";
import { ErrorCode } from "../src/types";
import { VerificationCache } from "../src/cache";
import { generateKeys, buildPresentation, type FixtureKeys } from "./fixtures";

// ─── RPC Mock Helpers ────────────────────────────────

interface MockOpts {
  deactivatedIssuer?: boolean;
  untrusted?: boolean;
  /** Holder account exposes zero keys. */
  holderNoKeys?: boolean;
  /** Holder's only key has validAt in the future (timelock not elapsed). */
  holderFutureValidAt?: boolean;
  /** Holder's only key is not a WebAuthnP256 key. */
  holderWrongKeyType?: boolean;
}

function buildMockRpcResponses(
  keys: FixtureKeys,
  issuerAddress: string,
  holderAddress: string,
  vct: string,
  opts: MockOpts = {},
) {
  const slot = (hex: string) => hex.padStart(64, "0");

  // DID Registry resolve() return for issuer
  const methodsOffset = slot((6 * 32).toString(16));
  const servicesOffset = slot((6 * 32 + 32 + 5 * 32).toString(16));
  const created = slot("65e1f400");
  const updated = slot("65e1f400");
  const versionId = slot("1");
  const deactivated = slot(opts.deactivatedIssuer ? "1" : "0");
  const methodsLength = slot("1");
  const methodId = "aa".repeat(32);
  const methodKeyType = slot("0"); // P256
  const methodPubKeyX = bytesToHex(keys.issuer.x, false);
  const methodPubKeyY = bytesToHex(keys.issuer.y, false);
  const methodRelationships = slot("2"); // assertionMethod
  const servicesLength = slot("0");

  const resolveResult =
    "0x" +
    methodsOffset + servicesOffset +
    created + updated + versionId + deactivated +
    methodsLength + methodId + methodKeyType +
    methodPubKeyX + methodPubKeyY + methodRelationships +
    servicesLength;

  // isTrusted() return
  const trustedResult = "0x" + slot(opts.untrusted ? "0" : "1");

  // Holder account view returns.
  const keysCountResult = "0x" + slot(opts.holderNoKeys ? "0" : "1");
  const keyHashResult = "0x" + "11".repeat(32);
  // Key { uint8 keyType; uint48 validAt; bytes publicKey (== abi.encode(x, y)) }
  // 2 = WebAuthnP256; validAt "1" is in the past, "ffffffffff" far in the future.
  const keyType = slot(opts.holderWrongKeyType ? "1" : "2");
  const validAt = slot(opts.holderFutureValidAt ? "ffffffffff" : "1");
  const keyStructResult =
    "0x" +
    slot("20") + // struct offset
    keyType +
    validAt +
    slot("60") + // publicKey offset
    slot("40") + // publicKey length = 64
    bytesToHex(keys.passkey.x, false) +
    bytesToHex(keys.passkey.y, false);

  return {
    resolveResult,
    trustedResult,
    keysCountResult,
    keyHashResult,
    keyStructResult,
  };
}

function createFetchMock(
  keys: FixtureKeys,
  issuerAddress: string,
  holderAddress: string,
  vct: string,
  opts: MockOpts = {},
) {
  const responses = buildMockRpcResponses(keys, issuerAddress, holderAddress, vct, opts);

  // Map function selectors to responses based on target address
  return vi.fn(async (url: string, init?: RequestInit) => {
    const body = JSON.parse(init?.body as string);
    const to = body.params[0].to.toLowerCase();
    const calldata = body.params[0].data as string;

    let result: string;

    if (to === "0xdidregistry") {
      result = responses.resolveResult;
    } else if (to === "0xissuerregistry") {
      result = responses.trustedResult;
    } else {
      // Holder account — match by function selector.
      const selector = calldata.slice(0, 10); // 0x + 8 hex chars
      const fns = [
        "getUserKeysCount()",
        "getKeyHashAt(uint256)",
        "getUserKeyByHash(bytes32)",
      ];
      const results = [
        responses.keysCountResult,
        responses.keyHashResult,
        responses.keyStructResult,
      ];
      const selectors: Record<string, string> = {};
      for (let i = 0; i < fns.length; i++) {
        const sel = "0x" + bytesToHex(
          keccak256(new TextEncoder().encode(fns[i])).slice(0, 4),
          false,
        );
        selectors[sel] = results[i];
      }

      result = selectors[selector] ?? "0x";
    }

    return {
      ok: true,
      json: async () => ({ jsonrpc: "2.0", id: 1, result }),
    };
  });
}

// ─── Tests ───────────────────────────────────────────

describe("verify", () => {
  let originalFetch: typeof globalThis.fetch;
  let testCache: VerificationCache;
  const keys = generateKeys();
  const issuerAddress = "0x1234567890abcdef1234567890abcdef12345678";
  const holderAddress = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
  const vct = "DrivingLicenceCredential";

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    testCache = new VerificationCache();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const baseOptions = {
    expectedNonce: "test-nonce-123",
    expectedAudience: "did:sovra:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    l2RpcUrl: "http://localhost:8545",
    didRegistryAddress: "0xdidregistry",
    issuerRegistryAddress: "0xissuerregistry",
  };

  it("verifies a valid presentation end-to-end", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(true);
    expect(result.issuer).toBe(`did:sovra:${issuerAddress}`);
    expect(result.holder).toBe(`did:sovra:${holderAddress}`);
    expect(result.credentialType).toBe(vct);
    expect(result.claims).toBeDefined();
    expect(result.claims!.given_name).toBe("Maria");
    expect(result.claims!.family_name).toBe("Rossi");
    expect(result.claims!.birth_date).toBe("1990-07-15");
  });

  it("returns ISSUER_SIG_INVALID for wrong issuer key", async () => {
    const wrongKeys = { ...keys, issuer: generateKeys().issuer };
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
    });

    // Mock returns WRONG issuer key (from wrongKeys)
    globalThis.fetch = createFetchMock(wrongKeys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.ISSUER_SIG_INVALID);
  });

  it("returns ISSUER_NOT_TRUSTED for untrusted issuer", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct, {
      untrusted: true,
    }) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.ISSUER_NOT_TRUSTED);
  });

  it("returns CREDENTIAL_EXPIRED for expired credential", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.CREDENTIAL_EXPIRED);
  });

  it("returns KB_NONCE_MISMATCH for wrong nonce", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      nonce: "wrong-nonce",
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.KB_NONCE_MISMATCH);
  });

  it("returns KB_AUDIENCE_MISMATCH for wrong audience", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      audience: "did:sovra:0xwrongaudience",
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.KB_AUDIENCE_MISMATCH);
  });

  it("returns ISSUER_DEACTIVATED for deactivated issuer", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct, {
      deactivatedIssuer: true,
    }) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.ISSUER_DEACTIVATED);
  });

  it("returns HOLDER_NOT_FOUND when the holder account has no keys", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct, {
      holderNoKeys: true,
    }) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.HOLDER_NOT_FOUND);
  });

  it("returns HOLDER_NOT_FOUND when the holder's only key is not yet valid (validAt in future)", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct, {
      holderFutureValidAt: true,
    }) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.HOLDER_NOT_FOUND);
  });

  it("returns HOLDER_NOT_FOUND when the holder's only key is not WebAuthnP256", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct, {
      holderWrongKeyType: true,
    }) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.HOLDER_NOT_FOUND);
  });

  it("verifies in offline mode — skips on-chain calls, returns trustNotVerified", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
    });

    // No fetch mock — offline mode should NOT call fetch at all
    globalThis.fetch = vi.fn(() => {
      throw new Error("fetch should not be called in offline mode");
    }) as typeof fetch;

    const offlineOptions = {
      ...baseOptions,
      offlineMode: true,
    };

    const result = await verify(fixture.presentation, offlineOptions, testCache);

    expect(result.valid).toBe(true);
    expect(result.offlineMode).toBe(true);
    expect(result.trustNotVerified).toBe(true);
    expect(result.claims).toBeDefined();
    expect(result.claims!.given_name).toBe("Maria");
    expect(result.credentialType).toBe(vct);
    expect(result.issuer).toBe(`did:sovra:${issuerAddress}`);
    expect(result.holder).toBe(`did:sovra:${holderAddress}`);
    // Verify fetch was never called
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("returns IAT_INVALID for credential with future iat", async () => {
    const futureIat = Math.floor(Date.now() / 1000) + 3600; // 1 hour in the future
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      iat: futureIat,
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.IAT_INVALID);
  });

  it("returns SUBJECT_KEY_MISMATCH when sub and cnf.kid differ", async () => {
    const differentHolder = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      sub: `did:sovra:${differentHolder}`, // sub points to different address than cnf.kid
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.SUBJECT_KEY_MISMATCH);
  });

  it("returns PARSE_ERROR for non-string iss", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      rawPayloadOverrides: { iss: 12345 },
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.PARSE_ERROR);
  });

  it("returns INVALID_ADDRESS for malformed issuer DID address", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      rawPayloadOverrides: { iss: "did:sovra:notahexaddress" },
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.INVALID_ADDRESS);
  });

  it("returns KB_PASSKEY_SIG_INVALID with wrong passkey on-chain", async () => {
    const wrongPasskey = generateKeys();
    const modifiedKeys = { ...keys, passkey: wrongPasskey.passkey };
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
    });

    // On-chain returns wrong passkey — signature won't match
    globalThis.fetch = createFetchMock(modifiedKeys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.KB_PASSKEY_SIG_INVALID);
  });

  // ─── WebAuthn (passkey) KB-JWT ─────────────────────────

  it("verifies a valid WebAuthn presentation end-to-end", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      kbAlg: "WebAuthn",
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(true);
    expect(result.holder).toBe(`did:sovra:${holderAddress}`);
    expect(result.claims!.given_name).toBe("Maria");
  });

  it("returns KB_PASSKEY_SIG_INVALID for a WebAuthn assertion whose challenge does not bind to the KB-JWT", async () => {
    // Signature is valid over the assertion, but the embedded challenge is not
    // base64url(sha256(signingInput)) — i.e. a replayed/foreign assertion.
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      kbAlg: "WebAuthn",
      webauthnOverrides: { challenge: "A".repeat(43) },
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.KB_PASSKEY_SIG_INVALID);
  });

  it("returns KB_PASSKEY_SIG_INVALID for a WebAuthn presentation with wrong on-chain passkey", async () => {
    const wrongPasskey = generateKeys();
    const modifiedKeys = { ...keys, passkey: wrongPasskey.passkey };
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      kbAlg: "WebAuthn",
    });

    globalThis.fetch = createFetchMock(modifiedKeys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.KB_PASSKEY_SIG_INVALID);
  });

  it("returns KB_PASSKEY_SIG_INVALID for a WebAuthn assertion without the user-verified flag", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      kbAlg: "WebAuthn",
      webauthnOverrides: { flags: 0x01 }, // UP only, UV not set
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.KB_PASSKEY_SIG_INVALID);
  });

  it("verifies a WebAuthn presentation in offline mode (skips signature, flags trustNotVerified)", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      kbAlg: "WebAuthn",
    });

    globalThis.fetch = vi.fn(() => {
      throw new Error("fetch should not be called in offline mode");
    }) as typeof fetch;

    const result = await verify(fixture.presentation, { ...baseOptions, offlineMode: true }, testCache);

    expect(result.valid).toBe(true);
    expect(result.trustNotVerified).toBe(true);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  // ─── holderRpcUrl ──────────────────────────────────
  //
  // A holder's key material lives in their own account contract, so it can
  // only be read on the chain where that account is delegated. When that is not
  // the chain holding the registries, the two lookups must be split.

  /** Record which endpoint each eth_call was sent to, keyed by target address. */
  function createRoutingFetchMock() {
    const inner = createFetchMock(keys, issuerAddress, holderAddress, vct);
    const calls: { url: string; to: string }[] = [];
    const mock = vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, to: JSON.parse(init?.body as string).params[0].to.toLowerCase() });
      return inner(url, init);
    });
    return { mock, calls };
  }

  it("reads holder keys from holderRpcUrl while registries stay on l2RpcUrl", async () => {
    const fixture = buildPresentation(keys, { issuerAddress, holderAddress, vct });
    const { mock, calls } = createRoutingFetchMock();
    globalThis.fetch = mock as unknown as typeof fetch;

    const result = await verify(
      fixture.presentation,
      { ...baseOptions, holderRpcUrl: "http://holder-chain:8545" },
      testCache,
    );

    expect(result.valid).toBe(true);

    const registryCalls = calls.filter(
      (c) => c.to === "0xdidregistry" || c.to === "0xissuerregistry",
    );
    const holderCalls = calls.filter((c) => c.to === holderAddress.toLowerCase());

    expect(registryCalls.length).toBeGreaterThan(0);
    expect(holderCalls.length).toBeGreaterThan(0);
    expect(registryCalls.every((c) => c.url === baseOptions.l2RpcUrl)).toBe(true);
    expect(holderCalls.every((c) => c.url === "http://holder-chain:8545")).toBe(true);
  });

  // ─── iss as a Credential Issuer identifier ─────────
  //
  // SD-JWT VC requires `iss` to be the Credential Issuer identifier, which under
  // OpenID4VCI is an HTTPS URL. The Sovra issuer emits
  // `https://<host>/did:sovra:0x…`, so the bare-DID form is
  // not what real credentials carry.

  it("accepts iss as an https Credential Issuer identifier ending in the DID", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      rawPayloadOverrides: {
        iss: `https://issuer.example.com/did:sovra:${issuerAddress}`,
      },
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(true);
    // The reported issuer is the identifier as presented, not a rewritten DID.
    expect(result.issuer).toBe(
      `https://issuer.example.com/did:sovra:${issuerAddress}`,
    );
  });

  it("resolves the same on-chain issuer whether iss is a URL or a bare DID", async () => {
    const asUrl = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      rawPayloadOverrides: {
        iss: `https://any-host.example/did:sovra:${issuerAddress}`,
      },
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    // A fresh cache each way, so neither run can be satisfied by the other's entry.
    const urlResult = await verify(asUrl.presentation, baseOptions, new VerificationCache());
    const bareResult = await verify(
      buildPresentation(keys, { issuerAddress, holderAddress, vct }).presentation,
      baseOptions,
      new VerificationCache(),
    );

    expect(urlResult.valid).toBe(true);
    expect(bareResult.valid).toBe(true);
  });

  it("rejects an iss whose last path segment is not a did:sovra address", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      rawPayloadOverrides: { iss: "https://issuer.example.com/issuers/42" },
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.PARSE_ERROR);
  });

  it("rejects an iss URL whose trailing DID has a malformed address", async () => {
    const fixture = buildPresentation(keys, {
      issuerAddress,
      holderAddress,
      vct,
      rawPayloadOverrides: { iss: "https://example.com/did:sovra:0xnothex" },
    });

    globalThis.fetch = createFetchMock(keys, issuerAddress, holderAddress, vct) as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.INVALID_ADDRESS);
  });

  it("defaults holder key reads to l2RpcUrl when holderRpcUrl is omitted", async () => {
    const fixture = buildPresentation(keys, { issuerAddress, holderAddress, vct });
    const { mock, calls } = createRoutingFetchMock();
    globalThis.fetch = mock as unknown as typeof fetch;

    const result = await verify(fixture.presentation, baseOptions, testCache);

    expect(result.valid).toBe(true);
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((c) => c.url === baseOptions.l2RpcUrl)).toBe(true);
  });
});
