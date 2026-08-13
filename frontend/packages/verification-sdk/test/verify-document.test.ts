import { describe, it, expect, vi, afterEach } from "vitest";
import { p256 } from "@noble/curves/p256";
import {
  sha256,
  base64urlEncode,
  bytesToHex,
  hexToBytes,
  concatBytes,
} from "@sovrahq/holder-core/utils";
import { verifyDocument, decodeDocument } from "../src/verify-document";
import { ErrorCode } from "../src/types";

const ISSUER_ADDRESS = "0x1111111111111111111111111111111111111111";
const VCT = "EmploymentLetter";
const IAT = 1_760_000_000;
const EXP = IAT + 31_536_000;

const CHAIN = {
  l2RpcUrl: "http://rpc.test",
  didRegistryAddress: "0xdidregistry",
  issuerRegistryAddress: "0xissuerregistry",
  signatureRegistryAddress: "0xsignatureregistry",
  now: IAT + 60,
};

const slot = (hex: string) => hex.padStart(64, "0");
const encodeSegment = (value: object) =>
  base64urlEncode(new TextEncoder().encode(JSON.stringify(value)));

/** A signed document: an ES256 JWS with an empty disclosure tail. */
function buildDocument(payloadOverrides: Record<string, unknown> = {}) {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(privateKey, false);

  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const payload = {
    iss: `https://issuer.test/did:sovra:${ISSUER_ADDRESS}`,
    vct: VCT,
    jti: "3f7c1e4a-2b91-4c0d-9a58-1e6b8d5f0c73",
    iat: IAT,
    exp: EXP,
    employee_name: "Ada Lovelace",
    ...payloadOverrides,
  };

  const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`;
  const digest = sha256(new TextEncoder().encode(signingInput));
  const signature = p256.sign(digest, privateKey, { lowS: true });
  const r = hexToBytes(signature.r.toString(16).padStart(64, "0"));
  const s = hexToBytes(signature.s.toString(16).padStart(64, "0"));

  return {
    credential: `${signingInput}.${base64urlEncode(concatBytes(r, s))}~`,
    signingInput,
    digest,
    r,
    s,
    x: publicKey.slice(1, 33),
    y: publicKey.slice(33, 65),
  };
}

type Document = ReturnType<typeof buildDocument>;

interface ChainOpts {
  untrusted?: boolean;
  noRecord?: boolean;
  /** Anchor a different signature than the one inside the JWS. */
  anchoredR?: Uint8Array;
}

function mockChain(document: Document, opts: ChainOpts = {}) {
  // resolve(address) returns (VerificationMethod[], ServiceEndpoint[], uint64,
  // uint64, uint32, bool): six head slots, then each dynamic array's length and
  // elements at its offset.
  const resolveResult =
    "0x" +
    slot((6 * 32).toString(16)) +
    slot((6 * 32 + 32 + 5 * 32).toString(16)) +
    slot("65e1f400") +
    slot("65e1f400") +
    slot("1") +
    slot("0") +
    slot("1") +
    "aa".repeat(32) +
    slot("0") +
    bytesToHex(document.x, false) +
    bytesToHex(document.y, false) +
    slot("2") +
    slot("0");

  const trustedResult = "0x" + slot(opts.untrusted ? "0" : "1");

  // Record { bytes32 r, bytes32 s, uint64 recordedAt }, all static, so inline.
  const recordResult = opts.noRecord
    ? "0x" + slot("0") + slot("0") + slot("0")
    : "0x" +
      bytesToHex(opts.anchoredR ?? document.r, false) +
      bytesToHex(document.s, false) +
      slot("65e1f400");

  return vi.fn(async (_url: string, init?: RequestInit) => {
    const body = JSON.parse(init?.body as string);
    const to = (body.params[0].to as string).toLowerCase();

    const result =
      to === "0xdidregistry"
        ? resolveResult
        : to === "0xissuerregistry"
          ? trustedResult
          : recordResult;

    return { ok: true, json: async () => ({ jsonrpc: "2.0", id: 1, result }) };
  });
}

function checkFor(result: Awaited<ReturnType<typeof verifyDocument>>, id: string) {
  return result.checks.find((check) => check.id === id);
}

describe("verifyDocument", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("accepts a document signed by a trusted issuer and anchored on-chain", async () => {
    const document = buildDocument();
    vi.stubGlobal("fetch", mockChain(document));

    const result = await verifyDocument(document.credential, CHAIN);

    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.claims?.employee_name).toBe("Ada Lovelace");
    expect(result.credentialType).toBe(VCT);
    expect(result.issuer?.address).toBe(ISSUER_ADDRESS);
    expect(result.checks.every((check) => check.ok)).toBe(true);
  });

  it("recomputes the digest the signature was anchored under", async () => {
    const document = buildDocument();
    vi.stubGlobal("fetch", mockChain(document));

    const result = await verifyDocument(document.credential, CHAIN);

    expect(result.digest).toBe(bytesToHex(document.digest));
  });

  it("rejects a document whose payload was altered after signing", async () => {
    const document = buildDocument();
    const [header, , signature] = document.credential.replace("~", "").split(".");
    const forged = encodeSegment({
      iss: `https://issuer.test/did:sovra:${ISSUER_ADDRESS}`,
      vct: VCT,
      jti: "3f7c1e4a-2b91-4c0d-9a58-1e6b8d5f0c73",
      iat: IAT,
      exp: EXP,
      employee_name: "Someone Else",
    });
    vi.stubGlobal("fetch", mockChain(document));

    const result = await verifyDocument(`${header}.${forged}.${signature}~`, CHAIN);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.ISSUER_SIG_INVALID);
    expect(checkFor(result, "signature")?.ok).toBe(false);
  });

  it("rejects a document with no signature record on-chain", async () => {
    const document = buildDocument();
    vi.stubGlobal("fetch", mockChain(document, { noRecord: true }));

    const result = await verifyDocument(document.credential, CHAIN);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.NOT_ANCHORED);
    expect(checkFor(result, "anchor")?.ok).toBe(false);
  });

  it("rejects a document whose anchored signature belongs to another document", async () => {
    const document = buildDocument();
    vi.stubGlobal("fetch", mockChain(document, { anchoredR: new Uint8Array(32).fill(7) }));

    const result = await verifyDocument(document.credential, CHAIN);

    expect(result.valid).toBe(false);
    expect(checkFor(result, "anchor")?.ok).toBe(true);
    expect(checkFor(result, "anchor-match")?.ok).toBe(false);
  });

  it("rejects a document whose issuer is not authorized for its type", async () => {
    const document = buildDocument();
    vi.stubGlobal("fetch", mockChain(document, { untrusted: true }));

    const result = await verifyDocument(document.credential, CHAIN);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.ISSUER_NOT_TRUSTED);
    expect(checkFor(result, "trust")?.ok).toBe(false);
  });

  it("rejects an expired document, allowing for clock skew", async () => {
    const document = buildDocument();
    vi.stubGlobal("fetch", mockChain(document));

    const justInside = await verifyDocument(document.credential, { ...CHAIN, now: EXP + 30 });
    const past = await verifyDocument(document.credential, { ...CHAIN, now: EXP + 3600 });

    expect(justInside.valid).toBe(true);
    expect(past.valid).toBe(false);
    expect(past.errorCode).toBe(ErrorCode.CREDENTIAL_EXPIRED);
  });

  it("rejects a holder credential, which belongs to verify instead", async () => {
    const document = buildDocument({ cnf: { kid: "did:sovra:0xabc#2of2" } });
    vi.stubGlobal("fetch", mockChain(document));

    const result = await verifyDocument(document.credential, CHAIN);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.NOT_A_DOCUMENT);
  });

  it("rejects an algorithm it does not verify", async () => {
    const header = encodeSegment({ alg: "none", typ: "vc+sd-jwt" });
    const payload = encodeSegment({ iss: "x", vct: VCT, iat: IAT });

    const result = await verifyDocument(`${header}.${payload}.sig~`, CHAIN);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.PARSE_ERROR);
  });
});

describe("decodeDocument", () => {
  it("returns the claims without checking anything", () => {
    const document = buildDocument();

    expect(decodeDocument(document.credential)).toMatchObject({
      vct: VCT,
      employee_name: "Ada Lovelace",
    });
  });
});
