import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/p256";
import {
  sha256,
  base64urlEncode,
  hexToBytes,
  concatBytes,
} from "@sovra/wallet-core/utils";
import { verifyES256, verifyCompoundSignature } from "../src/signature";
import { VerificationError } from "../src/parse";
import { ErrorCode } from "../src/types";
import { generateP256KeyPair } from "./fixtures";

function buildSignedJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: Uint8Array,
): string {
  const headerB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(header)),
  );
  const payloadB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  const signingInput = `${headerB64}.${payloadB64}`;
  const hash = sha256(new TextEncoder().encode(signingInput));
  const sig = p256.sign(hash, privateKey, { lowS: true });
  const r = hexToBytes(sig.r.toString(16).padStart(64, "0"));
  const s = hexToBytes(sig.s.toString(16).padStart(64, "0"));
  const sigB64 = base64urlEncode(concatBytes(r, s));
  return `${signingInput}.${sigB64}`;
}

describe("verifyES256", () => {
  const key = generateP256KeyPair();

  it("verifies a valid ES256 JWT signature", () => {
    const jwt = buildSignedJwt(
      { alg: "ES256", typ: "vc+sd-jwt" },
      { iss: "test", iat: 123 },
      key.privateKey,
    );
    expect(verifyES256(jwt, key.x, key.y)).toBe(true);
  });

  it("rejects a signature with wrong key", () => {
    const otherKey = generateP256KeyPair();
    const jwt = buildSignedJwt(
      { alg: "ES256" },
      { iss: "test" },
      key.privateKey,
    );
    expect(verifyES256(jwt, otherKey.x, otherKey.y)).toBe(false);
  });

  it("rejects a tampered payload", () => {
    const jwt = buildSignedJwt(
      { alg: "ES256" },
      { iss: "test" },
      key.privateKey,
    );
    // Tamper with the payload
    const parts = jwt.split(".");
    const tampered = `${parts[0]}.${base64urlEncode(
      new TextEncoder().encode(JSON.stringify({ iss: "tampered" })),
    )}.${parts[2]}`;
    expect(verifyES256(tampered, key.x, key.y)).toBe(false);
  });

  it("returns false for wrong-length signature", () => {
    const headerB64 = base64urlEncode(new TextEncoder().encode("{}"));
    const payloadB64 = base64urlEncode(new TextEncoder().encode("{}"));
    const badSig = base64urlEncode(new Uint8Array(32)); // wrong length
    const jwt = `${headerB64}.${payloadB64}.${badSig}`;
    expect(verifyES256(jwt, key.x, key.y)).toBe(false);
  });
});

describe("verifyCompoundSignature", () => {
  const passkey = generateP256KeyPair();
  const server = generateP256KeyPair();

  function buildCompoundJwt(): string {
    const header = { alg: "ES256", typ: "kb+jwt" };
    const payload = { iat: 123, nonce: "abc", aud: "test", sd_hash: "xyz" };
    const headerB64 = base64urlEncode(
      new TextEncoder().encode(JSON.stringify(header)),
    );
    const payloadB64 = base64urlEncode(
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    const signingInput = `${headerB64}.${payloadB64}`;
    const hash = sha256(new TextEncoder().encode(signingInput));

    const pSig = p256.sign(hash, passkey.privateKey, { lowS: true });
    const pR = hexToBytes(pSig.r.toString(16).padStart(64, "0"));
    const pS = hexToBytes(pSig.s.toString(16).padStart(64, "0"));

    const sSig = p256.sign(hash, server.privateKey, { lowS: true });
    const sR = hexToBytes(sSig.r.toString(16).padStart(64, "0"));
    const sS = hexToBytes(sSig.s.toString(16).padStart(64, "0"));

    const combined = concatBytes(pR, pS, sR, sS);
    return `${signingInput}.${base64urlEncode(combined)}`;
  }

  it("verifies a valid compound signature", () => {
    const jwt = buildCompoundJwt();
    expect(() =>
      verifyCompoundSignature(jwt, passkey.x, passkey.y, server.x, server.y),
    ).not.toThrow();
  });

  it("throws KB_PASSKEY_SIG_INVALID with wrong passkey", () => {
    const wrongKey = generateP256KeyPair();
    const jwt = buildCompoundJwt();
    try {
      verifyCompoundSignature(jwt, wrongKey.x, wrongKey.y, server.x, server.y);
      expect.fail("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VerificationError);
      expect((e as VerificationError).code).toBe(ErrorCode.KB_PASSKEY_SIG_INVALID);
    }
  });

  it("throws KB_SERVER_SIG_INVALID with wrong server key", () => {
    const wrongKey = generateP256KeyPair();
    const jwt = buildCompoundJwt();
    try {
      verifyCompoundSignature(jwt, passkey.x, passkey.y, wrongKey.x, wrongKey.y);
      expect.fail("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VerificationError);
      expect((e as VerificationError).code).toBe(ErrorCode.KB_SERVER_SIG_INVALID);
    }
  });

  it("throws on wrong-length signature", () => {
    const headerB64 = base64urlEncode(new TextEncoder().encode("{}"));
    const payloadB64 = base64urlEncode(new TextEncoder().encode("{}"));
    const badSig = base64urlEncode(new Uint8Array(64)); // 64 instead of 128
    const jwt = `${headerB64}.${payloadB64}.${badSig}`;
    try {
      verifyCompoundSignature(jwt, passkey.x, passkey.y, server.x, server.y);
      expect.fail("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VerificationError);
      expect((e as VerificationError).code).toBe(ErrorCode.KB_PASSKEY_SIG_INVALID);
    }
  });
});
