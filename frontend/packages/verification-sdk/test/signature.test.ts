import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/p256";
import {
  sha256,
  base64urlEncode,
  hexToBytes,
  concatBytes,
} from "@sovra/wallet-core/utils";
import { verifyES256 } from "../src/signature";
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
