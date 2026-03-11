import { describe, it, expect } from "vitest";
import { sha256, base64urlEncode } from "@sovra/wallet-core/utils";
import { verifyDisclosures } from "../src/disclosure";
import { VerificationError } from "../src/parse";
import { ErrorCode } from "../src/types";

describe("verifyDisclosures", () => {
  function makeDisclosure(salt: string, key: string, value: unknown) {
    const encoded = base64urlEncode(
      new TextEncoder().encode(JSON.stringify([salt, key, value])),
    );
    const hash = base64urlEncode(sha256(new TextEncoder().encode(encoded)));
    return { encoded, salt, key, value, hash };
  }

  it("verifies valid disclosures against _sd array", () => {
    const d1 = makeDisclosure("salt1", "name", "Alice");
    const d2 = makeDisclosure("salt2", "age", 30);

    const sdArray = [d1.hash, d2.hash];
    const payload = {
      iss: "did:sovra:0x123",
      _sd: sdArray,
      _sd_alg: "sha-256",
      static_field: "visible",
    };

    const claims = verifyDisclosures(
      [
        { encoded: d1.encoded, salt: d1.salt, key: d1.key, value: d1.value },
        { encoded: d2.encoded, salt: d2.salt, key: d2.key, value: d2.value },
      ],
      sdArray,
      "sha-256",
      payload,
    );

    expect(claims.name).toBe("Alice");
    expect(claims.age).toBe(30);
    expect(claims.static_field).toBe("visible");
    expect(claims._sd).toBeUndefined();
    expect(claims._sd_alg).toBeUndefined();
  });

  it("throws DISCLOSURE_MISMATCH when hash not in _sd", () => {
    const d1 = makeDisclosure("salt1", "name", "Alice");

    try {
      verifyDisclosures(
        [{ encoded: d1.encoded, salt: d1.salt, key: d1.key, value: d1.value }],
        ["wrong_hash"],
        "sha-256",
        { _sd: ["wrong_hash"], _sd_alg: "sha-256" },
      );
      expect.fail("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VerificationError);
      expect((e as VerificationError).code).toBe(ErrorCode.DISCLOSURE_MISMATCH);
    }
  });

  it("throws PARSE_ERROR for unsupported _sd_alg", () => {
    try {
      verifyDisclosures([], [], "sha-512", {});
      expect.fail("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(VerificationError);
      expect((e as VerificationError).code).toBe(ErrorCode.PARSE_ERROR);
    }
  });

  it("excludes cnf from returned claims", () => {
    const payload = {
      iss: "test",
      cnf: { kid: "did:sovra:0x123#passkey" },
      visible: true,
    };
    const claims = verifyDisclosures([], [], "sha-256", payload);
    expect(claims.cnf).toBeUndefined();
    expect(claims.visible).toBe(true);
  });
});
