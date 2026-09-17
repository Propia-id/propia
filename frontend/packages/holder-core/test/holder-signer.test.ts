import { describe, expect, it } from "vitest";
import { assertionToJwtSegment, type WebAuthnAssertion } from "../src/index";
import { holderSignerToDeviceSigner } from "../src/mdoc/index";
import { COSE_ALG, SOVRA_WEBAUTHN_LABEL } from "../src/cose/index";
import { base64urlEncode, sha256 } from "../src/utils/index";

const assertion: WebAuthnAssertion = {
  kind: "webauthn",
  r: "0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
  s: "0x09f8e7d6c5b4a3928170f6e5d4c3b2a10918f7e6d5c4b3a29180f7e6d5c4b3a2",
  challengeIndex: 23,
  typeIndex: 1,
  authenticatorData:
    "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
  clientDataJson: '{"type":"webauthn.get","challenge":"AAAA","origin":"https://sovra.io"}',
};

describe("assertionToJwtSegment", () => {
  it("matches byte for byte what the wallet produced before the signer widened", () => {
    // The signer used to return a finished JWT segment; it now returns the raw
    // assertion so one signature can be encoded as JWT *or* COSE. This literal
    // is the output of the previous inline construction, so a drift in key
    // order or hex formatting fails here rather than as an unexplained
    // "invalid_proof" from the backend — which parses this exact shape in
    // Sovra.Crypto.WebAuthn.parse_assertion/1.
    expect(assertionToJwtSegment(assertion, base64urlEncode)).toBe(
      "eyJyIjoiMHgxYTJiM2M0ZDVlNmY3MDgxOTJhM2I0YzVkNmU3ZjgwOTFhMmIzYzRkNWU2ZjcwODE5MmEz" +
        "YjRjNWQ2ZTdmODA5IiwicyI6IjB4MDlmOGU3ZDZjNWI0YTM5MjgxNzBmNmU1ZDRjM2IyYTEwOTE4Zjdl" +
        "NmQ1YzRiM2EyOTE4MGY3ZTZkNWM0YjNhMiIsImNoYWxsZW5nZV9pbmRleCI6MjMsInR5cGVfaW5kZXgi" +
        "OjEsImF1dGhlbnRpY2F0b3JfZGF0YSI6IjB4NDk5NjBkZTU4ODBlOGM2ODc0MzQxNzBmNjQ3NjYwNWI4" +
        "ZmU0YWViOWEyODYzMmM3OTk1Y2YzYmE4MzFkOTc2MzFkMDAwMDAwMDAiLCJjbGllbnRfZGF0YV9qc29u" +
        "Ijoie1widHlwZVwiOlwid2ViYXV0aG4uZ2V0XCIsXCJjaGFsbGVuZ2VcIjpcIkFBQUFcIixcIm9yaWdp" +
        "blwiOlwiaHR0cHM6Ly9zb3ZyYS5pb1wifSJ9",
    );
  });

  it("refuses to put a raw ES256 signature in a JWT segment", () => {
    // A future Secure Enclave device key produces this shape, and it has no
    // WebAuthn envelope to serialise — silently emitting a half-filled segment
    // would be worse than failing.
    expect(() =>
      assertionToJwtSegment({ kind: "es256", r: "0x00", s: "0x01" }, base64urlEncode),
    ).toThrow();
  });
});

describe("holderSignerToDeviceSigner", () => {
  const signer = {
    alg: "WebAuthn",
    coseAlg: COSE_ALG.SOVRA_WEBAUTHN_P256,
    async sign() {
      return assertion;
    },
  };

  it("splits the assertion into a COSE signature and an unprotected envelope", async () => {
    const device = holderSignerToDeviceSigner(signer, "cred-id", sha256);
    const { signature, unprotected } = await device.signCose(new Uint8Array([1, 2, 3]));

    // r || s, 64 bytes for P-256.
    expect(signature).toHaveLength(64);
    expect(signature[0]).toBe(0x1a);
    expect(signature[32]).toBe(0x09);

    const envelope = unprotected.get(SOVRA_WEBAUTHN_LABEL) as Map<string, unknown>;
    expect(envelope.get("challenge_index")).toBe(23);
    expect(envelope.get("type_index")).toBe(1);
    expect(envelope.get("authenticator_data")).toBeInstanceOf(Uint8Array);
    // clientDataJSON is hashed exactly as received, so it travels as its own
    // UTF-8 bytes rather than being re-serialised.
    expect(new TextDecoder().decode(envelope.get("client_data_json") as Uint8Array)).toBe(
      assertion.clientDataJson,
    );
  });

  it("declares the private-use algorithm rather than claiming ES256", async () => {
    // -7 would be a lie: a WebAuthn authenticator signs
    // authenticatorData || SHA-256(clientDataJSON), not the payload, so a
    // conformant reader following -7 fails with no diagnostic.
    const device = holderSignerToDeviceSigner(signer, "cred-id", sha256);
    expect(device.coseAlg).toBe(COSE_ALG.SOVRA_WEBAUTHN_P256);
    expect(device.coseAlg).toBeLessThanOrEqual(-65536);
  });

  it("signs the hash of the bytes, which is the WebAuthn challenge", async () => {
    let seen: Uint8Array | null = null;
    const spy = {
      ...signer,
      async sign(hash: Uint8Array) {
        seen = hash;
        return assertion;
      },
    };

    const toBeSigned = new Uint8Array([9, 8, 7]);
    await holderSignerToDeviceSigner(spy, "cred-id", sha256).signCose(toBeSigned);

    expect(seen).toEqual(sha256(toBeSigned));
  });
});
