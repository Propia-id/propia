import { describe, expect, it } from "vitest";
import fixture from "@sovrahq/holder-core/test-fixtures/mdoc-issuer-signed.json";
import {
  buildDeviceResponse,
  parseIssuerSigned,
  type DeviceSigner,
} from "@sovrahq/holder-core/mdoc";
import { COSE_ALG } from "@sovrahq/holder-core/cose";
import { base64urlDecode, base64urlEncode, hexToBytes, sha256 } from "@sovrahq/holder-core/utils";
import { CborTagged, decode, encode, type CborMap, type CborValue } from "@sovrahq/holder-core/cbor";
import { p256 } from "@noble/curves/p256";

import { verifyMdoc } from "../src/mdoc/verify-mdoc.js";
import { ErrorCode } from "../src/types.js";

/**
 * The wallet builds a presentation and the SDK verifies it, with nothing in
 * between written to make the two agree.
 *
 * This is the test the whole mdoc effort rests on. The two sides construct the
 * session transcript, the `Sig_structure` and the tag-24 digests independently,
 * and none of it is exchanged — so a divergence anywhere shows up here rather
 * than as an unexplained signature failure in the field.
 *
 * Runs in offline mode: the chain reads are covered by verify.ts's own suite,
 * and what is under test is the cryptographic contract.
 */

const parsed = parseIssuerSigned(fixture.issuerSigned);

const handover = {
  clientId: "verifier:018f4a1c-0000-7000-8000-000000000001",
  nonce: "n-0S6_WzA2Mj",
  responseUri: "https://api.sovra.io/wallet/verifier/direct_post/abc",
};

// The fixture carries the holder's private key, so these presentations are
// signed by the key the issuer actually bound — no substitution, no
// re-signing. The device-key binding check is therefore exercised for real.
const holderPrivateKey = hexToBytes(fixture.holderPrivateKey);

/** A device signer signing the payload directly — the conformant path. */
const es256Signer: DeviceSigner = {
  coseAlg: COSE_ALG.ES256,
  async signCose(toBeSigned) {
    const sig = p256.sign(sha256(toBeSigned), holderPrivateKey, { prehash: false });
    return { signature: sig.toBytes("compact"), unprotected: new Map() };
  },
};

/** The WebAuthn path the wallet actually ships: envelope in the unprotected header. */
const webAuthnSigner: DeviceSigner = {
  coseAlg: COSE_ALG.SOVRA_WEBAUTHN_P256,
  async signCose(toBeSigned) {
    const challenge = base64urlEncode(sha256(toBeSigned));
    const clientDataJson = `{"type":"webauthn.get","challenge":"${challenge}","origin":"https://sovra.io"}`;
    const cdjBytes = new TextEncoder().encode(clientDataJson);

    // rpIdHash(32) || flags(UP|UV|BE) || counter(4)
    const authenticatorData = new Uint8Array(37);
    authenticatorData[32] = 0x01 | 0x04 | 0x08;

    const signed = sha256(new Uint8Array([...authenticatorData, ...sha256(cdjBytes)]));
    const sig = p256.sign(signed, holderPrivateKey, { prehash: false });

    return {
      signature: sig.toBytes("compact"),
      unprotected: new Map<string, CborValue>([
        [
          "sovra_webauthn",
          new Map<string, CborValue>([
            ["authenticator_data", authenticatorData],
            ["client_data_json", cdjBytes],
            ["challenge_index", clientDataJson.indexOf('"challenge":')],
            ["type_index", clientDataJson.indexOf('"type":')],
          ]),
        ],
      ]),
    };
  },
};

async function present(
  signer: DeviceSigner = es256Signer,
  overrides: Partial<typeof handover> = {},
  disclose = ["member_name", "tier"],
) {
  const disclosed = parsed.items.filter(
    (i) => i.namespace !== parsed.docType || disclose.includes(i.elementIdentifier),
  );

  return buildDeviceResponse({
    parsed,
    disclosed,
    handover: { ...handover, ...overrides },
    signer,
  });
}

const offline = {
  ...handover,
  offlineMode: true,
  l2RpcUrl: "http://unused",
  didRegistryAddress: "0x0000000000000000000000000000000000000001",
  issuerRegistryAddress: "0x0000000000000000000000000000000000000002",
};

describe("wallet → SDK round trip", () => {
  it("accepts a raw ES256 presentation", async () => {
    const result = await verifyMdoc(await present(), offline);

    expect(result.error).toBeUndefined();
    expect(result.valid).toBe(true);
    // The registered type, as the SD-JWT path returns — the docType is
    // reported separately rather than in its place.
    expect(result.credentialType).toBe(fixture.credentialType);
    expect(result.docType).toBe(fixture.docType);
    expect(result.holder).toBe(fixture.holderDid);
    // Namespace-qualified, matching the backend — see `flattenClaims`.
    expect(result.claims?.[`${fixture.docType}.member_name`]).toBe("Ada Lovelace");
    expect(result.claims).not.toHaveProperty("member_name");
  });

  it("accepts the WebAuthn-wrapped presentation the wallet actually sends", async () => {
    // The envelope rides in the unsigned header; integrity comes from the
    // challenge binding. If that reasoning were wrong, this would fail.
    const result = await verifyMdoc(await present(webAuthnSigner), offline);

    expect(result.error).toBeUndefined();
    expect(result.valid).toBe(true);
  });

  it("does not leak the Sovra meta namespace into claims", async () => {
    const result = await verifyMdoc(await present(), offline);

    for (const element of ["holder_did", "status_list_index", "credential_type"]) {
      expect(result.claims).not.toHaveProperty(element);
      expect(result.claims).not.toHaveProperty(`io.sovra.meta.1.${element}`);
    }
  });
});

describe("binding", () => {
  it("rejects a presentation bound to a different verifier", async () => {
    const vp = await present(es256Signer, { clientId: "verifier:someone-else" });
    const result = await verifyMdoc(vp, offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.DEVICE_AUTH_INVALID);
  });

  it("rejects a stale nonce", async () => {
    const vp = await present(es256Signer, { nonce: "a-nonce-from-an-older-request" });
    const result = await verifyMdoc(vp, offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.DEVICE_AUTH_INVALID);
  });

  it("rejects a presentation posted to a different response address", async () => {
    const vp = await present(es256Signer, { responseUri: "https://elsewhere.example/post" });
    const result = await verifyMdoc(vp, offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.DEVICE_AUTH_INVALID);
  });
});

describe("integrity", () => {
  it("rejects a tampered element", async () => {
    // issuerAuth still verifies — the signature covers the MSO, which covers
    // digests — so this has to be caught by re-hashing.
    const vp = await present();
    const response = decode(base64urlDecode(vp)) as CborMap;

    const document = (response.get("documents") as CborValue[])[0] as CborMap;
    const issuerSigned = document.get("issuerSigned") as CborMap;
    const nameSpaces = issuerSigned.get("nameSpaces") as CborMap;
    const items = nameSpaces.get(fixture.docType) as CborValue[];

    // Swap one item's bytes for a re-encoded copy with a different value.
    const first = items[0] as CborTagged;
    const inner = decode(first.value as Uint8Array) as CborMap;
    inner.set("elementValue", "Mallory");
    items[0] = new CborTagged(24, encode(inner));

    const result = await verifyMdoc(base64urlEncode(encode(response)), offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.MSO_DIGEST_MISMATCH);
  });

  it("rejects a presentation that omits a mandatory element", async () => {
    const vp = await present(es256Signer, {}, ["member_name"]);
    const result = await verifyMdoc(vp, offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.DISCLOSURE_MISMATCH);
  });

  it("rejects a presentation with no Sovra metadata", async () => {
    const vp = await present();
    const response = decode(base64urlDecode(vp)) as CborMap;

    const document = (response.get("documents") as CborValue[])[0] as CborMap;
    const issuerSigned = document.get("issuerSigned") as CborMap;
    (issuerSigned.get("nameSpaces") as CborMap).delete("io.sovra.meta.1");

    const result = await verifyMdoc(base64urlEncode(encode(response)), offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.MDOC_PARSE_ERROR);
  });
});

describe("malformed input", () => {
  it("rejects something that is not CBOR", async () => {
    const result = await verifyMdoc(base64urlEncode(new TextEncoder().encode("nope")), offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.MDOC_PARSE_ERROR);
  });

  it("rejects a docType that names no issuer", async () => {
    const vp = await present();
    const response = decode(base64urlDecode(vp)) as CborMap;
    const document = (response.get("documents") as CborValue[])[0] as CborMap;
    document.set("docType", "not.a.sovra.doctype");

    const result = await verifyMdoc(base64urlEncode(encode(response)), offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.DOCTYPE_MISMATCH);
  });

  // The docType is what selects the issuer's key, so its parse is a wire
  // contract shared with `Sovra.Mdoc.DocType.issuer_address/1`. These pin the
  // two properties that keep the parse from being redirected.
  it("rejects a mixed-case issuer address", async () => {
    // `build/2` only ever emits lowercase, so this docType was never issued.
    const upper = fixture.docType.replace(/0x[0-9a-f]+/, (a) => a.toUpperCase());
    const result = await verifyMdoc(await presentWithDocType(upper), offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.DOCTYPE_MISMATCH);
  });

  it("rejects a docType that names an issuer but no schema", async () => {
    const address = fixture.docType.split(".")[2];
    const result = await verifyMdoc(await presentWithDocType(`io.sovra.${address}`), offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.DOCTYPE_MISMATCH);
  });
});

async function presentWithDocType(docType: string): Promise<string> {
  const response = decode(base64urlDecode(await present())) as CborMap;
  const document = (response.get("documents") as CborValue[])[0] as CborMap;
  document.set("docType", docType);

  return base64urlEncode(encode(response));
}

describe("issuer signature (online path)", () => {
  it("verifies against the issuer key the fixture was signed with", async () => {
    // Offline mode skips this, so exercise the construction directly: it is
    // where the SDK's Sig_structure has to match the backend's.
    const { sig1ToBeSigned, sign1Alg } = await import("@sovrahq/holder-core/cose");

    expect(sign1Alg(parsed.issuerAuth)).toBe(COSE_ALG.ES256);

    const toBeSigned = sig1ToBeSigned(
      parsed.issuerAuth.protectedBytes,
      new Uint8Array(),
      parsed.issuerAuth.payload!,
    );

    const ok = p256.verify(
      parsed.issuerAuth.signature,
      sha256(toBeSigned),
      new Uint8Array([
        4,
        ...hexToBytes(fixture.issuerPublicKey.x),
        ...hexToBytes(fixture.issuerPublicKey.y),
      ]),
      { prehash: false },
    );

    expect(ok).toBe(true);
  });
});

describe("malformed deviceSigned", () => {
  it("returns a result rather than throwing when nameSpaces is absent", async () => {
    // `verifyDeviceAuth` encodes this value, and an unencodable one used to
    // throw a CborError past verifyMdoc's promise to return a result.
    const response = decode(base64urlDecode(await present())) as CborMap;
    const document = (response.get("documents") as CborValue[])[0] as CborMap;
    (document.get("deviceSigned") as CborMap).delete("nameSpaces");

    const result = await verifyMdoc(base64urlEncode(encode(response)), offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.MDOC_PARSE_ERROR);
  });

  it("rejects nameSpaces that is not embedded CBOR", async () => {
    const response = decode(base64urlDecode(await present())) as CborMap;
    const document = (response.get("documents") as CborValue[])[0] as CborMap;
    (document.get("deviceSigned") as CborMap).set("nameSpaces", new Map());

    const result = await verifyMdoc(base64urlEncode(encode(response)), offline);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.MDOC_PARSE_ERROR);
  });
});
