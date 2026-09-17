import { describe, expect, it } from "vitest";
import fixture from "./fixtures/mdoc-issuer-signed.json";
import {
  buildDeviceResponse,
  parseIssuerSigned,
  sessionTranscript,
  type DeviceSigner,
} from "../src/mdoc/index";
import {
  CborTagged,
  decode,
  encode,
  unwrapEmbedded,
  type CborMap,
  type CborValue,
} from "../src/cbor/index";
import { COSE_ALG, parseSign1, sig1ToBeSigned, sign1Alg } from "../src/cose/index";
import { base64urlDecode } from "../src/utils/index";

const parsed = parseIssuerSigned(fixture.issuerSigned);

const handover = {
  clientId: "verifier:018f4a1c-0000-7000-8000-000000000001",
  nonce: "n-0S6_WzA2Mj",
  responseUri: "https://api.sovra.io/wallet/verifier/direct_post/abc",
};

/** Records what it was asked to sign, so the transcript binding can be asserted. */
function stubSigner(): DeviceSigner & { seen: Uint8Array[] } {
  const seen: Uint8Array[] = [];
  return {
    seen,
    coseAlg: COSE_ALG.SOVRA_WEBAUTHN_P256,
    async signCose(toBeSigned) {
      seen.push(toBeSigned);
      return { signature: new Uint8Array(64).fill(0xab), unprotected: new Map() };
    },
  };
}

async function present(elementIds: string[]) {
  const signer = stubSigner();
  const disclosed = parsed.items.filter((i) => elementIds.includes(i.elementIdentifier));
  const b64 = await buildDeviceResponse({ parsed, disclosed, handover, signer });
  return { signer, response: decode(base64urlDecode(b64)) as CborMap };
}

function document(response: CborMap): CborMap {
  const documents = response.get("documents") as CborValue[];
  return documents[0] as CborMap;
}

function disclosedIds(response: CborMap): string[] {
  const issuerSigned = document(response).get("issuerSigned") as CborMap;
  const nameSpaces = issuerSigned.get("nameSpaces") as CborMap;

  const ids: string[] = [];
  for (const items of nameSpaces.values()) {
    for (const tagged of items as CborValue[]) {
      const item = decode(unwrapEmbedded(tagged)!) as CborMap;
      ids.push(String(item.get("elementIdentifier")));
    }
  }
  return ids.sort();
}

describe("DeviceResponse structure", () => {
  it("wraps one document with an OK status", async () => {
    const { response } = await present(["member_name"]);

    expect(response.get("version")).toBe("1.0");
    expect(response.get("status")).toBe(0);
    expect((response.get("documents") as CborValue[]).length).toBe(1);
    expect(document(response).get("docType")).toBe(fixture.docType);
  });

  it("discloses only the selected elements", async () => {
    // Selective disclosure is subtractive: withholding an element just omits
    // its bytes, and the issuer's signature over the digests is untouched.
    const { response } = await present(["member_name"]);
    expect(disclosedIds(response)).toEqual(["member_name"]);
  });

  it("passes issuer-signed item bytes through verbatim", async () => {
    // Re-encoding a decoded item would change the bytes the MSO digests cover
    // and invalidate an otherwise valid credential.
    const { response } = await present(["member_name", "tier"]);
    const nameSpaces = (document(response).get("issuerSigned") as CborMap).get(
      "nameSpaces",
    ) as CborMap;

    const emitted = (nameSpaces.get(fixture.docType) as CborValue[]).map((t) =>
      encode(t as CborTagged),
    );
    const original = parsed.items
      .filter((i) => ["member_name", "tier"].includes(i.elementIdentifier))
      .map((i) => i.raw);

    for (const bytes of original) {
      expect(emitted.some((e) => e.length === bytes.length && e.every((b, j) => b === bytes[j])))
        .toBe(true);
    }
  });

  it("keeps issuerAuth exactly as the issuer signed it", async () => {
    const { response } = await present(["member_name"]);
    const issuerAuth = (document(response).get("issuerSigned") as CborMap).get("issuerAuth");
    const round = parseSign1(issuerAuth as CborValue);

    expect(round.signature).toEqual(parsed.issuerAuth.signature);
    expect(round.protectedBytes).toEqual(parsed.issuerAuth.protectedBytes);
    expect(round.payload).toEqual(parsed.issuerAuth.payload);
  });
});

describe("device authentication", () => {
  it("signs over the session transcript, detached", async () => {
    const { signer, response } = await present(["member_name"]);

    const deviceSigned = document(response).get("deviceSigned") as CborMap;
    const deviceAuth = deviceSigned.get("deviceAuth") as CborMap;
    const sign1 = parseSign1(deviceAuth.get("deviceSignature") as CborValue);

    // Nothing on the wire — the verifier rebuilds what was covered.
    expect(sign1.payload).toBeNull();
    expect(sign1Alg(sign1)).toBe(COSE_ALG.SOVRA_WEBAUTHN_P256);

    const expected = sig1ToBeSigned(
      sign1.protectedBytes,
      new Uint8Array(),
      encode(
        new CborTagged(
          24,
          encode([
            "DeviceAuthentication",
            sessionTranscript(handover),
            fixture.docType,
            deviceSigned.get("nameSpaces") as CborValue,
          ]),
        ),
      ),
    );

    expect(signer.seen[0]).toEqual(expected);
  });

  it("asserts no device-supplied namespaces", async () => {
    // Anything here would be holder-asserted data with no issuer signature
    // behind it, which a verifier has no basis to trust.
    const { response } = await present(["member_name"]);
    const deviceSigned = document(response).get("deviceSigned") as CborMap;

    const inner = unwrapEmbedded(deviceSigned.get("nameSpaces") as CborValue);
    expect(inner).toBeDefined();
    expect((decode(inner!) as CborMap).size).toBe(0);
  });

  it("binds to this verifier, so a response cannot be replayed elsewhere", async () => {
    const a = stubSigner();
    const b = stubSigner();
    const disclosed = parsed.items.filter((i) => i.elementIdentifier === "member_name");

    await buildDeviceResponse({ parsed, disclosed, handover, signer: a });
    await buildDeviceResponse({
      parsed,
      disclosed,
      handover: { ...handover, clientId: "verifier:someone-else" },
      signer: b,
    });

    expect(a.seen[0]).not.toEqual(b.seen[0]);
  });
});
