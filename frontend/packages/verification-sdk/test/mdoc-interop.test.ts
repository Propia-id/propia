/**
 * Cross-implementation interop, against `@animo-id/mdoc`.
 *
 * Every other mdoc test here checks our code against our code. The CBOR vectors
 * prove Elixir and TypeScript agree with *each other*; the round trip proves our
 * wallet and our verifier agree. None of that can catch a misreading of the
 * standard we made consistently in both places — which is the expensive class of
 * bug, because it surfaces as an unexplained signature failure against a real
 * wallet rather than as a failing test.
 *
 * So this file crosses the boundary in both directions, using an implementation
 * written by people who have never seen ours:
 *
 *   1. their issuer → our reader: they build an `IssuerSigned`; we verify the
 *      MSO signature and re-hash every element against `valueDigests`.
 *   2. our issuer → their reader: they parse our committed fixture, rebuild the
 *      `Sig_structure` with their own code, and run their own digest check.
 *
 * Deliberately scoped to the issuer-signed half. Device authentication is bound
 * to an OpenID4VP 1.0 session transcript and no external tool builds ours —
 * theirs follows ISO/IEC TS 18013-7 Annex B, which hashes an `mdocGeneratedNonce`
 * unencrypted `direct_post` has nowhere to put. That half is covered by
 * `session-transcript.test.ts` and `mdoc-roundtrip.test.ts` instead.
 */

import { describe, expect, it } from "vitest";
import fixture from "@sovrahq/holder-core/test-fixtures/mdoc-issuer-signed.json";
import {
  Document,
  cborEncode,
  parseIssuerSigned as animoParseIssuerSigned,
  type IssuerSignedItem,
} from "@animo-id/mdoc";
import { parseIssuerSigned } from "@sovrahq/holder-core/mdoc";
import { COSE_ALG, sig1ToBeSigned, sign1Alg } from "@sovrahq/holder-core/cose";
import { decode, unwrapEmbedded, type CborMap } from "@sovrahq/holder-core/cbor";
import {
  base64urlDecode,
  base64urlEncode,
  bytesToHex,
  sha256,
} from "@sovrahq/holder-core/utils";
import { p256 } from "@noble/curves/p256";

import { verifyP256Raw } from "../src/signature.js";

const DOC_TYPE = "io.sovra.0xab34cd09f900112233445566778899aabbccddee.interop.1";

// A fixed issuer key, so a failure is reproducible rather than one-in-a-run.
const ISSUER_PRIVATE_KEY = hexToKey(
  "5f1d3a9c2b8e47f06d915c3ea8724bd1f0396e58ac7241db90e5f6a3c82014d7",
);

function hexToKey(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
}

const issuerPublic = p256.getPublicKey(ISSUER_PRIVATE_KEY, false);
const issuerX = issuerPublic.slice(1, 33);
const issuerY = issuerPublic.slice(33, 65);

const issuerJwk = {
  kty: "EC",
  crv: "P-256",
  d: base64urlEncode(ISSUER_PRIVATE_KEY),
  x: base64urlEncode(issuerX),
  y: base64urlEncode(issuerY),
};

const holderJwk = {
  kty: "EC",
  crv: "P-256",
  x: fixture.holderPublicKey.x,
  y: fixture.holderPublicKey.y,
};

/**
 * The crypto their library needs injected. Ours, deliberately — what is under
 * test is their *structure* building against our reading of it, so sharing a
 * hash and a curve removes a variable rather than weakening the test.
 */
const ctx = {
  crypto: {
    random: (length: number) => sha256(new Uint8Array([length])).slice(0, length),
    digest: ({ digestAlgorithm, bytes }: { digestAlgorithm: string; bytes: Uint8Array }) => {
      if (digestAlgorithm !== "SHA-256") throw new Error(`unexpected ${digestAlgorithm}`);
      return sha256(bytes);
    },
    calculateEphemeralMacKeyJwk: () => {
      throw new Error("proximity MAC is out of scope");
    },
  },
  cose: {
    sign1: {
      sign: ({ sign1 }: { sign1: { getRawSigningData(): { data: Uint8Array } } }) =>
        p256
          .sign(sha256(sign1.getRawSigningData().data), ISSUER_PRIVATE_KEY, { prehash: false })
          .toBytes("compact"),
      verify: () => {
        throw new Error("verification is done with our own code, on purpose");
      },
    },
    mac0: {
      sign: () => {
        throw new Error("proximity MAC is out of scope");
      },
      verify: () => {
        throw new Error("proximity MAC is out of scope");
      },
    },
  },
} as never;

/** An `IssuerSigned` built entirely by their code, in the form ours ingests. */
async function issueWithAnimo(): Promise<string> {
  const doc = new Document(DOC_TYPE, ctx);

  doc.addIssuerNameSpace(DOC_TYPE, { tier: "gold", visits: 12, member_name: "Ada Lovelace" });
  doc.addDeviceKeyInfo({ deviceKey: holderJwk as never });
  doc.addValidityInfo({
    signed: new Date("2026-09-01T00:00:00Z"),
    validFrom: new Date("2026-09-01T00:00:00Z"),
    validUntil: new Date("2027-09-01T00:00:00Z"),
  });
  doc.useDigestAlgorithm("SHA-256");

  const signed = await doc.sign(
    {
      issuerPrivateKey: issuerJwk as never,
      // They put an x5chain in the unprotected header; we resolve issuers from
      // the signed docType and never read that header, so its contents are
      // irrelevant here. See `Sovra.Mdoc.IssuerTrust`.
      issuerCertificate: new Uint8Array([0x30, 0x00]),
      alg: "ES256",
    },
    ctx,
  );

  return base64urlEncode(cborEncode(signed.prepare().get("issuerSigned")));
}

describe("their issuer → our reader", () => {
  it("parses an IssuerSigned we did not build", async () => {
    const parsed = parseIssuerSigned(await issueWithAnimo());

    expect(parsed.docType).toBe(DOC_TYPE);
    expect(parsed.items.map((i) => i.elementIdentifier).sort()).toEqual([
      "member_name",
      "tier",
      "visits",
    ]);
  });

  it("agrees on the MSO structure the 2021 edition defines", async () => {
    const parsed = parseIssuerSigned(await issueWithAnimo());

    // The fields the 2020 draft gets wrong: it has no `version`, and carries a
    // bare `deviceKey` where the published edition nests it in `deviceKeyInfo`.
    // Two independent readings of the standard landing on the same six keys is
    // the assurance no amount of self-consistency could give.
    expect(parsed.mso.get("version")).toBe("1.0");
    expect(parsed.mso.get("digestAlgorithm")).toBe("SHA-256");
    expect(parsed.mso.get("docType")).toBe(DOC_TYPE);
    expect(parsed.mso.has("valueDigests")).toBe(true);
    expect(parsed.mso.has("validityInfo")).toBe(true);

    const deviceKeyInfo = parsed.mso.get("deviceKeyInfo") as CborMap;
    expect(deviceKeyInfo.has("deviceKey")).toBe(true);
  });

  it("verifies their MSO signature with our Sig_structure", async () => {
    const parsed = parseIssuerSigned(await issueWithAnimo());
    const { issuerAuth } = parsed;

    expect(sign1Alg(issuerAuth)).toBe(COSE_ALG.ES256);

    // Zero-length `external_aad`, protected header bytes verbatim. If their
    // Sig_structure and ours disagreed by a byte, this fails.
    const toBeSigned = sig1ToBeSigned(
      issuerAuth.protectedBytes,
      new Uint8Array(),
      issuerAuth.payload ?? new Uint8Array(),
    );

    expect(
      verifyP256Raw(issuerAuth.signature, sha256(toBeSigned), issuerX, issuerY, true),
    ).toBe(true);
  });

  it("re-hashes their elements to the digests they signed", async () => {
    const parsed = parseIssuerSigned(await issueWithAnimo());
    const valueDigests = parsed.mso.get("valueDigests") as CborMap;
    const namespaceDigests = valueDigests.get(DOC_TYPE) as CborMap;

    expect(parsed.items.length).toBeGreaterThan(0);

    for (const item of parsed.items) {
      const expected = namespaceDigests.get(item.digestId) as Uint8Array;

      // The tag-24 trap, checked across implementations: the digest covers the
      // whole `#6.24(bstr .cbor IssuerSignedItem)` wrapper, not the bare item.
      expect(expected, `no digest for ${item.elementIdentifier}`).toBeInstanceOf(Uint8Array);
      expect(bytesToHex(sha256(item.raw))).toBe(bytesToHex(expected));

      // And the wrong reading really is wrong — without this the assertion
      // above would still pass if both sides hashed the bare item.
      const inner = unwrapEmbedded(decode(item.raw));
      expect(inner).not.toBeNull();
      expect(bytesToHex(sha256(inner!))).not.toBe(bytesToHex(expected));
    }
  });

  it("salts every element with at least 16 bytes", async () => {
    // 18013-5 sets a floor, and it is the only thing stopping a digest from
    // being a guessable commitment to a low-entropy value.
    const parsed = parseIssuerSigned(await issueWithAnimo());

    expect(parsed.items.length).toBeGreaterThan(0);

    for (const item of parsed.items) {
      const inner = unwrapEmbedded(decode(item.raw));
      const decoded = decode(inner!) as CborMap;
      const random = decoded.get("random") as Uint8Array;

      expect(random).toBeInstanceOf(Uint8Array);
      expect(random.length).toBeGreaterThanOrEqual(16);
    }
  });
});

describe("our issuer → their reader", () => {
  const animoDoc = () =>
    animoParseIssuerSigned(base64urlDecode(fixture.issuerSigned), fixture.docType);

  it("parses the credential our backend issued", () => {
    const doc = animoDoc();

    expect(doc.docType).toBe(fixture.docType);
    expect(doc.issuerSignedNameSpaces).toContain(fixture.docType);
  });

  it("rebuilds our Sig_structure and verifies our signature", () => {
    const { issuerAuth } = animoDoc().issuerSigned;
    const { data, signature } = issuerAuth.getRawVerificationData();

    // `data` is *their* Sig_structure over our credential. Verifying it against
    // our issuer key proves the two constructions are byte-identical — the
    // thing our own tests structurally cannot check.
    expect(
      verifyP256Raw(
        signature,
        sha256(data),
        hexToKey(fixture.issuerPublicKey.x),
        hexToKey(fixture.issuerPublicKey.y),
        true,
      ),
    ).toBe(true);
  });

  it("runs their digest check over our elements", async () => {
    const doc = animoDoc();
    const { issuerAuth } = doc.issuerSigned;
    const items = doc.issuerSigned.nameSpaces.get(fixture.docType) as IssuerSignedItem[];

    expect(items?.length ?? 0).toBeGreaterThan(0);

    for (const item of items) {
      await expect(
        item.isValid(fixture.docType, issuerAuth, ctx),
        `their digest check rejected ${item.elementIdentifier}`,
      ).resolves.toBe(true);
    }
  });
});
