import { describe, expect, it } from "vitest";
import fixture from "./fixtures/mdoc-issuer-signed.json";
import {
  claimKeyFor,
  displayValue,
  flattenClaims,
  parseIssuerSigned,
  SOVRA_META_NAMESPACE,
} from "../src/mdoc/index";
import { CborTagged, CBOR_TAG, decode, encode, unwrapEmbedded } from "../src/cbor/index";
import { sig1ToBeSigned, sign1Alg } from "../src/cose/index";
import { hexToBytes, sha256 } from "../src/utils/index";
import { p256 } from "@noble/curves/p256";

// The fixture was produced by the backend's Sovra.Issuer.Mdoc, not written to
// match this parser. That is the point: it pins the wire contract between the
// two implementations, and a change to either side that breaks the other shows
// up here rather than as an unexplained verification failure in the field.
const parsed = parseIssuerSigned(fixture.issuerSigned);

describe("parseIssuerSigned", () => {
  it("reads the docType out of the signed MSO", () => {
    // Not from a wrapper: a credential must not be able to claim one type
    // while being signed as another.
    expect(parsed.docType).toBe(fixture.docType);
    expect(String(parsed.mso.get("docType"))).toBe(fixture.docType);
  });

  it("finds every element the issuer put in", () => {
    const ids = parsed.items
      .filter((i) => i.namespace === fixture.docType)
      .map((i) => i.elementIdentifier)
      .sort();

    expect(ids).toEqual(["joined_on", "member_name", "tier", "visits"]);
  });

  it("carries the Sovra meta namespace alongside the schema one", () => {
    const namespaces = [...new Set(parsed.items.map((i) => i.namespace))].sort();
    expect(namespaces).toEqual([SOVRA_META_NAMESPACE, fixture.docType].sort());
  });

  it("recovers the holder DID an mdoc otherwise has nowhere to put", () => {
    expect(parsed.holderDid).toBe(fixture.holderDid);
  });

  it("recovers the mandatory element set frozen at issuance", () => {
    expect(parsed.mandatoryElements).toEqual(fixture.mandatoryElements);
  });

  it("reads validity from the MSO", () => {
    const signedAt = Math.floor(Date.parse(fixture.signedAt) / 1000);
    expect(parsed.validFrom).toBe(signedAt);
    expect(parsed.validUntil - parsed.validFrom).toBe(365 * 86400);
  });
});

describe("issuer signature and digests", () => {
  it("verifies against the issuer's public key", () => {
    // Proves the TypeScript Sig_structure construction matches the Elixir one
    // byte for byte — the thing that silently breaks everything if it drifts.
    expect(sign1Alg(parsed.issuerAuth)).toBe(-7);

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

  it("every element digest matches the MSO", () => {
    // The digest covers the whole tag-24 wrapper, not the inner item. Getting
    // this wrong yields credentials that look right and verify nowhere.
    const valueDigests = parsed.mso.get("valueDigests") as Map<string, Map<number, Uint8Array>>;

    for (const item of parsed.items) {
      const expected = valueDigests.get(item.namespace)?.get(item.digestId);
      expect(expected, `no digest for ${item.elementIdentifier}`).toBeDefined();
      expect(sha256(item.raw), `digest mismatch for ${item.elementIdentifier}`).toEqual(expected);
    }
  });

  it("keeps item bytes verbatim rather than re-encoding", () => {
    // Re-deriving the wrapper from the decoded item must reproduce the same
    // bytes, or the digests above would be checking the wrong thing.
    for (const item of parsed.items) {
      const inner = unwrapEmbedded(decode(item.raw));
      expect(inner).toBeDefined();
      expect(encode(new CborTagged(CBOR_TAG.EMBEDDED, inner!))).toEqual(item.raw);
    }
  });
});

describe("flattenClaims", () => {
  const claims = flattenClaims(parsed.items, parsed.docType);

  it("drops the Sovra meta namespace", () => {
    // Plumbing with nothing to render — a holder should never see their own
    // status list index on a card.
    expect(claims).not.toHaveProperty("holder_did");
    expect(claims).not.toHaveProperty("status_list_index");
    expect(claims).not.toHaveProperty("mandatory_elements");
  });

  it("leaves the credential's own namespace unqualified", () => {
    expect(Object.keys(claims).sort()).toEqual([
      "joined_on",
      "member_name",
      "tier",
      "visits",
    ]);
    expect(claims.member_name).toBe("Ada Lovelace");
    expect(claims.visits).toBe(12);
  });

  it("renders a tagged full-date as its string, not as a tag object", () => {
    expect(claims.joined_on).toBe("2026-01-15");
  });

  it("is JSON-encodable, since it is persisted in the credential index", () => {
    expect(() => JSON.stringify(claims)).not.toThrow();
  });
});

describe("claimKeyFor", () => {
  const item = {
    namespace: "org.iso.18013.5.1",
    digestId: 1,
    elementIdentifier: "given_name",
    elementValue: null,
    raw: new Uint8Array(),
  };

  it("qualifies elements from a namespace other than the docType", () => {
    // ISO permits several namespaces per document and a real mDL has two, so
    // the common single-namespace case must not bake in an assumption that
    // collides later.
    expect(claimKeyFor(item, "org.iso.18013.5.1.mDL")).toBe("org.iso.18013.5.1.given_name");
    expect(claimKeyFor(item, "org.iso.18013.5.1")).toBe("given_name");
  });
});

describe("displayValue", () => {
  it("reduces byte strings to a descriptor", () => {
    // A portrait left as raw bytes would reach JSON.stringify in the card
    // renderer and the search index as a 20,000-character array.
    const portrait = new Uint8Array(4096).fill(0xff);
    portrait.set([0xff, 0xd8, 0xff, 0xe0], 0);

    expect(displayValue(portrait)).toEqual({ __bytes: 4096, __preview: "ffd8ffe0" });
  });

  it("unwraps date tags to their string form", () => {
    expect(displayValue(new CborTagged(CBOR_TAG.FULL_DATE, "2026-01-15"))).toBe("2026-01-15");
    expect(displayValue(new CborTagged(CBOR_TAG.DATE_TIME, "2026-01-15T00:00:00Z"))).toBe(
      "2026-01-15T00:00:00Z",
    );
  });

  it("renders maps and arrays recursively", () => {
    const privileges = [new Map<string, unknown>([["vehicle_category_code", "B"]])];
    expect(displayValue(privileges as never)).toEqual([{ vehicle_category_code: "B" }]);
  });

  it("stringifies bigints so JSON.stringify cannot throw", () => {
    expect(displayValue(2n ** 64n)).toBe("18446744073709551616");
  });
});
