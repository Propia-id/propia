/**
 * The two ISO element types a renderer cannot handle generically: a
 * byte-string portrait and a structured `driving_privileges` array.
 *
 * Both are answered here rather than in the wallet because both are questions
 * about the format — which element holds the photograph, where its bytes live,
 * what kind of image they are, and whether a given value is a privileges array
 * at all. How a screen lays any of it out is not.
 */

import { describe, expect, it } from "vitest";

import { encode, embed, CborTagged } from "../src/cbor/index";
import {
  displayValue,
  drivingPrivilegeCategories,
  isBytesDescriptor,
  ISO_MDL_NAMESPACE,
  portraitDataUri,
  readElementBytes,
} from "../src/mdoc/index";
import { base64urlEncode } from "../src/utils/index";

const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46]);
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const JP2 = new Uint8Array([0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20]);

/**
 * An `IssuerSigned` carrying the given elements.
 *
 * Hand-built rather than issued: what is under test is reading elements back
 * out, and no signature is checked on this path. The MSO is still real, because
 * `parseIssuerSigned` decodes one — a stub that skipped it would be testing a
 * parse the wallet never performs.
 */
function issuerSigned(elements: Array<[string, unknown]>, namespace = ISO_MDL_NAMESPACE): string {
  const items = elements.map(([elementIdentifier, elementValue], index) =>
    embed(
      new Map<string, unknown>([
        ["digestID", index + 1],
        ["random", new Uint8Array(16)],
        ["elementIdentifier", elementIdentifier],
        ["elementValue", elementValue],
      ]),
    ),
  );

  const mso = new Map<string, unknown>([
    ["version", "1.0"],
    ["digestAlgorithm", "SHA-256"],
    ["valueDigests", new Map()],
    ["docType", "org.iso.18013.5.1.mDL"],
    [
      "validityInfo",
      new Map<string, unknown>([
        ["signed", new CborTagged(0, "2026-01-01T00:00:00Z")],
        ["validFrom", new CborTagged(0, "2026-01-01T00:00:00Z")],
        ["validUntil", new CborTagged(0, "2027-01-01T00:00:00Z")],
      ]),
    ],
  ]);

  return base64urlEncode(
    encode(
      new Map<string, unknown>([
        ["nameSpaces", new Map([[namespace, items]])],
        [
          "issuerAuth",
          [new Uint8Array(), new Map(), encode(embed(mso)), new Uint8Array(64)],
        ],
      ]),
    ),
  );
}

describe("reading a byte-string element back out", () => {
  it("returns the bytes the issuer put in", () => {
    const credential = issuerSigned([["portrait", JPEG]]);

    expect(readElementBytes(credential, ISO_MDL_NAMESPACE, "portrait")).toEqual(JPEG);
  });

  it("returns null for an element in a different namespace", () => {
    // Element identifiers are only unique within a namespace, so the namespace
    // is part of the question and not a hint.
    const credential = issuerSigned([["portrait", JPEG]]);

    expect(readElementBytes(credential, "org.iso.18013.5.1.aamva", "portrait")).toBeNull();
  });

  it("returns null for an element that is not a byte string", () => {
    const credential = issuerSigned([["family_name", "Lovelace"]]);

    expect(readElementBytes(credential, ISO_MDL_NAMESPACE, "family_name")).toBeNull();
  });

  it("leaves a descriptor in the flattened claims, not the bytes", () => {
    // A portrait is tens of kilobytes and `claims` is re-serialised to secure
    // storage on every write. The descriptor is what makes that cheap, and
    // `isBytesDescriptor` is how a renderer knows to go and fetch the real
    // thing.
    const value = displayValue(JPEG);

    expect(isBytesDescriptor(value)).toBe(true);
    expect(value).toMatchObject({ __bytes: 8 });
  });

  it("does not mistake an ordinary object for a descriptor", () => {
    expect(isBytesDescriptor({ __bytes: "8" })).toBe(false);
    expect(isBytesDescriptor({ vehicle_category_code: "B" })).toBe(false);
    expect(isBytesDescriptor(null)).toBe(false);
    expect(isBytesDescriptor("portrait")).toBe(false);
  });
});

describe("portraitDataUri", () => {
  it("builds a data URI a renderer can show directly", () => {
    const uri = portraitDataUri(issuerSigned([["portrait", JPEG]]));

    expect(uri).toBe(`data:image/jpeg;base64,${btoa(String.fromCharCode(...JPEG))}`);
  });

  it("reads the media type from the bytes, not from a declaration", () => {
    // ISO says JPEG or JPEG 2000. Issuers ship PNG anyway, and the magic number
    // is the only thing that is actually true about the bytes.
    expect(portraitDataUri(issuerSigned([["portrait", PNG]]))).toMatch(/^data:image\/png;/);
    expect(portraitDataUri(issuerSigned([["portrait", JP2]]))).toMatch(/^data:image\/jp2;/);
  });

  it("is undefined when the credential carries no portrait", () => {
    expect(portraitDataUri(issuerSigned([["family_name", "Lovelace"]]))).toBeUndefined();
  });

  it("is undefined rather than throwing on a credential it cannot parse", () => {
    // One unreadable credential must not take a whole screen down with it.
    expect(portraitDataUri("not-a-credential")).toBeUndefined();
  });

  it("is undefined for an empty portrait", () => {
    expect(portraitDataUri(issuerSigned([["portrait", new Uint8Array()]]))).toBeUndefined();
  });
});

describe("drivingPrivilegeCategories", () => {
  it("names the categories, in the order the credential lists them", () => {
    const value = displayValue([
      new Map<string, unknown>([
        ["vehicle_category_code", "A1"],
        ["issue_date", new CborTagged(1004, "2020-03-01")],
      ]),
      new Map<string, unknown>([["vehicle_category_code", "B"]]),
    ]);

    expect(drivingPrivilegeCategories(value)).toEqual(["A1", "B"]);
  });

  it("returns null for a value that is not a privileges array", () => {
    // The caller falls through to its generic rendering, so a false positive
    // here would mangle an unrelated claim.
    expect(drivingPrivilegeCategories("B")).toBeNull();
    expect(drivingPrivilegeCategories([])).toBeNull();
    expect(drivingPrivilegeCategories([{ code: "S01" }])).toBeNull();
    expect(drivingPrivilegeCategories(["B"])).toBeNull();
  });

  it("returns null when any entry is missing its category", () => {
    // Partial rendering would quietly drop a category the holder actually
    // holds, which on a driving licence is the whole content of the claim.
    expect(
      drivingPrivilegeCategories([
        { vehicle_category_code: "B" },
        { issue_date: "2020-03-01" },
      ]),
    ).toBeNull();
  });
});
