import { describe, expect, it } from "vitest";
import {
  CBOR_TAG,
  CborError,
  CborTagged,
  decode,
  embed,
  encode,
  fullDate,
  unwrapEmbedded,
  type CborMap,
  type CborValue,
} from "../src/cbor/index";

const hex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const fromHex = (s: string) =>
  new Uint8Array((s.match(/../g) ?? []).map((h) => parseInt(h, 16)));

const map = (entries: [number | string, CborValue][]): CborMap => new Map(entries);

describe("encode — RFC 8949 Appendix A vectors", () => {
  it("encodes unsigned integers in shortest form", () => {
    expect(hex(encode(0))).toBe("00");
    expect(hex(encode(1))).toBe("01");
    expect(hex(encode(10))).toBe("0a");
    expect(hex(encode(23))).toBe("17");
    expect(hex(encode(24))).toBe("1818");
    expect(hex(encode(100))).toBe("1864");
    expect(hex(encode(1000))).toBe("1903e8");
    expect(hex(encode(1000000))).toBe("1a000f4240");
    expect(hex(encode(1000000000000n))).toBe("1b000000e8d4a51000");
  });

  it("encodes negative integers", () => {
    expect(hex(encode(-1))).toBe("20");
    expect(hex(encode(-10))).toBe("29");
    expect(hex(encode(-100))).toBe("3863");
    expect(hex(encode(-1000))).toBe("3903e7");
  });

  it("encodes byte and text strings", () => {
    expect(hex(encode(new Uint8Array()))).toBe("40");
    expect(hex(encode(new Uint8Array([1, 2, 3, 4])))).toBe("4401020304");
    expect(hex(encode(""))).toBe("60");
    expect(hex(encode("a"))).toBe("6161");
    expect(hex(encode("IETF"))).toBe("6449455446");
    expect(hex(encode('"\\'))).toBe("62225c");
  });

  it("encodes arrays and maps", () => {
    expect(hex(encode([]))).toBe("80");
    expect(hex(encode([1, 2, 3]))).toBe("83010203");
    expect(hex(encode([1, [2, 3], [4, 5]]))).toBe("8301820203820405");
    expect(hex(encode(map([])))).toBe("a0");
    expect(hex(encode(map([[1, 2], [3, 4]])))).toBe("a201020304");
    expect(hex(encode(map([["a", 1], ["b", [2, 3]]])))).toBe("a26161016162820203");
    expect(hex(encode(["a", map([["b", "c"]])]))).toBe("826161a161626163");
  });

  it("encodes simple values and tags", () => {
    expect(hex(encode(false))).toBe("f4");
    expect(hex(encode(true))).toBe("f5");
    expect(hex(encode(null))).toBe("f6");
    expect(hex(encode(fullDate("2026-08-25")))).toBe("d903ec6a323032362d30382d3235");
  });
});

describe("encode — deterministic map ordering", () => {
  it("sorts text keys shortest-first, then bytewise", () => {
    // "a" -> 6161, "b" -> 6162, "bb" -> 626262, "aaa" -> 63616161.
    const encoded = encode(map([["bb", 2], ["a", 1], ["b", 3], ["aaa", 4]]));
    expect(hex(encoded)).toBe("a4" + "616101" + "616203" + "62626202" + "6361616104");
  });

  it("does not depend on insertion order", () => {
    const pairs: [string, number][] = Array.from({ length: 64 }, (_, i) => [`key${i}`, i]);
    const forward = encode(new Map(pairs));
    const reverse = encode(new Map([...pairs].reverse()));
    expect(hex(forward)).toBe(hex(reverse));
  });

  it("sorts integer keys by encoded form, not numeric value", () => {
    // COSE_Key labels: 1 -> 01, -1 -> 20, -2 -> 21, -3 -> 22.
    const encoded = encode(
      map([[1, 2], [-1, 1], [-2, new Uint8Array([0xaa])], [-3, new Uint8Array([0xbb])]]),
    );
    expect(hex(encoded)).toBe("a4" + "0102" + "2001" + "2141aa" + "2241bb");
  });
});

describe("cross-language vectors", () => {
  // These MUST match Sovra.Cbor byte for byte. The SessionTranscript is built
  // independently on each side and then signed, so a divergence here surfaces
  // only as an opaque signature failure. Any diff to these strings is a
  // deliberate, reviewed protocol change — not a test to update.
  const vectors: [string, CborValue, string][] = [
    ["empty map", map([]), "a0"],
    ["COSE protected header {1: -7}", map([[1, -7]]), "a10126"],
    [
      "COSE_Key label ordering",
      map([[1, 2], [-1, 1], [-2, new Uint8Array(32).fill(0xab)], [-3, new Uint8Array(32).fill(0xcd)]]),
      "a401022001215820" +
        "ab".repeat(32) +
        "225820" +
        "cd".repeat(32),
    ],
    [
      "IssuerSignedItem",
      map([
        ["digestID", 7],
        ["random", new Uint8Array(16).fill(0x11)],
        ["elementIdentifier", "given_name"],
        ["elementValue", "Ada"],
      ]),
      "a4" +
        "6672616e646f6d50" +
        "11".repeat(16) +
        "68646967657374494407" +
        "6c656c656d656e7456616c756563416461" +
        "71656c656d656e744964656e7469666965726a676976656e5f6e616d65",
    ],
    ["embedded CBOR", embed([1, 2]), "d81843820102"],
    ["full-date", fullDate("2026-08-25"), "d903ec6a323032362d30382d3235"],
    [
      "SessionTranscript skeleton",
      [null, null, ["OpenID4VPHandover", new Uint8Array(32)]],
      // 83 f6 f6 | 82 | 71 = tstr(17) "OpenID4VPHandover" | 5820 = bstr(32)
      "83f6f682" + "71" + "4f70656e494434565048616e646f766572" + "5820" + "00".repeat(32),
    ],
  ];

  it.each(vectors)("%s", (_name, value, expected) => {
    expect(hex(encode(value))).toBe(expected);
  });
});

describe("embed / unwrapEmbedded", () => {
  it("round-trips the inner bytes verbatim", () => {
    const item = map([["digestID", 7], ["elementIdentifier", "given_name"]]);
    const inner = encode(item);

    const decoded = decode(encode(embed(item)));
    expect(unwrapEmbedded(decoded)).toEqual(inner);
  });

  it("does not auto-decode tag 24 — bytes survive a round trip", () => {
    // The whole point: encode(decode(x)) === x for a tag-24 wrapper, which is
    // what keeps MSO digests valid.
    const wrapped = encode(embed(map([["a", 1]])));
    expect(hex(encode(decode(wrapped)))).toBe(hex(wrapped));
  });

  it("returns null for anything that is not a tag-24 wrapper", () => {
    expect(unwrapEmbedded("plain")).toBeNull();
    expect(unwrapEmbedded(new CborTagged(CBOR_TAG.DATE_TIME, "2026-08-25"))).toBeNull();
  });
});

describe("encode — rejections", () => {
  it("rejects floats", () => {
    expect(() => encode(1.5)).toThrow(CborError);
  });

  it("rejects undefined and unsupported objects", () => {
    expect(() => encode(undefined as unknown as CborValue)).toThrow(CborError);
    expect(() => encode(new Date() as unknown as CborValue)).toThrow(CborError);
  });

  it("rejects unsafe integers, steering callers to bigint", () => {
    expect(() => encode(Number.MAX_SAFE_INTEGER + 2)).toThrow(/bigint/);
  });
});

describe("decode", () => {
  it("round-trips the structures mDoc uses", () => {
    const value = map([
      ["version", "1.0"],
      ["digestAlgorithm", "SHA-256"],
      ["valueDigests", map([["io.sovra.meta.1", map([[0, new Uint8Array(32).fill(7)]])]])],
      ["flag", true],
      ["absent", null],
      ["items", [1, -1, "x"]],
    ]);

    expect(hex(encode(decode(encode(value))))).toBe(hex(encode(value)));
  });

  it("returns tags unconverted", () => {
    const decoded = decode(encode(fullDate("2026-08-25")));
    expect(decoded).toBeInstanceOf(CborTagged);
    expect((decoded as CborTagged).tag).toBe(CBOR_TAG.FULL_DATE);
    expect((decoded as CborTagged).value).toBe("2026-08-25");
  });

  it("rejects trailing bytes", () => {
    expect(() => decode(fromHex("01ff"))).toThrow(/trailing/);
  });

  it("rejects a container claiming more items than the input holds", () => {
    // 83 01 — an array of 3 with one element present. Caught before allocating.
    expect(() => decode(fromHex("830102").subarray(0, 2))).toThrow(/longer than the remaining/);
  });

  it("rejects input truncated mid-item", () => {
    // 43 01 02 — a 3-byte string with only 2 bytes following.
    expect(() => decode(fromHex("430102"))).toThrow(CborError);
    // 1a 00 0f — a 4-byte argument with only 2 bytes following.
    expect(() => decode(fromHex("1a000f"))).toThrow(/truncated/);
  });

  it("rejects indefinite-length items", () => {
    // 0x9f = indefinite-length array.
    expect(() => decode(fromHex("9f01ff"))).toThrow(/indefinite/);
  });

  it("rejects duplicate map keys", () => {
    // a2 6161 01 6161 02 — {"a": 1, "a": 2}
    expect(() => decode(fromHex("a2616101616102"))).toThrow(/duplicate/);
  });

  it("rejects input past the size cap", () => {
    expect(() => decode(new Uint8Array(100), { maxBytes: 10 })).toThrow(/exceeds/);
  });

  it("rejects nesting past the depth cap", () => {
    let value: CborValue = 1;
    for (let i = 0; i < 10; i++) value = [value];
    expect(() => decode(encode(value), { maxDepth: 4 })).toThrow(/nesting/);
  });

  it("rejects floats and undefined on the wire", () => {
    expect(() => decode(fromHex("f97e00"))).toThrow(CborError); // NaN
    expect(() => decode(fromHex("f7"))).toThrow(CborError); // undefined
  });

  it("copies byte strings so callers cannot mutate the input buffer", () => {
    const input = fromHex("43010203");
    const decoded = decode(input) as Uint8Array;
    decoded[0] = 0xff;
    expect(input[1]).toBe(0x01);
  });
});
