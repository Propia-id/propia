import { describe, it, expect } from "vitest";
import { decodeResolveResult, keccak256 } from "../src/utils/index";
import { encodeResolveResult } from "./fixtures";

const utf8 = (s: string) => new TextEncoder().encode(s);

const METHOD = {
  id: keccak256(utf8("key-assert")),
  keyType: 0,
  pubKeyX: new Uint8Array(32).fill(0x11),
  pubKeyY: new Uint8Array(32).fill(0x22),
  relationships: 2,
};

describe("decodeResolveResult services", () => {
  it("decodes every service endpoint, including endpoints longer than a word", () => {
    const services = [
      {
        id: keccak256(utf8("oid4vci")),
        serviceType: keccak256(utf8("OpenID4VCIIssuer")),
        endpoint: "https://api.sovra.example",
      },
      {
        id: keccak256(utf8("status")),
        serviceType: keccak256(utf8("CredentialStatusService")),
        endpoint: `https://status.example/${"a".repeat(80)}/ñandú`,
      },
    ];

    const decoded = decodeResolveResult(encodeResolveResult({ methods: [METHOD], services }));

    expect(decoded.methods).toHaveLength(1);
    expect(decoded.services).toEqual(services);
  });

  it("decodes a document that publishes no services", () => {
    const decoded = decodeResolveResult(encodeResolveResult({ methods: [METHOD] }));

    expect(decoded.services).toEqual([]);
  });

  it("throws on a response cut short inside a service endpoint", () => {
    const encoded = encodeResolveResult({
      methods: [METHOD],
      services: [
        {
          id: keccak256(utf8("oid4vci")),
          serviceType: keccak256(utf8("OpenID4VCIIssuer")),
          endpoint: "https://api.sovra.example/some/long/path/segment",
        },
      ],
    });

    expect(() => decodeResolveResult(encoded.slice(0, -64))).toThrow(/ends inside service 0/);
  });
});
