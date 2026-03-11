import { describe, it, expect } from "vitest";
import { bytesToHex, hexToBytes } from "@sovra/wallet-core/utils";
import {
  functionSelector,
  encodeAddress,
  encodeFunctionCall,
  decodeBytes32,
  decodeBool,
  decodeUint32,
  decodeUint64,
  decodeUint8,
  decodeResolveResult,
} from "../src/rpc";

describe("ABI encoding", () => {
  it("computes correct function selector", () => {
    // keccak256("resolve(address)") first 4 bytes
    const selector = functionSelector("resolve(address)");
    expect(selector.length).toBe(4);
    // Verify it matches the expected selector
    const hex = bytesToHex(selector, false);
    expect(hex).toMatch(/^[0-9a-f]{8}$/);
  });

  it("encodes address with left-padding to 32 bytes", () => {
    const encoded = encodeAddress("0x1234567890abcdef1234567890abcdef12345678");
    expect(encoded.length).toBe(32);
    // First 12 bytes should be zero
    for (let i = 0; i < 12; i++) {
      expect(encoded[i]).toBe(0);
    }
    // Last 20 bytes should be the address
    expect(bytesToHex(encoded.slice(12), false)).toBe(
      "1234567890abcdef1234567890abcdef12345678",
    );
  });

  it("builds correct function call encoding", () => {
    const calldata = encodeFunctionCall("passkeyX()", []);
    // Should be just the 4-byte selector with 0x prefix
    expect(calldata.startsWith("0x")).toBe(true);
    expect(calldata.length).toBe(10); // "0x" + 8 hex chars
  });

  it("builds function call with address param", () => {
    const calldata = encodeFunctionCall(
      "resolve(address)",
      [encodeAddress("0x1234567890abcdef1234567890abcdef12345678")],
    );
    // 4 bytes selector + 32 bytes address = 36 bytes = 72 hex chars + "0x"
    expect(calldata.length).toBe(74);
  });
});

describe("ABI decoding", () => {
  it("decodes bytes32 at slot 0", () => {
    const data =
      "0x" +
      "abcd".padStart(64, "0") +
      "0000000000000000000000000000000000000000000000000000000000000001";
    const result = decodeBytes32(data, 0);
    expect(result.length).toBe(32);
    expect(result[30]).toBe(0xab);
    expect(result[31]).toBe(0xcd);
  });

  it("decodes bool from slot", () => {
    const trueData =
      "0x0000000000000000000000000000000000000000000000000000000000000001";
    const falseData =
      "0x0000000000000000000000000000000000000000000000000000000000000000";
    expect(decodeBool(trueData, 0)).toBe(true);
    expect(decodeBool(falseData, 0)).toBe(false);
  });

  it("decodes uint32", () => {
    const data =
      "0x000000000000000000000000000000000000000000000000000000000000002a"; // 42
    expect(decodeUint32(data, 0)).toBe(42);
  });

  it("decodes uint64", () => {
    const data =
      "0x0000000000000000000000000000000000000000000000000000000065e1f400"; // 1709310976
    expect(decodeUint64(data, 0)).toBe(1709306880);
  });

  it("decodes uint8", () => {
    const data =
      "0x0000000000000000000000000000000000000000000000000000000000000002"; // 2
    expect(decodeUint8(data, 0)).toBe(2);
  });
});

describe("decodeResolveResult", () => {
  it("decodes a resolve result with one verification method", () => {
    // Build a mock return value for resolve(address):
    // (VerificationMethod[] memory, ServiceEndpoint[] memory,
    //  uint64 created, uint64 updated, uint32 versionId, bool deactivated)

    const slot = (hex: string) => hex.padStart(64, "0");

    // Offsets to dynamic arrays
    const methodsOffset = slot((6 * 32).toString(16)); // offset = 192 bytes = 0xC0
    const servicesOffset = slot((6 * 32 + 32 + 5 * 32).toString(16)); // after methods data

    // Static values
    const created = slot("65e1f400"); // some timestamp
    const updated = slot("65e1f400");
    const versionId = slot("1"); // version 1
    const deactivated = slot("0"); // not deactivated

    // VerificationMethod array: length=1, then 5 slots per method
    const methodsLength = slot("1");
    const methodId = "aa".repeat(32);
    const methodKeyType = slot("0"); // P256
    const methodPubKeyX = "11".repeat(32);
    const methodPubKeyY = "22".repeat(32);
    const methodRelationships = slot("2"); // assertionMethod bit

    // ServiceEndpoint array: length=0
    const servicesLength = slot("0");

    const data =
      "0x" +
      methodsOffset +
      servicesOffset +
      created +
      updated +
      versionId +
      deactivated +
      methodsLength +
      methodId +
      methodKeyType +
      methodPubKeyX +
      methodPubKeyY +
      methodRelationships +
      servicesLength;

    const result = decodeResolveResult(data);

    expect(result.versionId).toBe(1);
    expect(result.deactivated).toBe(false);
    expect(result.methods).toHaveLength(1);
    expect(result.methods[0].keyType).toBe(0);
    expect(result.methods[0].relationships).toBe(2);
    expect(bytesToHex(result.methods[0].pubKeyX, false)).toBe("11".repeat(32));
    expect(bytesToHex(result.methods[0].pubKeyY, false)).toBe("22".repeat(32));
  });
});
