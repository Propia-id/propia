import { describe, it, expect } from "vitest";
import { VerificationCache } from "../src/cache";

describe("VerificationCache", () => {
  it("evicts oldest issuer key entry when cache exceeds max size", () => {
    const cache = new VerificationCache();
    const dummyKey = {
      pubKeyX: new Uint8Array(32),
      pubKeyY: new Uint8Array(32),
      versionId: 1,
    };

    // Fill with 200 entries (max size)
    for (let i = 0; i < 200; i++) {
      cache.setIssuerKeys(`0x${i.toString(16).padStart(40, "0")}`, dummyKey);
    }

    // First entry should still exist
    expect(cache.getIssuerKeys("0x" + "0".padStart(40, "0"))).not.toBeNull();

    // Adding one more should evict the oldest
    cache.setIssuerKeys("0x" + "ff".padStart(40, "f"), dummyKey);
    expect(cache.getIssuerKeys("0x" + "0".padStart(40, "0"))).toBeNull();
  });

  it("evicts oldest holder key entry when cache exceeds max size", () => {
    const cache = new VerificationCache();
    const dummyKey = {
      passkeyX: new Uint8Array(32),
      passkeyY: new Uint8Array(32),
      recoveryKeyX: new Uint8Array(32),
      recoveryKeyY: new Uint8Array(32),
      versionId: 1,
    };

    for (let i = 0; i < 200; i++) {
      cache.setHolderKeys(`0x${i.toString(16).padStart(40, "0")}`, dummyKey);
    }

    cache.setHolderKeys("0x" + "ff".padStart(40, "f"), dummyKey);
    expect(cache.getHolderKeys("0x" + "0".padStart(40, "0"))).toBeNull();
  });

  it("evicts oldest trust entry when cache exceeds max size", () => {
    const cache = new VerificationCache();

    for (let i = 0; i < 200; i++) {
      cache.setIssuerTrust(`0x${i.toString(16).padStart(40, "0")}`, "type1", true);
    }

    cache.setIssuerTrust("0x" + "ff".padStart(40, "f"), "type1", true);
    expect(cache.getIssuerTrust("0x" + "0".padStart(40, "0"), "type1")).toBeNull();
  });
});
