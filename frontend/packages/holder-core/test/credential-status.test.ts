import { describe, expect, it, vi } from "vitest";
import fixture from "./fixtures/mdoc-issuer-signed.json";
import { CredentialManager } from "../src/credentials";
import { createCredentialStore } from "../src/state/index";
import {
  isStatusSet,
  readRegistryStatuses,
  readStatusBitmap,
  statusReference,
  STATUS_PURPOSE,
} from "../src/status/index";
import { bytesToHex, encodeFunctionCall } from "../src/utils/index";
import type { EthCall } from "../src/did/index";
import { mdocCredential, memoryStorage, sdJwtCredential } from "./fixtures";

const ISSUER = "0x00000000000000000000000000000000000000b2";
const OTHER_ISSUER = "0x00000000000000000000000000000000000000c3";
const REGISTRY = "0x00000000000000000000000000000000000000ee";

function b64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/** An SD-JWT whose issuer payload is `payload`. The signature is never checked here. */
function sdJwtWith(payload: Record<string, unknown>): string {
  return `${b64u({ alg: "ES256", typ: "vc+sd-jwt" })}.${b64u(payload)}.sig~`;
}

/** The two entries the backend's `ClaimUtils.credential_status_entries` writes. */
function statusEntries(index: number) {
  return ["revocation", "suspension"].map((statusPurpose) => ({
    type: "BitstringStatusListEntry",
    statusPurpose,
    statusListIndex: String(index),
    statusListCredential: `https://issuer.example/api/v1/status/did:sovra:${ISSUER}/${statusPurpose}`,
  }));
}

function credentialAt(id: string, index: number, issuer = ISSUER) {
  return sdJwtCredential({
    id,
    sdJwt: sdJwtWith({
      iss: `https://issuer.example/did:sovra:${issuer}`,
      vct: "NationalIdCredential",
      iat: 1_700_000_000,
      credentialStatus: statusEntries(index),
    }),
  });
}

/** `getBitmap`'s ABI return: offset, length, then each 256-bit word. */
function encodeBitmap(setBits: number[], words = 2): string {
  const bytes = new Uint8Array(words * 32);
  for (const index of setBits) {
    const word = Math.floor(index / 256);
    const bit = index % 256;
    bytes[word * 32 + 31 - Math.floor(bit / 8)] |= 1 << (bit % 8);
  }
  const word = (n: number) => n.toString(16).padStart(64, "0");
  return `0x${word(32)}${word(words)}${bytesToHex(bytes, false)}`;
}

/**
 * A registry holding `lists[issuer][purpose]` as set bit positions. Answers
 * only `getBitmap`, and records every call.
 */
function fakeRegistry(lists: Record<string, Partial<Record<number, number[]>>>) {
  const calls: string[] = [];
  const ethCall: EthCall = async (to, calldata) => {
    expect(to).toBe(REGISTRY);
    calls.push(calldata);
    for (const [issuer, byPurpose] of Object.entries(lists)) {
      for (const purpose of [STATUS_PURPOSE.revocation, STATUS_PURPOSE.suspension]) {
        if (calldata === getBitmapCall(issuer, purpose)) return encodeBitmap(byPurpose[purpose] ?? []);
      }
    }
    throw new Error("execution reverted");
  };
  return { ethCall, calls };
}

function getBitmapCall(issuer: string, purpose: number): string {
  return bytesToHex(
    encodeFunctionCall("getBitmap(address,uint8)", [
      Buffer.from(issuer.slice(2), "hex"),
      new Uint8Array([purpose]),
    ]),
  );
}

describe("statusReference", () => {
  it("reads the index and issuer an SD-JWT's issuer signed", () => {
    expect(statusReference(credentialAt("a", 7))).toEqual({
      issuerAddress: ISSUER,
      revocationIndex: 7,
      suspensionIndex: 7,
    });
  });

  it("reads a purpose the credential leaves out at the first entry's index", () => {
    // As verifiers do: omitting the suspension entry must not exempt a
    // credential from the suspension list.
    const [revocation] = statusEntries(9);
    const cred = sdJwtCredential({
      sdJwt: sdJwtWith({ iss: `did:sovra:${ISSUER}`, credentialStatus: revocation }),
    });

    expect(statusReference(cred)).toEqual({
      issuerAddress: ISSUER,
      revocationIndex: 9,
      suspensionIndex: 9,
    });
  });

  it("is null for an SD-JWT that declares no status", () => {
    const cred = sdJwtCredential({ sdJwt: sdJwtWith({ iss: `did:sovra:${ISSUER}` }) });
    expect(statusReference(cred)).toBeNull();
  });

  it("is null for an issuer that is not a did:sovra", () => {
    const cred = sdJwtCredential({
      sdJwt: sdJwtWith({ iss: "https://issuer.example", credentialStatus: statusEntries(1) }),
    });
    expect(statusReference(cred)).toBeNull();
  });

  it("reads the index from an mdoc's Sovra meta namespace", () => {
    // The fixture is the backend's own Sovra.Issuer.Mdoc output.
    const cred = mdocCredential({ issuerSigned: fixture.issuerSigned });

    expect(statusReference(cred)).toEqual({
      issuerAddress: fixture.issuerAddress.toLowerCase(),
      revocationIndex: fixture.statusListIndex,
      suspensionIndex: fixture.statusListIndex,
    });
  });
});

describe("isStatusSet", () => {
  it("follows the contract's word and bit arithmetic", async () => {
    const { ethCall } = fakeRegistry({ [ISSUER]: { 0: [0, 9, 255, 256, 300] } });
    const bitmap = await readStatusBitmap(ethCall, REGISTRY, ISSUER, STATUS_PURPOSE.revocation);

    for (const index of [0, 9, 255, 256, 300]) expect(isStatusSet(bitmap, index)).toBe(true);
    for (const index of [1, 8, 10, 254, 257, 511]) expect(isStatusSet(bitmap, index)).toBe(false);
  });

  it("treats a bit past the end of the list as unset", async () => {
    const { ethCall } = fakeRegistry({ [ISSUER]: {} });
    const bitmap = await readStatusBitmap(ethCall, REGISTRY, ISSUER, STATUS_PURPOSE.revocation);

    expect(isStatusSet(bitmap, 512)).toBe(false);
    expect(isStatusSet(bitmap, 1_000_000)).toBe(false);
  });
});

describe("readRegistryStatuses", () => {
  it("reports each credential's bit, with revocation outranking suspension", async () => {
    const { ethCall } = fakeRegistry({ [ISSUER]: { 0: [1, 3], 1: [2, 3] } });
    const creds = [0, 1, 2, 3].map((i) => credentialAt(`c${i}`, i));

    const statuses = await readRegistryStatuses(ethCall, REGISTRY, creds);

    expect(Object.fromEntries(statuses)).toEqual({
      c0: "valid",
      c1: "revoked",
      c2: "suspended",
      c3: "revoked",
    });
  });

  it("reads whole lists, once per issuer and purpose", async () => {
    // The index never leaves the device: asking for one bit would tell the
    // RPC node which credential this holder has.
    const { ethCall, calls } = fakeRegistry({ [ISSUER]: {}, [OTHER_ISSUER]: {} });
    const creds = [
      credentialAt("a", 1),
      credentialAt("b", 2),
      credentialAt("c", 3, OTHER_ISSUER),
    ];

    await readRegistryStatuses(ethCall, REGISTRY, creds);

    expect(calls.sort()).toEqual(
      [
        getBitmapCall(ISSUER, 0),
        getBitmapCall(ISSUER, 1),
        getBitmapCall(OTHER_ISSUER, 0),
        getBitmapCall(OTHER_ISSUER, 1),
      ].sort(),
    );
  });

  it("leaves out credentials whose issuer's lists cannot be read", async () => {
    // A failed read is not evidence of validity.
    const { ethCall } = fakeRegistry({ [ISSUER]: { 0: [1] } });
    const creds = [credentialAt("a", 1), credentialAt("b", 1, OTHER_ISSUER)];

    const statuses = await readRegistryStatuses(ethCall, REGISTRY, creds);

    expect(Object.fromEntries(statuses)).toEqual({ a: "revoked" });
  });

  it("leaves out credentials that declare no status", async () => {
    const { ethCall, calls } = fakeRegistry({});
    const statuses = await readRegistryStatuses(ethCall, REGISTRY, [sdJwtCredential()]);

    expect(statuses.size).toBe(0);
    expect(calls).toHaveLength(0);
  });
});

describe("CredentialManager.refreshRegistryStatuses", () => {
  const NS = "0xwallet";

  async function managerWith(...creds: ReturnType<typeof credentialAt>[]) {
    const { storage } = memoryStorage();
    const store = createCredentialStore();
    const manager = new CredentialManager(storage, store);
    manager.setActiveWallet(NS);
    for (const c of creds) store.getState().addCredential(c);
    await store.getState().persistToStorage(storage, NS);
    return { manager, store, storage };
  }

  it("persists a revocation, so it survives a reload", async () => {
    const { manager, storage } = await managerWith(credentialAt("a", 4));
    const { ethCall } = fakeRegistry({ [ISSUER]: { 0: [4] } });

    await manager.refreshRegistryStatuses(ethCall, REGISTRY);

    const reloaded = createCredentialStore();
    await reloaded.getState().loadFromStorage(storage, NS);
    expect(reloaded.getState().credentials[0].registryStatus).toBe("revoked");
  });

  it("lifts a suspension the issuer cleared", async () => {
    const { manager, store } = await managerWith(credentialAt("a", 4));

    await manager.refreshRegistryStatuses(fakeRegistry({ [ISSUER]: { 1: [4] } }).ethCall, REGISTRY);
    expect(store.getState().credentials[0].registryStatus).toBe("suspended");

    await manager.refreshRegistryStatuses(fakeRegistry({ [ISSUER]: {} }).ethCall, REGISTRY);
    expect(store.getState().credentials[0].registryStatus).toBe("valid");
  });

  it("keeps the last known status when the registry is unreachable", async () => {
    const { manager, store } = await managerWith(credentialAt("a", 4));
    await manager.refreshRegistryStatuses(fakeRegistry({ [ISSUER]: { 0: [4] } }).ethCall, REGISTRY);

    await manager.refreshRegistryStatuses(fakeRegistry({}).ethCall, REGISTRY);

    expect(store.getState().credentials[0].registryStatus).toBe("revoked");
  });

  it("drops answers that land after the wallet switched", async () => {
    const { manager, store } = await managerWith(credentialAt("a", 4));
    const { ethCall } = fakeRegistry({ [ISSUER]: { 0: [4] } });

    await manager.refreshRegistryStatuses(async (to, data) => {
      manager.setActiveWallet("0xsomeone-else");
      return ethCall(to, data);
    }, REGISTRY);

    expect(store.getState().credentials[0].registryStatus).toBeUndefined();
  });

  it("does not rewrite storage when nothing changed", async () => {
    const { manager, storage } = await managerWith(credentialAt("a", 4));
    const { ethCall } = fakeRegistry({ [ISSUER]: {} });
    await manager.refreshRegistryStatuses(ethCall, REGISTRY);

    const set = vi.spyOn(storage, "set");
    await manager.refreshRegistryStatuses(ethCall, REGISTRY);

    expect(set).not.toHaveBeenCalled();
  });
});
