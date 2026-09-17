import { describe, expect, it } from "vitest";
import { createCredentialStore, credentialKey, isMdoc, isSdJwt } from "../src/state/index";
import { mdocCredential, memoryStorage, sdJwtCredential } from "./fixtures";

const NS = "0xwallet";
const INDEX_KEY = `sovra.credentials.${NS}.index`;

describe("persistence round trip", () => {
  it("restores both formats with their blobs", async () => {
    const { storage } = memoryStorage();
    const store = createCredentialStore();

    store.getState().addCredential(sdJwtCredential());
    store.getState().addCredential(mdocCredential());
    await store.getState().persistToStorage(storage, NS);

    const restored = createCredentialStore();
    await restored.getState().loadFromStorage(storage, NS);

    const [sd, mdoc] = restored.getState().credentials;
    expect(isSdJwt(sd) && sd.sdJwt).toBe(sdJwtCredential().sdJwt);
    expect(isMdoc(mdoc) && mdoc.issuerSigned).toBe(mdocCredential().issuerSigned);
  });

  it("keeps mdoc metadata that a naive Omit would have dropped", async () => {
    // `Omit<StoredCredential, "sdJwt">` type-checks against a union but
    // collapses to the common keys, silently losing docType and elements. This
    // is the regression guard for that.
    const { storage } = memoryStorage();
    const store = createCredentialStore();

    store.getState().addCredential(mdocCredential());
    await store.getState().persistToStorage(storage, NS);

    const restored = createCredentialStore();
    await restored.getState().loadFromStorage(storage, NS);

    const [cred] = restored.getState().credentials;
    expect(isMdoc(cred)).toBe(true);
    if (!isMdoc(cred)) return;

    expect(cred.docType).toBe(mdocCredential().docType);
    expect(cred.elements).toHaveLength(2);
    expect(cred.elements.find((e) => e.elementIdentifier === "tier")?.mandatory).toBe(true);
  });

  it("keeps the blob out of the index", async () => {
    const { storage, map } = memoryStorage();
    const store = createCredentialStore();

    store.getState().addCredential(sdJwtCredential());
    await store.getState().persistToStorage(storage, NS);

    expect(map.get(INDEX_KEY)).not.toContain("header.payload.sig");
    expect(map.get(credentialKey(NS, "cred-sd-jwt-1"))).toBe("header.payload.sig~");
  });
});

describe("back-compat with records written before mdoc existed", () => {
  // Every stored index entry predating this change lacks `format`. The whole
  // migration is reading `undefined` as "vc+sd-jwt" — no version marker, no
  // rewrite pass.
  const legacyIndex = JSON.stringify([
    {
      id: "legacy-1",
      issuerDid: "did:sovra:0xissuer",
      credentialType: "NationalIdCredential",
      issuerName: "Old Issuer",
      issuedAt: 1_600_000_000,
      expiresAt: 1_900_000_000,
      claims: { given_name: "Maria" },
    },
  ]);

  it("hydrates a formatless entry as SD-JWT", async () => {
    const { storage } = memoryStorage({
      [INDEX_KEY]: legacyIndex,
      [credentialKey(NS, "legacy-1")]: "legacy.jwt.sig~",
    });

    const store = createCredentialStore();
    await store.getState().loadFromStorage(storage, NS);

    const [cred] = store.getState().credentials;
    expect(cred.format).toBe("vc+sd-jwt");
    expect(isSdJwt(cred) && cred.sdJwt).toBe("legacy.jwt.sig~");
    expect(cred.claims.given_name).toBe("Maria");
  });

  it("backfills format on the next persist, so it self-heals", async () => {
    const { storage, map } = memoryStorage({
      [INDEX_KEY]: legacyIndex,
      [credentialKey(NS, "legacy-1")]: "legacy.jwt.sig~",
    });

    const store = createCredentialStore();
    await store.getState().loadFromStorage(storage, NS);
    await store.getState().persistToStorage(storage, NS);

    expect(JSON.parse(map.get(INDEX_KEY)!)[0].format).toBe("vc+sd-jwt");
  });

  it("reads a mixed index of legacy and mdoc entries", async () => {
    const { storage } = memoryStorage();
    const store = createCredentialStore();

    store.getState().addCredential(mdocCredential());
    await store.getState().persistToStorage(storage, NS);

    // Splice a formatless legacy entry in beside the mdoc one.
    const index = JSON.parse(await storage.get(INDEX_KEY)!);
    index.push(JSON.parse(legacyIndex)[0]);
    await storage.set(INDEX_KEY, JSON.stringify(index));
    await storage.set(credentialKey(NS, "legacy-1"), "legacy.jwt.sig~");

    const restored = createCredentialStore();
    await restored.getState().loadFromStorage(storage, NS);

    expect(restored.getState().credentials.map((c) => c.format)).toEqual([
      "mso_mdoc",
      "vc+sd-jwt",
    ]);
  });
});

describe("failure handling", () => {
  it("skips an index entry whose blob is missing rather than failing the load", async () => {
    const { storage } = memoryStorage({ [INDEX_KEY]: legacyIndexWithTwo() });
    await storage.set(credentialKey(NS, "present"), "a.b.c~");

    const store = createCredentialStore();
    await store.getState().loadFromStorage(storage, NS);

    expect(store.getState().credentials.map((c) => c.id)).toEqual(["present"]);
  });

  it("clears a corrupted index instead of leaving the wallet unusable", async () => {
    const { storage, map } = memoryStorage({ [INDEX_KEY]: "{not json" });

    const store = createCredentialStore();
    await store.getState().loadFromStorage(storage, NS);

    expect(store.getState().credentials).toEqual([]);
    expect(map.has(INDEX_KEY)).toBe(false);
  });

  it("empties the in-memory list when a wallet has no index", async () => {
    // A wallet switch must never leave the previous holder's credentials on screen.
    const { storage } = memoryStorage();
    const store = createCredentialStore();
    store.getState().addCredential(sdJwtCredential());

    await store.getState().loadFromStorage(storage, "0xother");
    expect(store.getState().credentials).toEqual([]);
  });
});

function legacyIndexWithTwo(): string {
  const base = {
    issuerDid: "did:sovra:0xissuer",
    credentialType: "NationalIdCredential",
    issuerName: "Old Issuer",
    issuedAt: 1_600_000_000,
    expiresAt: 1_900_000_000,
    claims: {},
  };
  return JSON.stringify([
    { ...base, id: "present" },
    { ...base, id: "orphaned" },
  ]);
}
