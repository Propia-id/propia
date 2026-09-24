/**
 * Cross-repo contract: the backend publishes the schema design's logo per
 * credential configuration (Sovra.Issuer.OID4VCI.display_for/3 — a `data:` URI
 * from the design's thumbnail, or the organization's logo URL when the schema
 * has no design), and the wallet draws the card badge from whatever is
 * captured here. Worth pinning because losing it is invisible: the credential
 * still arrives, just wearing the app's brand mark instead of the issuer's.
 *
 * The bytes must never reach the credential index — it is persisted into the
 * platform keychain — so what lands on the credential is a reference and the
 * image goes to the asset store.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { pickLogo } from "../src/protocols";
import { CredentialManager } from "../src/credentials";
import { createCredentialStore, logoAssetKey } from "../src/state";
import { base64urlEncode } from "../src/utils";
import type { CredentialDisplay } from "../src/api";
import type { AssetStorage, SecureStorage } from "../src/platform";

const PNG_URI = "data:image/png;base64,iVBORw0KGgo=";

describe("pickLogo", () => {
  it("returns undefined when the issuer publishes no logo", () => {
    expect(pickLogo(undefined)).toBeUndefined();
    expect(pickLogo({ name: "Badge" })).toBeUndefined();
    expect(pickLogo({ name: "Badge", logo: { uri: "   " } })).toBeUndefined();
  });

  it("splits an inline data URI into the bytes and the extension to store", () => {
    expect(pickLogo({ name: "Badge", logo: { uri: PNG_URI } })).toEqual({
      kind: "data",
      extension: "png",
      base64: "iVBORw0KGgo=",
    });
  });

  it("maps each media type the wallet can draw onto its extension", () => {
    const extensionOf = (mediaType: string) => {
      const picked = pickLogo({ name: "B", logo: { uri: `data:${mediaType};base64,AAAA` } });
      return picked?.kind === "data" ? picked.extension : undefined;
    };
    expect(extensionOf("image/png")).toBe("png");
    expect(extensionOf("image/jpeg")).toBe("jpg");
    expect(extensionOf("image/webp")).toBe("webp");
    expect(extensionOf("image/svg+xml")).toBe("svg");
    // Not a format any renderer in the wallet handles: a file it cannot decode
    // is worse than falling back to the brand mark.
    expect(extensionOf("image/tiff")).toBeUndefined();
    // A PDF is still not card art, and this gate is not the one that changed
    // when attachments arrived — those come in as a claim, through
    // `parseAttachmentValue`, with their own media-type list.
    expect(extensionOf("application/pdf")).toBeUndefined();
  });

  it("is case-insensitive on the media type", () => {
    expect(pickLogo({ name: "B", logo: { uri: "data:IMAGE/PNG;base64,AAAA" } })).toMatchObject({
      extension: "png",
    });
  });

  it("keeps the issuer's alt text, trimmed, and omits a blank one", () => {
    expect(pickLogo({ name: "B", logo: { uri: PNG_URI, alt_text: "  State seal " } })).toMatchObject(
      { alt: "State seal" },
    );
    expect(
      pickLogo({ name: "B", logo: { uri: PNG_URI, alt_text: "  " } }),
    ).not.toHaveProperty("alt");
  });

  it("keeps an https URL as a URL rather than as bytes", () => {
    expect(pickLogo({ name: "B", logo: { uri: "https://issuer.test/logo.png" } })).toEqual({
      kind: "url",
      url: "https://issuer.test/logo.png",
    });
  });

  it("refuses a URL past the cap, which the backend's 256KB uri check lets through", () => {
    const url = (length: number) =>
      `https://issuer.test/${"a".repeat(length - "https://issuer.test/".length)}`;
    expect(pickLogo({ name: "B", logo: { uri: url(512) } })).toMatchObject({ kind: "url" });
    expect(pickLogo({ name: "B", logo: { uri: url(513) } })).toBeUndefined();
    // Under the backend's 256KB cap, far past what the index can carry.
    expect(pickLogo({ name: "B", logo: { uri: url(200 * 1024) } })).toBeUndefined();
  });

  it("drops an alt past the cap but keeps the logo", () => {
    const alt = (length: number) => "a".repeat(length);
    expect(
      pickLogo({ name: "B", logo: { uri: PNG_URI, alt_text: alt(128) } }),
    ).toMatchObject({ alt: alt(128) });

    const trimmed = pickLogo({ name: "B", logo: { uri: PNG_URI, alt_text: alt(129) } });
    expect(trimmed).toMatchObject({ kind: "data", extension: "png" });
    expect(trimmed).not.toHaveProperty("alt");

    // Same on the remote branch — the backend bounds alt_text nowhere.
    const remote = pickLogo({
      name: "B",
      logo: { uri: "https://issuer.test/logo.png", alt_text: alt(200 * 1024) },
    });
    expect(remote).toMatchObject({ kind: "url" });
    expect(remote).not.toHaveProperty("alt");
  });

  it("refuses a cleartext or non-http scheme", () => {
    // Both mobile platforms block cleartext by default, so accepting these
    // would trade the brand mark for a broken image.
    expect(pickLogo({ name: "B", logo: { uri: "http://issuer.test/logo.png" } })).toBeUndefined();
    expect(pickLogo({ name: "B", logo: { uri: "https://" } })).toBeUndefined();
    expect(pickLogo({ name: "B", logo: { uri: "file:///etc/passwd" } })).toBeUndefined();
    expect(pickLogo({ name: "B", logo: { uri: "javascript:alert(1)" } })).toBeUndefined();
  });

  it("refuses a data URI that is not base64 or not an image", () => {
    expect(pickLogo({ name: "B", logo: { uri: "data:image/png,notbase64" } })).toBeUndefined();
    expect(
      pickLogo({ name: "B", logo: { uri: "data:image/png;base64,not*base64!" } }),
    ).toBeUndefined();
    expect(pickLogo({ name: "B", logo: { uri: "data:;base64,AAAA" } })).toBeUndefined();
    // Unpadded: the platform decoder behind `AssetStorage.put` refuses it.
    expect(pickLogo({ name: "B", logo: { uri: "data:image/png;base64,AAA" } })).toBeUndefined();
  });

  it("refuses a payload past the cap instead of writing an unbounded blob", () => {
    const oversize = `data:image/png;base64,${"A".repeat(512 * 1024 + 1)}`;
    expect(pickLogo({ name: "B", logo: { uri: oversize } })).toBeUndefined();
    const atCap = `data:image/png;base64,${"A".repeat(512 * 1024)}`;
    expect(pickLogo({ name: "B", logo: { uri: atCap } })).toMatchObject({ kind: "data" });
  });

  it("ignores the background image — nothing renders it", () => {
    const display: CredentialDisplay = {
      name: "B",
      background_image: { uri: "data:image/png;base64,AAAA" },
    };
    expect(pickLogo(display)).toBeUndefined();
  });
});

// ─── Capture into the store ────────────────────────────────────────────────

class MemorySecureStorage implements SecureStorage {
  values = new Map<string, string>();
  async get(key: string) {
    return this.values.get(key) ?? null;
  }
  async set(key: string, value: string) {
    this.values.set(key, value);
  }
  async delete(key: string) {
    this.values.delete(key);
  }
}

class MemoryAssetStorage implements AssetStorage {
  files = new Map<string, string>();
  async put(key: string, base64: string) {
    this.files.set(key, base64);
  }
  uriFor(key: string) {
    return `file:///assets/${key}`;
  }
  async text(key: string) {
    return this.files.get(key) ?? null;
  }
  async delete(key: string) {
    this.files.delete(key);
  }
}

/** Minimal SD-JWT: an unsigned issuer JWT with no disclosures. */
function sdJwt(payload: Record<string, unknown>): string {
  const part = (value: unknown) =>
    base64urlEncode(new TextEncoder().encode(JSON.stringify(value)));
  return `${part({ alg: "ES256", typ: "vc+sd-jwt" })}.${part(payload)}.sig~`;
}

describe("CredentialManager logo capture", () => {
  let storage: MemorySecureStorage;
  let assets: MemoryAssetStorage;
  let store: ReturnType<typeof createCredentialStore>;
  let manager: CredentialManager;

  const issuer = { issuerDid: "did:sovra:issuer.test", issuerName: "ACME" };
  const credential = sdJwt({ vct: "EmployeeCredential", iat: 1700000000 });

  beforeEach(() => {
    storage = new MemorySecureStorage();
    assets = new MemoryAssetStorage();
    store = createCredentialStore();
    manager = new CredentialManager(storage, store, assets);
    manager.setActiveWallet("0xABC");
  });

  it("writes inline bytes to the asset store and keeps only the reference", async () => {
    const stored = await manager.storeCredential(credential, {
      ...issuer,
      display: { name: "Employee Badge" },
      logo: { kind: "data", extension: "png", base64: "iVBORw0KGgo=", alt: "Seal" },
    });

    expect(stored.display).toEqual({
      name: "Employee Badge",
      logo: { source: "asset", key: logoAssetKey(stored.id, "png"), alt: "Seal" },
    });
    expect(assets.files.get(logoAssetKey(stored.id, "png"))).toBe("iVBORw0KGgo=");

    // The index is persisted into the keychain — no image bytes may reach it.
    const index = storage.values.get("sovra.credentials.0xabc.index");
    expect(index).toBeTruthy();
    expect(index).not.toContain("iVBORw0KGgo=");
    expect(index).toContain(logoAssetKey(stored.id, "png"));
  });

  it("records a remote logo as a URL, writing no file", async () => {
    const stored = await manager.storeCredential(credential, {
      ...issuer,
      logo: { kind: "url", url: "https://issuer.test/logo.png" },
    });

    expect(stored.display).toEqual({
      logo: { source: "url", url: "https://issuer.test/logo.png" },
    });
    expect(assets.files.size).toBe(0);
  });

  it("stores the credential without a logo when the issuer published none", async () => {
    const stored = await manager.storeCredential(credential, {
      ...issuer,
      display: { name: "Employee Badge" },
    });
    expect(stored.display).toEqual({ name: "Employee Badge" });
    expect(assets.files.size).toBe(0);
  });

  it("keeps the credential when the art cannot be written", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    assets.put = () => Promise.reject(new Error("disk full"));

    const stored = await manager.storeCredential(credential, {
      ...issuer,
      display: { name: "Employee Badge" },
      logo: { kind: "data", extension: "png", base64: "iVBORw0KGgo=" },
    });

    expect(store.getState().credentials).toHaveLength(1);
    expect(stored.display).toEqual({ name: "Employee Badge" });
    expect(stored.display?.logo).toBeUndefined();
  });

  it("captures nothing with no asset store wired up", async () => {
    const bare = new CredentialManager(storage, createCredentialStore());
    bare.setActiveWallet("0xABC");
    const stored = await bare.storeCredential(credential, {
      ...issuer,
      logo: { kind: "data", extension: "png", base64: "iVBORw0KGgo=" },
    });
    expect(stored.display).toBeUndefined();
  });

  it("deletes the captured art with the credential", async () => {
    const stored = await manager.storeCredential(credential, {
      ...issuer,
      logo: { kind: "data", extension: "png", base64: "iVBORw0KGgo=" },
    });
    const key = logoAssetKey(stored.id, "png");
    expect(assets.files.has(key)).toBe(true);

    await manager.deleteCredential(stored.id);

    expect(assets.files.has(key)).toBe(false);
    expect(store.getState().credentials).toHaveLength(0);
  });

  it("survives deleting a credential whose art is already gone", async () => {
    const stored = await manager.storeCredential(credential, {
      ...issuer,
      logo: { kind: "data", extension: "png", base64: "iVBORw0KGgo=" },
    });
    assets.delete = () => Promise.reject(new Error("gone"));
    await expect(manager.deleteCredential(stored.id)).resolves.toBeUndefined();
    expect(store.getState().credentials).toHaveLength(0);
  });

  it("reloads the reference from storage, so a card renders it offline", async () => {
    const stored = await manager.storeCredential(credential, {
      ...issuer,
      logo: { kind: "data", extension: "png", base64: "iVBORw0KGgo=" },
    });

    const fresh = createCredentialStore();
    const reopened = new CredentialManager(storage, fresh, assets);
    reopened.setActiveWallet("0xABC");
    await reopened.loadAll();

    expect(fresh.getState().getCredential(stored.id)?.display?.logo).toEqual({
      source: "asset",
      key: logoAssetKey(stored.id, "png"),
    });
  });
});
