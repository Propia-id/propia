/**
 * The contract that keeps a credential's attached document out of the platform
 * secure store.
 *
 * `expo-secure-store` documents a 2048-byte limit per value, and both the
 * credential index — one value holding every credential's metadata — and each
 * credential blob go through it. A 400 KB PDF is ~546 KB of base64. So the
 * assertions that matter here are about size and about reversibility: the
 * document is described in `claims`, the disclosure it arrived in lives in the
 * asset store, and that disclosure can be put back to produce the original
 * credential — or written out, once verified, as the file the holder opens.
 */

import { describe, expect, it, vi } from "vitest";

import {
  CredentialManager,
  createCredentialStore,
  isAttachmentDescriptor,
  isSdJwt,
  MAX_ATTACHMENT_BASE64_LENGTH,
  parseAttachmentValue,
  type StoredSdJwtCredential,
} from "../src/index";
import { PresentationProtocol, type VPRequest } from "../src/protocols/index";
import { memoryAssetStorage, memoryStorage, sdJwtWithAttachment } from "./fixtures";

const NAMESPACE = "0x00000000000000000000000000000000000000aa";

const ISSUER = {
  issuerDid: "did:sovra:0x00000000000000000000000000000000000000b2",
  issuerName: "Ministry of Transport",
};

function manager(options: { withAssets?: boolean } = {}) {
  const { storage, map } = memoryStorage();
  const { assets, map: assetMap } = memoryAssetStorage();
  const store = createCredentialStore();
  const credentials = new CredentialManager(
    storage,
    store,
    options.withAssets === false ? undefined : assets,
  );
  credentials.setActiveWallet(NAMESPACE);
  return { credentials, store, storage, map, assets, assetMap };
}

/** The bytes a `data:` URI carries. */
function bytesOf(dataUri: string): Buffer {
  return Buffer.from(dataUri.slice(dataUri.indexOf(",") + 1), "base64");
}

describe("parseAttachmentValue", () => {
  it("reads a PDF data URI", () => {
    const parsed = parseAttachmentValue(`data:application/pdf;base64,${btoa("%PDF-1.7")}`);

    expect(parsed?.descriptor.mediaType).toBe("application/pdf");
    expect(parsed?.descriptor.extension).toBe("pdf");
    expect(parsed?.descriptor.bytes).toBe("%PDF-1.7".length);
  });

  it("gets the size right across every padding length", () => {
    for (const text of ["a", "ab", "abc", "abcd", "abcde", "abcdef"]) {
      const parsed = parseAttachmentValue(`data:application/pdf;base64,${btoa(text)}`);
      expect(parsed?.descriptor.bytes).toBe(text.length);
    }
  });

  it("leaves a media type it cannot store alone", () => {
    // Not described as a document the wallet cannot produce — it stays the
    // string it is, and renders as one.
    expect(parseAttachmentValue(`data:image/png;base64,${btoa("png")}`)).toBeNull();
  });

  it("leaves an ordinary claim value alone", () => {
    expect(parseAttachmentValue("Rossi")).toBeNull();
    expect(parseAttachmentValue(42)).toBeNull();
    expect(parseAttachmentValue(null)).toBeNull();
  });

  it("refuses a payload past the cap", () => {
    const pdf = (length: number) => `data:application/pdf;base64,${"A".repeat(length)}`;
    expect(parseAttachmentValue(pdf(MAX_ATTACHMENT_BASE64_LENGTH))).not.toBeNull();
    expect(parseAttachmentValue(pdf(MAX_ATTACHMENT_BASE64_LENGTH + 4))).toBeNull();
  });

  it("leaves a payload no decoder accepts alone", () => {
    // Unpadded, or a length that is not a multiple of four: described as a
    // document, it would be split out of the credential and then refused by
    // the platform decoder every time the holder opened it.
    expect(parseAttachmentValue("data:application/pdf;base64,QUJD")).not.toBeNull();
    expect(parseAttachmentValue("data:application/pdf;base64,QUI")).toBeNull();
    expect(parseAttachmentValue("data:application/pdf;base64,QUJDR")).toBeNull();
  });

  it("reads only the spelling the spec defines", () => {
    // The backend admits `application/pdf` and nothing else.
    expect(parseAttachmentValue(`data:application/PDF;base64,${btoa("%PDF-1.7")}`)).toBeNull();
  });
});

describe("parseSDJwt", () => {
  it("swaps the data URI for a descriptor", () => {
    const { credentials } = manager();
    const { sdJwt, claim } = sdJwtWithAttachment();

    const parsed = credentials.parseSDJwt(sdJwt);

    expect(isAttachmentDescriptor(parsed.claims[claim])).toBe(true);
    expect(JSON.stringify(parsed.claims)).not.toContain("application/pdf;base64");
    expect(parsed.claims.family_name).toBe("Rossi");
    expect(parsed.attachment?.key).toBe(claim);
  });

  it("reports nothing for a credential carrying no document", () => {
    const { credentials } = manager();
    const { sdJwt } = sdJwtWithAttachment({ pdf: "not a document" });

    expect(credentials.parseSDJwt(sdJwt).attachment).toBeUndefined();
  });
});

describe("storeCredential", () => {
  it("moves the disclosure to the asset store, and keeps it out of the secure store", async () => {
    const { credentials, map, assets, assetMap } = manager();
    const { sdJwt, claim, disclosure } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);

    expect(stored.attachment).toMatchObject({ claim, mediaType: "application/pdf" });
    // Read back through the store's own semantics — `put` decodes base64,
    // `text` reads UTF-8 — so this is the disclosure itself, not an encoding.
    await expect(assets.text(stored.attachment!.disclosureKey)).resolves.toBe(disclosure);
    // The document is written from the disclosure when the holder opens it.
    expect(assetMap.has(stored.attachment!.key)).toBe(false);

    // The blob, and the index, are what go into the platform secure store.
    const blob = map.get(`sovra.credential.${NAMESPACE}.${stored.id}`)!;
    expect(blob).not.toContain(disclosure);
    expect(blob).not.toContain("application/pdf;base64");
    expect(blob.length).toBeLessThan(4096);

    const index = map.get(`sovra.credentials.${NAMESPACE}.index`)!;
    expect(index).not.toContain("application/pdf;base64");
  });

  it("stores the credential whole when there is no asset store", async () => {
    // Every non-mobile assembly — the Node e2e suite, the web build. Stripping
    // the disclosure without capturing it would destroy the only copy.
    const { credentials, map } = manager({ withAssets: false });
    const { sdJwt, disclosure, claim } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);

    expect(stored.attachment).toBeUndefined();
    expect(stored.sdJwt).toBe(sdJwt);
    expect(map.get(`sovra.credential.${NAMESPACE}.${stored.id}`)).toContain(disclosure);
    // The descriptor still stands in for the value, so nothing renders a wall
    // of base64 and the index stays small.
    expect(isAttachmentDescriptor(stored.claims[claim])).toBe(true);
  });

  it("keeps the document out of the secure store when capture fails", async () => {
    // Kept whole, the blob would be a ~750 KB secure-store write that fails
    // and takes the credential with it. So the disclosure is split out anyway:
    // the credential survives, and the document reads as missing rather than
    // leaving no trace. The write fails half-way, so this also covers the
    // partial file being cleared — read back, it would say "tampered".
    const { storage, map } = memoryStorage();
    const { assets, map: assetMap } = memoryAssetStorage();
    vi.spyOn(assets, "put").mockImplementation(async (key) => {
      assetMap.set(key, new TextEncoder().encode("eyJ0cnVuY2F0ZWQ"));
      throw new Error("disk full");
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const credentials = new CredentialManager(storage, createCredentialStore(), assets);
    credentials.setActiveWallet(NAMESPACE);
    const { sdJwt, disclosure, claim } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);

    expect(stored.attachment).toMatchObject({ claim, mediaType: "application/pdf" });
    expect(stored.sdJwt).not.toContain(disclosure);
    expect(map.get(`sovra.credential.${NAMESPACE}.${stored.id}`)).not.toContain(disclosure);
    await expect(credentials.attachmentUri(stored)).resolves.toEqual({ error: "missing" });
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("survives a reload with the attachment reference intact", async () => {
    // `PersistedSdJwt` omits over the concrete member type, so a new field is
    // inherited into the index silently. This is the assertion that it is.
    const { credentials, store, storage } = manager();
    const { sdJwt } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);
    store.getState().reset();
    await store.getState().loadFromStorage(storage, NAMESPACE);

    const reloaded = store.getState().getCredential(stored.id)!;
    expect(isSdJwt(reloaded)).toBe(true);
    expect((reloaded as StoredSdJwtCredential).attachment).toEqual(stored.attachment);
  });
});

describe("attachmentUri", () => {
  it("writes the document the issuer signed and returns its URI", async () => {
    const { credentials, assetMap } = manager();
    const { sdJwt, pdf } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);

    await expect(credentials.attachmentUri(stored)).resolves.toEqual({
      uri: `file:///assets/${stored.attachment!.key}`,
    });
    expect(Buffer.from(assetMap.get(stored.attachment!.key)!)).toEqual(bytesOf(pdf));
  });

  it("shares the signed bytes, not a file altered on disk", async () => {
    // The file lives in ordinary app storage, not the secure store, so "the
    // bytes on disk" and "the bytes the issuer signed" are different claims.
    // Writing the file from the verified disclosure makes them the same one.
    const { credentials, assetMap } = manager();
    const { sdJwt, pdf } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);
    await credentials.attachmentUri(stored);
    assetMap.set(stored.attachment!.key, new TextEncoder().encode("%PDF-1.7 forged"));

    await expect(credentials.attachmentUri(stored)).resolves.toHaveProperty("uri");
    expect(Buffer.from(assetMap.get(stored.attachment!.key)!)).toEqual(bytesOf(pdf));
  });

  it("refuses a stored disclosure that is not the one that was signed", async () => {
    const { credentials, assetMap } = manager();
    const { sdJwt } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);
    const tampered = Buffer.from(
      JSON.stringify(["sALT-2", stored.attachment!.claim, "data:application/pdf;base64,AAAA"]),
    ).toString("base64url");
    assetMap.set(stored.attachment!.disclosureKey, new TextEncoder().encode(tampered));

    await expect(credentials.attachmentUri(stored)).resolves.toEqual({ error: "tampered" });
    expect(assetMap.has(stored.attachment!.key)).toBe(false);
  });

  it("reports a document whose disclosure is gone as missing", async () => {
    const { credentials, assetMap } = manager();
    const { sdJwt } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);
    assetMap.delete(stored.attachment!.disclosureKey);

    await expect(credentials.attachmentUri(stored)).resolves.toEqual({ error: "missing" });
  });

  it("returns null for a credential with no document", async () => {
    const { credentials } = manager();
    const { sdJwt } = sdJwtWithAttachment({ pdf: "not a document" });

    const stored = await credentials.storeCredential(sdJwt, ISSUER);

    await expect(credentials.attachmentUri(stored)).resolves.toBeNull();
  });
});

describe("presentation", () => {
  it("never discloses the attachment, and says so when asked", async () => {
    const { credentials } = manager();
    const { sdJwt, claim } = sdJwtWithAttachment();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const stored = await credentials.storeCredential(sdJwt, ISSUER);
    const selected = credentials.selectDisclosures(stored, ["family_name", claim]);

    expect(selected).toHaveLength(1);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining(claim));
    warn.mockRestore();
  });

  it("is reversible: the split disclosure rebuilds the original credential", async () => {
    // What makes the split safe to do at all. The digest stays in the signed
    // `_sd`, so the stored credential is an ordinary one with a claim withheld,
    // and putting the segment back reconstructs the issued bytes exactly.
    const { credentials } = manager();
    const { sdJwt } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);
    const disclosure = await credentials.loadAttachmentDisclosure(stored);
    const [jwt, ...rest] = stored.sdJwt.split("~");

    expect([jwt, ...rest.filter(Boolean), disclosure, ""].join("~")).toBe(
      [sdJwt.split("~")[0], ...sdJwt.split("~").slice(1).filter(Boolean), ""].join("~"),
    );
  });

  it("builds a presentation whose sd_hash covers the re-appended disclosure", async () => {
    const { credentials } = manager();
    const { sdJwt } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);
    const disclosure = (await credentials.loadAttachmentDisclosure(stored))!;
    const selected = [...credentials.selectDisclosures(stored, ["family_name"]), disclosure];

    const presentation = credentials.buildPresentationSDJwt(stored, selected, "kb.jwt.sig");

    expect(presentation).toContain(disclosure);
    expect(credentials.computeSdHash(stored.sdJwt.split("~")[0], selected)).toHaveLength(32);
  });

  it("lists a requested attachment with what stays private, not as a toggle", async () => {
    // A toggle would tell the holder they are sending a document that
    // `selectDisclosures` will never include.
    const { credentials } = manager();
    const { sdJwt, claim } = sdJwtWithAttachment();
    const stored = await credentials.storeCredential(sdJwt, ISSUER);

    const protocol = new PresentationProtocol(
      null as never,
      null as never,
      null as never,
      null as never,
    );
    const ref = (key: string) => ({ id: key, path: [key], key, mandatory: false });
    const approval = protocol.buildApprovalData({ verified: false } as VPRequest, stored, [
      ref("family_name"),
      ref(claim),
    ]);

    expect(approval.sharedClaims.map((c) => c.key)).toEqual(["family_name"]);
    expect(approval.withheldClaims.map((c) => c.key)).toContain(claim);
  });
});

describe("deleteCredential", () => {
  it("takes both asset files with it", async () => {
    const { credentials, assetMap } = manager();
    const { sdJwt } = sdJwtWithAttachment();

    const stored = await credentials.storeCredential(sdJwt, ISSUER);
    // Opened once, so the document file exists beside its disclosure.
    await credentials.attachmentUri(stored);
    expect(assetMap.size).toBe(2);

    await credentials.deleteCredential(stored.id);

    expect(assetMap.size).toBe(0);
  });
});
