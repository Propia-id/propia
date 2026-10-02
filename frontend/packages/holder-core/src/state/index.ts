import { createStore } from "zustand/vanilla";
import type { SecureStorage } from "../platform/index.js";

// ─── Credential Store ─────────────────────────────────

/**
 * Where a captured card logo lives — never the bytes themselves.
 *
 * An issuer inlines its logo as a `data:` URI, so those bytes are written to
 * the `AssetStorage` at issuance and only the key is kept here. A logo the
 * issuer published as a remote URL is short enough to keep as it stands.
 */
export type StoredLogo =
  | { source: "asset"; key: string; alt?: string }
  | { source: "url"; url: string; alt?: string };

/**
 * The logo an issuer published, before it is persisted.
 *
 * `data:` payloads still carry their bytes, for capture into the `AssetStorage`
 * at issuance; a remote URL is kept as a URL and left to the platform image
 * loader (which disk-caches it). Only `https` — a cleartext fetch is blocked by
 * both mobile platforms by default anyway, so accepting `http` would trade a
 * brand mark for a broken image.
 */
export type PendingLogo =
  | { kind: "data"; extension: string; base64: string; alt?: string }
  | { kind: "url"; url: string; alt?: string };

/**
 * The issuer's card design, from its OID4VCI `display` entry at issuance.
 *
 * Text plus a reference to the logo — no image bytes. An issuer may inline
 * `logo`/`background_image` as `data:` URIs hundreds of kilobytes long, and
 * this record is persisted into the credential index in the platform secure
 * store, which is sized for key material, not images. `background_image` is
 * dropped outright; `logo` survives as a `StoredLogo` reference.
 */
export interface CredentialDisplayMetadata {
  name?: string;
  locale?: string;
  description?: string;
  backgroundColor?: string;
  textColor?: string;
  /**
   * The issuer's own card logo. Absent when it published none, when the one it
   * published is in a format the wallet cannot render, or when capturing it
   * failed — the card falls back to the app's brand mark in all three cases.
   */
  logo?: StoredLogo;
}

export type CredentialFormat = "vc+sd-jwt" | "mso_mdoc";

/** What the issuer's revocation and suspension lists say about a credential. */
export type RegistryStatus = "valid" | "revoked" | "suspended";

/**
 * Fields every credential has, whatever its wire format.
 *
 * `claims` stays a flat, display-ready map on the base type on purpose. An
 * mdoc's data is namespaced, but flattening it here is what lets every card,
 * search box and detail view keep working unchanged — the format is plumbing a
 * holder should never have to see. Namespaced element metadata lives on the
 * mdoc variant for the code that genuinely needs it.
 *
 * Binary and tagged CBOR values are normalised into display-safe forms before
 * they reach `claims`; raw bytes stay in the credential blob.
 */
interface StoredCredentialBase {
  id: string;
  issuerDid: string;
  /** The `vct` for SD-JWT, the docType for mdoc. One field, so lookups by type work for both. */
  credentialType: string;
  issuerName: string;
  issuedAt: number;
  expiresAt: number;
  claims: Record<string, unknown>;
  /** Absent pre-capture and on issuers publishing no `display` — always have a fallback. */
  display?: CredentialDisplayMetadata;
  /**
   * Claim key → the issuer's own label, from the OID4VCI claims descriptions
   * at issuance. Captured here rather than re-fetched so a card still renders
   * the issuer's wording offline, and so credentials stored before this
   * existed keep working on the derived label.
   *
   * Sparse: only claims the issuer actually labelled appear.
   */
  claimLabels?: Record<string, string>;
  /**
   * The last answer from the revocation registry. Persisted, so a credential
   * the issuer revoked still reads as revoked when the wallet is offline.
   * Absent until the first successful check, and on a credential that declares
   * no status entry.
   */
  registryStatus?: RegistryStatus;
}

/**
 * A credential's attached document — never the bytes themselves.
 *
 * Two asset keys. `disclosureKey` holds the verbatim SD-JWT disclosure the
 * document arrived in, and it is the only copy kept: its digest is in the
 * signed `_sd` array, so the wallet can prove it is what the issuer signed.
 * `key` is where the document is written, from that verified disclosure, each
 * time the holder opens it — so the file handed to the operating system is
 * never one that could have drifted from what was signed.
 *
 * Not folded into `CredentialDisplayMetadata` beside the logo. That shape
 * describes card art, and it is what the backup payload carries — an
 * attachment is credential data, and putting it there would have backups start
 * smuggling it.
 */
export interface StoredAttachment {
  /** The claim key the document was disclosed under. Operator-chosen. */
  claim: string;
  /** Asset key the document is written to when the holder opens it. */
  key: string;
  /** Asset key for the verbatim base64url disclosure segment. */
  disclosureKey: string;
  mediaType: string;
  bytes: number;
}

export interface StoredSdJwtCredential extends StoredCredentialBase {
  format: "vc+sd-jwt";
  sdJwt: string;
  /**
   * Absent on every credential that carries no document, and on one stored
   * with no asset store at all — in which case `sdJwt` still holds the
   * disclosure whole. Present with nothing behind `disclosureKey` when the
   * capture failed: the document is gone, and opening it says so.
   */
  attachment?: StoredAttachment;
}

/** One data element inside an mdoc namespace. */
export interface MdocElementMeta {
  namespace: string;
  elementIdentifier: string;
  /** The key this element was flattened to in `claims`. */
  claimKey: string;
  /** From the schema's `disclosable: false` — the holder may not withhold it. */
  mandatory: boolean;
}

export interface StoredMdocCredential extends StoredCredentialBase {
  format: "mso_mdoc";
  /** base64url(CBOR) of the OID4VCI `IssuerSigned` structure. */
  issuerSigned: string;
  docType: string;
  elements: MdocElementMeta[];
}

export type StoredCredential = StoredSdJwtCredential | StoredMdocCredential;

export function isSdJwt(c: StoredCredential): c is StoredSdJwtCredential {
  return c.format === "vc+sd-jwt";
}

export function isMdoc(c: StoredCredential): c is StoredMdocCredential {
  return c.format === "mso_mdoc";
}

export interface CredentialState {
  credentials: StoredCredential[];
}

export interface CredentialActions {
  addCredential(cred: StoredCredential): void;
  removeCredential(id: string): void;
  getCredential(id: string): StoredCredential | undefined;
  getByType(type: string): StoredCredential[];
  /**
   * Apply registry answers by credential id. Ids no longer in the store are
   * ignored. Returns whether any credential changed, so a caller can skip
   * persisting a refresh that found nothing new.
   */
  setRegistryStatuses(statuses: ReadonlyMap<string, RegistryStatus>): boolean;
  loadFromStorage(storage: SecureStorage, namespace: string): Promise<void>;
  persistToStorage(storage: SecureStorage, namespace: string): Promise<void>;
  /** Clear only the in-memory list (e.g. on logout / wallet switch). Storage is untouched. */
  reset(): void;
}

export type CredentialStore = CredentialState & CredentialActions;

// Credentials are scoped per wallet so one holder never sees another's.
// `namespace` is the lowercased wallet address (the DID is did:sovra:<namespace>).
const indexKey = (namespace: string) => `sovra.credentials.${namespace}.index`;
export const credentialKey = (namespace: string, id: string) =>
  `sovra.credential.${namespace}.${id}`;

/**
 * What the index holds: everything except the credential blob, which is stored
 * under its own key.
 *
 * Spelled out per variant rather than as `Omit<StoredCredential, "sdJwt">`.
 * That would look correct and silently lose data: `keyof` over a union yields
 * only the keys *common* to its members, so the `Omit` would collapse to the
 * base fields and drop `docType` and `elements` — while still type-checking.
 *
 * `format` is optional on the SD-JWT variant, and that single optionality is
 * the whole back-compat story. Every record written before mdoc existed lacks
 * the field, so `undefined` reads as `"vc+sd-jwt"`. No version marker, no
 * rewrite pass: legacy entries pick up the field on the next persist.
 */
type PersistedSdJwt = Omit<StoredSdJwtCredential, "sdJwt" | "format"> & {
  format?: "vc+sd-jwt";
};
type PersistedMdoc = Omit<StoredMdocCredential, "issuerSigned">;
type PersistedEntry = PersistedSdJwt | PersistedMdoc;

/** The blob stored under the credential's own key. */
function blobFor(cred: StoredCredential): string {
  return isSdJwt(cred) ? cred.sdJwt : cred.issuerSigned;
}

function stripBlob(cred: StoredCredential): PersistedEntry {
  if (isSdJwt(cred)) {
    const { sdJwt: _sdJwt, ...rest } = cred;
    return rest;
  }
  const { issuerSigned: _issuerSigned, ...rest } = cred;
  return rest;
}

function hydrate(entry: PersistedEntry, blob: string): StoredCredential {
  return entry.format === "mso_mdoc"
    ? { ...entry, issuerSigned: blob }
    : { ...entry, format: "vc+sd-jwt", sdJwt: blob };
}

/**
 * Asset-store key for one credential's captured logo.
 *
 * Not namespaced by wallet: credential ids are random UUIDs, so two holders on
 * the same device cannot collide. The extension is part of the key so the
 * platform image loader can pick a decoder from the file name, and so
 * `AssetStorage.uriFor` stays a pure string join.
 */
export const logoAssetKey = (credentialId: string, extension: string) =>
  `logo-${credentialId}.${extension}`;

/**
 * Asset-store key for one credential's attached document.
 *
 * The extension carries its weight twice here: `AssetStorage.uriFor` stays a
 * pure string join, and the operating system's share sheet picks the
 * application to open a file by its name.
 */
export const attachmentAssetKey = (credentialId: string, extension: string) =>
  `attachment-${credentialId}.${extension}`;

/** Asset-store key for the disclosure that document arrived in. */
export const attachmentDisclosureAssetKey = (credentialId: string) =>
  `attachment-${credentialId}.disclosure`;

export function createCredentialStore() {
  return createStore<CredentialStore>((set, get) => ({
    credentials: [],

    addCredential(cred) {
      set((state) => ({ credentials: [...state.credentials, cred] }));
    },

    removeCredential(id) {
      set((state) => ({
        credentials: state.credentials.filter((c) => c.id !== id),
      }));
    },

    getCredential(id) {
      return get().credentials.find((c) => c.id === id);
    },

    getByType(type) {
      return get().credentials.filter((c) => c.credentialType === type);
    },

    setRegistryStatuses(statuses) {
      let changed = false;
      const credentials = get().credentials.map((c) => {
        const registryStatus = statuses.get(c.id);
        if (!registryStatus || registryStatus === c.registryStatus) return c;
        changed = true;
        return { ...c, registryStatus };
      });
      if (changed) set({ credentials });
      return changed;
    },

    async loadFromStorage(storage, namespace) {
      const indexRaw = await storage.get(indexKey(namespace));
      // No index for this wallet → ensure the in-memory list is empty so a
      // wallet switch never leaves the previous holder's credentials behind.
      if (!indexRaw) {
        set({ credentials: [] });
        return;
      }

      try {
        const index: PersistedEntry[] = JSON.parse(indexRaw);
        const credentials: StoredCredential[] = [];

        for (const entry of index) {
          const blob = await storage.get(credentialKey(namespace, entry.id));
          if (blob) {
            credentials.push(hydrate(entry, blob));
          } else {
            // An index entry whose blob is gone is unrecoverable, but dropping
            // it silently makes "my credential vanished" impossible to
            // diagnose from a log.
            console.warn(
              `[credentials] index entry ${entry.id} has no stored blob — skipping`,
            );
          }
        }

        set({ credentials });
      } catch (err) {
        console.warn("Corrupted credentials storage, clearing:", err);
        await storage.delete(indexKey(namespace));
        set({ credentials: [] });
      }
    },

    async persistToStorage(storage, namespace) {
      const { credentials } = get();

      // The index carries metadata only; each credential blob is stored under
      // its own key so the index stays small.
      await storage.set(
        indexKey(namespace),
        JSON.stringify(credentials.map(stripBlob)),
      );

      for (const cred of credentials) {
        await storage.set(credentialKey(namespace, cred.id), blobFor(cred));
      }
    },

    reset() {
      set({ credentials: [] });
    },
  }));
}
