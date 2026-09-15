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

export interface StoredCredential {
  id: string;
  sdJwt: string;
  issuerDid: string;
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
}

export interface CredentialState {
  credentials: StoredCredential[];
}

export interface CredentialActions {
  addCredential(cred: StoredCredential): void;
  removeCredential(id: string): void;
  getCredential(id: string): StoredCredential | undefined;
  getByType(type: string): StoredCredential[];
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
 * Asset-store key for one credential's captured logo.
 *
 * Not namespaced by wallet: credential ids are random UUIDs, so two holders on
 * the same device cannot collide. The extension is part of the key so the
 * platform image loader can pick a decoder from the file name, and so
 * `AssetStorage.uriFor` stays a pure string join.
 */
export const logoAssetKey = (credentialId: string, extension: string) =>
  `logo-${credentialId}.${extension}`;

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

    async loadFromStorage(storage, namespace) {
      const indexRaw = await storage.get(indexKey(namespace));
      // No index for this wallet → ensure the in-memory list is empty so a
      // wallet switch never leaves the previous holder's credentials behind.
      if (!indexRaw) {
        set({ credentials: [] });
        return;
      }

      try {
        const index: Array<Omit<StoredCredential, "sdJwt">> =
          JSON.parse(indexRaw);
        const credentials: StoredCredential[] = [];

        for (const entry of index) {
          const sdJwt = await storage.get(credentialKey(namespace, entry.id));
          if (sdJwt) {
            credentials.push({ ...entry, sdJwt });
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

      // Store index (without raw SD-JWT to keep index small)
      const index = credentials.map(({ sdJwt: _, ...rest }) => rest);
      await storage.set(indexKey(namespace), JSON.stringify(index));

      // Store each SD-JWT separately
      for (const cred of credentials) {
        await storage.set(credentialKey(namespace, cred.id), cred.sdJwt);
      }
    },

    reset() {
      set({ credentials: [] });
    },
  }));
}
