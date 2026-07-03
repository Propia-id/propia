import { createStore } from "zustand/vanilla";
import type { SecureStorage } from "../platform/index";

// ─── Credential Store ─────────────────────────────────

export interface StoredCredential {
  id: string;
  sdJwt: string;
  issuerDid: string;
  credentialType: string;
  issuerName: string;
  issuedAt: number;
  expiresAt: number;
  claims: Record<string, unknown>;
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
