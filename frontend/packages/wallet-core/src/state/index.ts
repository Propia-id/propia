import { createStore } from "zustand/vanilla";
import type { SecureStorage } from "../platform/index";

// ─── Identity Store ───────────────────────────────────

export interface PendingRecovery {
  passkeyCredentialId: string;
  passkeyPublicKey: Uint8Array;
  initiatedAt: number;
}

export interface IdentityState {
  did: string | null;
  eoaAddress: string | null;
  passkeyCredentialId: string | null;
  passkeyPublicKey: Uint8Array | null;
  recoveryPublicKey: { x: Uint8Array; y: Uint8Array } | null;
  sessionToken: string | null;
  sessionExpiresAt: number | null;
  chainId: bigint | null;
  isOnboarded: boolean;
  pendingRecovery: PendingRecovery | null;
}

export interface IdentityActions {
  setIdentity(data: {
    did: string;
    eoaAddress: string;
    passkeyCredentialId: string;
    passkeyPublicKey: Uint8Array;
    recoveryPublicKey: { x: Uint8Array; y: Uint8Array };
    chainId: bigint;
  }): void;
  setLoginIdentity(data: {
    did: string;
    eoaAddress: string;
    chainId: bigint;
  }): void;
  setSession(token: string, expiresAt: number): void;
  clearSession(): void;
  isSessionValid(): boolean;
  setPendingRecovery(data: PendingRecovery): void;
  clearPendingRecovery(): void;
  reset(): void;
  persistToStorage(storage: SecureStorage): Promise<void>;
  loadFromStorage(storage: SecureStorage): Promise<void>;
}

export type IdentityStore = IdentityState & IdentityActions;

const IDENTITY_STORAGE_KEY = "sovra.identity";

export function createIdentityStore() {
  return createStore<IdentityStore>((set, get) => ({
    did: null,
    eoaAddress: null,
    passkeyCredentialId: null,
    passkeyPublicKey: null,
    recoveryPublicKey: null,
    sessionToken: null,
    sessionExpiresAt: null,
    chainId: null,
    isOnboarded: false,
    pendingRecovery: null,

    setIdentity(data) {
      set({
        did: data.did,
        eoaAddress: data.eoaAddress,
        passkeyCredentialId: data.passkeyCredentialId,
        passkeyPublicKey: data.passkeyPublicKey,
        recoveryPublicKey: data.recoveryPublicKey,
        chainId: data.chainId,
        isOnboarded: true,
      });
    },

    setLoginIdentity(data) {
      set({
        did: data.did,
        eoaAddress: data.eoaAddress,
        chainId: data.chainId,
        isOnboarded: true,
      });
    },

    setSession(token, expiresAt) {
      set({ sessionToken: token, sessionExpiresAt: expiresAt });
    },

    clearSession() {
      set({ sessionToken: null, sessionExpiresAt: null });
    },

    isSessionValid() {
      const { sessionToken, sessionExpiresAt } = get();
      if (!sessionToken || !sessionExpiresAt) return false;
      return Date.now() < sessionExpiresAt;
    },

    setPendingRecovery(data) {
      set({ pendingRecovery: data });
    },

    clearPendingRecovery() {
      set({ pendingRecovery: null });
    },

    reset() {
      set({
        did: null,
        eoaAddress: null,
        passkeyCredentialId: null,
        passkeyPublicKey: null,
        recoveryPublicKey: null,
        sessionToken: null,
        sessionExpiresAt: null,
        chainId: null,
        isOnboarded: false,
        pendingRecovery: null,
      });
    },

    async persistToStorage(storage) {
      const state = get();
      if (!state.isOnboarded) return;

      const serializable = {
        did: state.did,
        eoaAddress: state.eoaAddress,
        passkeyCredentialId: state.passkeyCredentialId,
        passkeyPublicKey: state.passkeyPublicKey
          ? Array.from(state.passkeyPublicKey)
          : null,
        recoveryPublicKey: state.recoveryPublicKey
          ? {
              x: Array.from(state.recoveryPublicKey.x),
              y: Array.from(state.recoveryPublicKey.y),
            }
          : null,
        chainId: state.chainId?.toString() ?? null,
        pendingRecovery: state.pendingRecovery
          ? {
              passkeyCredentialId: state.pendingRecovery.passkeyCredentialId,
              passkeyPublicKey: Array.from(state.pendingRecovery.passkeyPublicKey),
              initiatedAt: state.pendingRecovery.initiatedAt,
            }
          : null,
      };
      await storage.set(IDENTITY_STORAGE_KEY, JSON.stringify(serializable));
    },

    async loadFromStorage(storage) {
      const raw = await storage.get(IDENTITY_STORAGE_KEY);
      if (!raw) return;

      const data = JSON.parse(raw);
      set({
        did: data.did,
        eoaAddress: data.eoaAddress,
        passkeyCredentialId: data.passkeyCredentialId,
        passkeyPublicKey: data.passkeyPublicKey
          ? new Uint8Array(data.passkeyPublicKey)
          : null,
        recoveryPublicKey: data.recoveryPublicKey
          ? {
              x: new Uint8Array(data.recoveryPublicKey.x),
              y: new Uint8Array(data.recoveryPublicKey.y),
            }
          : null,
        chainId: data.chainId ? BigInt(data.chainId) : null,
        pendingRecovery: data.pendingRecovery
          ? {
              passkeyCredentialId: data.pendingRecovery.passkeyCredentialId,
              passkeyPublicKey: new Uint8Array(data.pendingRecovery.passkeyPublicKey),
              initiatedAt: data.pendingRecovery.initiatedAt,
            }
          : null,
        isOnboarded: true,
      });
    },
  }));
}

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
  loadFromStorage(storage: SecureStorage): Promise<void>;
  persistToStorage(storage: SecureStorage): Promise<void>;
}

export type CredentialStore = CredentialState & CredentialActions;

const CREDENTIALS_INDEX_KEY = "sovra.credentials.index";
const CREDENTIAL_PREFIX = "sovra.credential.";

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

    async loadFromStorage(storage) {
      const indexRaw = await storage.get(CREDENTIALS_INDEX_KEY);
      if (!indexRaw) return;

      const index: Array<Omit<StoredCredential, "sdJwt">> =
        JSON.parse(indexRaw);
      const credentials: StoredCredential[] = [];

      for (const entry of index) {
        const sdJwt = await storage.get(`${CREDENTIAL_PREFIX}${entry.id}`);
        if (sdJwt) {
          credentials.push({ ...entry, sdJwt });
        }
      }

      set({ credentials });
    },

    async persistToStorage(storage) {
      const { credentials } = get();

      // Store index (without raw SD-JWT to keep index small)
      const index = credentials.map(({ sdJwt: _, ...rest }) => rest);
      await storage.set(CREDENTIALS_INDEX_KEY, JSON.stringify(index));

      // Store each SD-JWT separately
      for (const cred of credentials) {
        await storage.set(`${CREDENTIAL_PREFIX}${cred.id}`, cred.sdJwt);
      }
    },
  }));
}
