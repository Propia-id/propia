/**
 * Platform-agnostic interface for encrypted key material storage.
 * Implementations: ExpoSecureStorage (mobile), BrowserStorage (web).
 */
export interface SecureStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
