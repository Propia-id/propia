/**
 * Platform-agnostic interface for plain (unencrypted) credential card art.
 *
 * Deliberately separate from `SecureStorage`: this holds bulk bytes, not key
 * material. An issuer's card logo arrives inline as a `data:` URI up to a few
 * hundred kilobytes, while the secure store is the platform keychain — its
 * advisory limit is 2048 bytes per value. Card art is not a secret; it is only
 * too big to live next to the keys.
 *
 * Implementations: ExpoAssetStorage (document directory).
 */
export interface AssetStorage {
  /** Write `base64`-decoded bytes under `key`, replacing whatever was there. */
  put(key: string, base64: string): Promise<void>;
  /**
   * A URI a native image view can load for `key`, or null when the platform
   * will not name a file for it.
   *
   * Synchronous, so a card renders the logo on its first pass rather than
   * flashing a placeholder — which also means it runs inside a React render,
   * where a throw takes the card's tree down. An implementation returns null
   * instead. The file it names may not exist either, so every caller needs a
   * fallback for both. Never persist the result: on iOS the absolute container
   * path is not stable across installs. Persist the key instead.
   */
  uriFor(key: string): string | null;
  /**
   * Read `key` back as UTF-8 text, or null when it is not there.
   *
   * For the formats a native image view cannot decode from a file — an SVG
   * logo has to be handed to a renderer as markup, not as a URI.
   */
  text(key: string): Promise<string | null>;
  /** Remove `key`. Absent keys are not an error. */
  delete(key: string): Promise<void>;
}
