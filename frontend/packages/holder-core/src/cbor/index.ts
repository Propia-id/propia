/**
 * Deterministic CBOR for ISO/IEC 18013-5 mDoc and COSE.
 *
 * Hand-rolled rather than taken from a library, for four reasons that all still
 * hold: COSE has to be written here regardless (no React Native-viable library
 * exists — they want Node `crypto`, `Buffer`, or WebCrypto, and the wallet's
 * polyfill supplies only `getRandomValues`); byte-preservation on the way
 * through is a correctness requirement that a general canonicaliser can only be
 * hoped to satisfy; the subset mDoc needs is closed and small; and the wallet's
 * Metro config (`disableHierarchicalLookup`, fixed `nodeModulesPaths`) makes a
 * dependency with conditional exports or an optional native addon a debugging
 * session rather than an install. `utils/index.ts` already hand-rolls RLP and
 * ABI encoding for the same reasons.
 *
 * Shared by the wallet and `@sovrahq/verification-sdk`, and required to agree
 * byte-for-byte with the backend's `Sovra.Cbor`.
 */

export { encode } from "./encode.js";
export { decode, unwrapEmbedded, type DecodeOptions } from "./decode.js";
export {
  CBOR_TAG,
  CborError,
  CborTagged,
  type CborKey,
  type CborMap,
  type CborValue,
} from "./types.js";

import { encode } from "./encode.js";
import { CborTagged } from "./types.js";

/**
 * Wrap a value as `#6.24(bstr .cbor value)`.
 *
 * mDoc hashes and signs these wrappers, never the bare inner value, so this and
 * `unwrapEmbedded` are the only places tag 24 is constructed or opened.
 */
export function embed(value: Parameters<typeof encode>[0]): CborTagged {
  return embedEncoded(encode(value));
}

/**
 * Wrap already-encoded CBOR as `#6.24(bstr .cbor ...)`.
 *
 * `embed` when the value still needs encoding; this when the bytes came off the
 * wire and must not be re-encoded. Rebuilding a wrapper around an untouched
 * payload is safe, and normalising: both heads come out shortest-form, the only
 * form ISO 18013-5 permits, so it lands on the bytes the issuer signed. A map
 * cannot be treated this way — key order is unconstrained, so a signed map has
 * to be kept verbatim.
 */
export function embedEncoded(bytes: Uint8Array): CborTagged {
  return new CborTagged(24, bytes);
}

/** A `full-date` (tag 1004) — the `YYYY-MM-DD` form mDoc uses for plain dates. */
export function fullDate(date: string): CborTagged {
  return new CborTagged(1004, date);
}

/** A `tdate` (tag 0), truncated to the second as 18013-5 requires. */
export function tdate(date: Date): CborTagged {
  return new CborTagged(0, `${new Date(Math.floor(date.getTime() / 1000) * 1000).toISOString().slice(0, 19)}Z`);
}
