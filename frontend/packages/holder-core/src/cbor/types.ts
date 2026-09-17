/**
 * CBOR value model, scoped to the subset ISO/IEC 18013-5 mDoc and COSE use.
 *
 * Deliberately excluded: floats, indefinite-length items, bignums, and the
 * simple values beyond true/false/null. mDoc needs none of them, and floats in
 * particular have no deterministic encoding without shortest-float selection.
 *
 * The split TypeScript gives us for free — `Uint8Array` is a byte string,
 * `string` is a text string — is the distinction Elixir needs an explicit
 * `bstr/1` wrapper for. Getting it backwards changes every digest taken over
 * the value, so the types carry the whole burden here.
 */

/** A tagged value. Tag 24 (embedded CBOR) and 1004 (full-date) are the ones mDoc uses. */
export class CborTagged {
  constructor(
    readonly tag: number,
    readonly value: CborValue,
  ) {}
}

/**
 * Map keys are text or integer only.
 *
 * A `Map` rather than a plain object because CBOR maps admit integer keys —
 * COSE headers and COSE_Key are keyed by small signed integers — and an object
 * would silently stringify them.
 */
export type CborKey = number | string;

export type CborMap = Map<CborKey, CborValue>;

export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | CborValue[]
  | CborMap
  | CborTagged;

/** Tag numbers this codebase constructs or inspects. */
export const CBOR_TAG = {
  /** RFC 8949 §3.4.1 — standard date/time string. */
  DATE_TIME: 0,
  /** RFC 8949 §3.4.5.1 — embedded CBOR data item. */
  EMBEDDED: 24,
  /** RFC 8943 — a `YYYY-MM-DD` date with no time. */
  FULL_DATE: 1004,
} as const;

export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborError";
  }
}
