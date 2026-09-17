/**
 * `COSE_Sign1` (RFC 9052 §4.2) — build the signed bytes, encode, and parse.
 *
 * Signing itself lives with whoever holds the key: the wallet's `DeviceSigner`
 * for `DeviceAuth`, the backend's KMS seam for the issuer's `MSO`. This module
 * only shapes the structure and computes what a signature must cover.
 *
 * `parse` keeps `protectedBytes` and the payload byte string exactly as
 * received, and `sig1ToBeSigned` uses those. Recomputing the protected header
 * from its decoded form would produce different bytes and fail every
 * signature — treat verbatim bytes as an invariant, not an optimisation.
 */

import { encode, decode, CborError, type CborMap, type CborValue } from "../cbor/index.js";
import { COSE_HEADER } from "./alg.js";

export interface CoseSign1 {
  /** The protected header exactly as received — never re-encoded. */
  protectedBytes: Uint8Array;
  protectedHeader: CborMap;
  unprotectedHeader: CborMap;
  /** `null` for a detached payload, which is how `DeviceAuth` is transmitted. */
  payload: Uint8Array | null;
  /** Raw `r || s`, 64 bytes for P-256. */
  signature: Uint8Array;
}

/**
 * The `Sig_structure` bytes a `COSE_Sign1` signature covers (RFC 9052 §4.4).
 *
 * `payload` is passed explicitly rather than read off the structure because a
 * detached signature transmits `null` while still covering real bytes.
 */
export function sig1ToBeSigned(
  protectedBytes: Uint8Array,
  externalAad: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  return encode(["Signature1", protectedBytes, externalAad, payload]);
}

export function encodeSign1(sign1: CoseSign1): Uint8Array {
  return encode([
    sign1.protectedBytes,
    sign1.unprotectedHeader,
    sign1.payload,
    sign1.signature,
  ]);
}

export function decodeSign1(bytes: Uint8Array): CoseSign1 {
  return parseSign1(decode(bytes));
}

export function parseSign1(value: CborValue): CoseSign1 {
  if (!Array.isArray(value) || value.length !== 4) {
    throw new CborError("COSE_Sign1 must be a 4-element array");
  }

  const [protectedRaw, unprotected, payload, signature] = value;

  if (!(protectedRaw instanceof Uint8Array)) {
    throw new CborError("COSE_Sign1 protected header must be a byte string");
  }
  if (!(signature instanceof Uint8Array)) {
    throw new CborError("COSE_Sign1 signature must be a byte string");
  }
  if (payload !== null && !(payload instanceof Uint8Array)) {
    throw new CborError("COSE_Sign1 payload must be a byte string or null");
  }
  if (!(unprotected instanceof Map)) {
    throw new CborError("COSE_Sign1 unprotected header must be a map");
  }

  return {
    protectedBytes: protectedRaw,
    // An empty protected header is legal, and encodes as a zero-length byte
    // string rather than as an encoded empty map.
    protectedHeader: protectedRaw.length === 0 ? new Map() : asMap(decode(protectedRaw)),
    unprotectedHeader: unprotected,
    payload: payload as Uint8Array | null,
    signature,
  };
}

/**
 * The algorithm from the **protected** header only.
 *
 * An `alg` in the unprotected header is not covered by the signature and so
 * carries no authority; honouring one would let an attacker choose the
 * verification path. Absent means absent — never fall back.
 */
export function sign1Alg(sign1: CoseSign1): number | null {
  const alg = sign1.protectedHeader.get(COSE_HEADER.ALG);
  return typeof alg === "number" ? alg : null;
}

function asMap(value: CborValue): CborMap {
  if (!(value instanceof Map)) throw new CborError("expected a CBOR map");
  return value;
}
