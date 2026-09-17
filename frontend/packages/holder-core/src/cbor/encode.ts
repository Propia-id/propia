/**
 * Deterministic CBOR encoder (RFC 8949 §4.2).
 *
 * Must produce byte-identical output to `Sovra.Cbor` in the backend for the
 * same logical value — the `SessionTranscript` is built independently on both
 * sides and then signed, so any divergence surfaces as a signature failure with
 * no other symptom. The shared test vectors are the contract.
 *
 * Map keys are sorted by their *encoded* form, shortest first and then
 * bytewise. That is RFC 7049 §3.9 canonical ordering, which ISO/IEC 18013-5
 * §9.1.2.1 cites. RFC 8949 core-deterministic drops the length-first step; the
 * two coincide for every map mDoc emits, and `keyOrder` is the single place to
 * change if that ever stops being true.
 */

import { concatBytes } from "../utils/index.js";
import { CborError, CborTagged, type CborKey, type CborMap, type CborValue } from "./types.js";

const MT_UINT = 0;
const MT_NEGINT = 1;
const MT_BYTES = 2;
const MT_TEXT = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_TAG = 6;

const FALSE = 0xf4;
const TRUE = 0xf5;
const NULL = 0xf6;

export function encode(value: CborValue): Uint8Array {
  return concatBytes(...enc(value));
}

function enc(value: CborValue): Uint8Array[] {
  if (typeof value === "number" || typeof value === "bigint") return encInteger(value);
  if (typeof value === "string") return encText(value);
  if (value instanceof Uint8Array) return [head(MT_BYTES, value.length), value];
  if (value === null) return [new Uint8Array([NULL])];
  if (typeof value === "boolean") return [new Uint8Array([value ? TRUE : FALSE])];
  if (value instanceof CborTagged) return [head(MT_TAG, value.tag), ...enc(value.value)];
  if (Array.isArray(value)) return [head(MT_ARRAY, value.length), ...value.flatMap(enc)];
  if (value instanceof Map) return encMap(value);

  throw new CborError(`no deterministic CBOR encoding for ${describe(value)}`);
}

function encInteger(value: number | bigint): Uint8Array[] {
  if (typeof value === "number" && !Number.isInteger(value)) {
    // Floats are rejected rather than encoded: no deterministic form without
    // shortest-float selection, and mDoc never needs one. Failing here beats
    // emitting bytes a verifier would hash differently.
    throw new CborError(`no deterministic CBOR encoding for the non-integer ${value}`);
  }
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new CborError(`integer ${value} exceeds safe range — pass a bigint`);
  }

  const n = typeof value === "bigint" ? value : BigInt(value);
  return n >= 0n ? [head(MT_UINT, n)] : [head(MT_NEGINT, -1n - n)];
}

function encText(value: string): Uint8Array[] {
  const bytes = new TextEncoder().encode(value);
  return [head(MT_TEXT, bytes.length), bytes];
}

function encMap(map: CborMap): Uint8Array[] {
  const entries = [...map.entries()].map(
    ([k, v]) => [encode(assertKey(k)), v] as const,
  );
  entries.sort(([a], [b]) => keyOrder(a, b));

  const out: Uint8Array[] = [head(MT_MAP, map.size)];
  for (const [keyBytes, v] of entries) {
    out.push(keyBytes, ...enc(v));
  }
  return out;
}

function assertKey(key: CborKey): CborValue {
  if (typeof key === "string" || typeof key === "number") return key;
  throw new CborError(`CBOR map keys must be text or integer, got ${describe(key)}`);
}

/** RFC 7049 §3.9: shorter encoded keys first, then bytewise. */
function keyOrder(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

/** Shortest-form argument encoding — required for determinism. */
function head(majorType: number, argument: number | bigint): Uint8Array {
  const n = typeof argument === "bigint" ? argument : BigInt(argument);
  const mt = majorType << 5;

  if (n < 24n) return new Uint8Array([mt | Number(n)]);
  if (n < 0x100n) return new Uint8Array([mt | 24, Number(n)]);
  if (n < 0x10000n) return new Uint8Array([mt | 25, Number(n >> 8n) & 0xff, Number(n) & 0xff]);

  if (n < 0x100000000n) {
    return new Uint8Array([
      mt | 26,
      Number((n >> 24n) & 0xffn),
      Number((n >> 16n) & 0xffn),
      Number((n >> 8n) & 0xffn),
      Number(n & 0xffn),
    ]);
  }

  if (n < 0x10000000000000000n) {
    const out = new Uint8Array(9);
    out[0] = mt | 27;
    for (let i = 0; i < 8; i++) out[8 - i] = Number((n >> BigInt(i * 8)) & 0xffn);
    return out;
  }

  throw new CborError(`argument ${n} exceeds the 64-bit CBOR head`);
}

function describe(value: unknown): string {
  if (value === undefined) return "undefined";
  if (typeof value === "object" && value !== null) return value.constructor?.name ?? "object";
  return `${typeof value} ${String(value)}`;
}
