/**
 * CBOR decoder for the mDoc subset — strict, and lossless by construction.
 *
 * ## Lossless
 *
 * Every tag comes back as a `CborTagged` holding its raw inner value. Nothing
 * is helpfully converted: tag 0 does not become a `Date`, tag 24 does not get
 * recursively decoded. That is deliberate. mDoc digests and signatures are
 * taken over encoded bytes, so a decoder that normalises on the way in makes
 * `encode(decode(x)) !== x` and silently breaks every digest computed from a
 * round-tripped value. Callers that want the inside of a tag-24 wrapper ask
 * for it explicitly via `unwrapEmbedded`.
 *
 * ## Strict
 *
 * This parses attacker-controlled input, so the rejections matter as much as
 * the parsing:
 *
 *   - indefinite-length items are refused outright (they have no deterministic
 *     form, and accepting them would let one value have two encodings)
 *   - trailing bytes are an error, not ignored — silently accepting them is a
 *     signature-bypass vector for length-prefixed structures
 *   - nesting depth and input size are capped
 *   - truncation is detected rather than yielding a short read
 */

import {
  CborError,
  CborTagged,
  type CborKey,
  type CborMap,
  type CborValue,
} from "./types.js";

/** Generous next to any real mDoc, small enough to bound a hostile parse. */
const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const MAX_DEPTH = 32;

export interface DecodeOptions {
  /** Override the default input-size cap. */
  maxBytes?: number;
  /** Override the default nesting-depth cap. */
  maxDepth?: number;
}

export function decode(bytes: Uint8Array, options: DecodeOptions = {}): CborValue {
  const maxBytes = options.maxBytes ?? MAX_INPUT_BYTES;
  if (bytes.length > maxBytes) {
    throw new CborError(`CBOR input of ${bytes.length} bytes exceeds the ${maxBytes} cap`);
  }

  const reader = new Reader(bytes, options.maxDepth ?? MAX_DEPTH);
  const value = reader.value(0);

  if (reader.offset !== bytes.length) {
    throw new CborError(
      `${bytes.length - reader.offset} trailing byte(s) after the CBOR item`,
    );
  }
  return value;
}

/** Pull the raw inner bytes out of a `#6.24(bstr .cbor ...)` wrapper. */
export function unwrapEmbedded(value: CborValue): Uint8Array | null {
  if (value instanceof CborTagged && value.tag === 24 && value.value instanceof Uint8Array) {
    return value.value;
  }
  return null;
}

class Reader {
  offset = 0;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly maxDepth: number,
  ) {}

  value(depth: number): CborValue {
    if (depth > this.maxDepth) {
      throw new CborError(`CBOR nesting deeper than ${this.maxDepth}`);
    }

    const initial = this.byte();
    const majorType = initial >> 5;
    const additional = initial & 0x1f;

    if (additional === 31) {
      throw new CborError("indefinite-length CBOR items are not accepted");
    }

    const argument = this.argument(additional);

    switch (majorType) {
      case 0:
        return toNumber(argument);
      case 1:
        return toNumber(-1n - argument);
      case 2:
        return this.take(argument);
      case 3:
        return new TextDecoder("utf-8", { fatal: true }).decode(this.take(argument));
      case 4:
        return this.array(argument, depth);
      case 5:
        return this.map(argument, depth);
      case 6:
        return new CborTagged(Number(argument), this.value(depth + 1));
      case 7:
        return simple(initial);
      default:
        throw new CborError(`unsupported CBOR major type ${majorType}`);
    }
  }

  private array(length: bigint, depth: number): CborValue[] {
    const count = this.count(length);
    const out: CborValue[] = new Array(count);
    for (let i = 0; i < count; i++) out[i] = this.value(depth + 1);
    return out;
  }

  private map(size: bigint, depth: number): CborMap {
    const count = this.count(size);
    const out: CborMap = new Map();

    for (let i = 0; i < count; i++) {
      const key = this.value(depth + 1);
      if (typeof key !== "string" && typeof key !== "number") {
        throw new CborError("CBOR map keys must be text or integer");
      }
      // A duplicate key means two readings of the same document — one for the
      // verifier and another for anything downstream. Refuse it.
      if (out.has(key as CborKey)) {
        throw new CborError(`duplicate CBOR map key ${String(key)}`);
      }
      out.set(key as CborKey, this.value(depth + 1));
    }
    return out;
  }

  /** Guard container sizes against the remaining input before allocating. */
  private count(value: bigint): number {
    const remaining = this.bytes.length - this.offset;
    if (value > BigInt(remaining)) {
      throw new CborError("CBOR container longer than the remaining input");
    }
    return Number(value);
  }

  private argument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    if (additional === 24) return BigInt(this.byte());
    if (additional === 25) return this.uint(2);
    if (additional === 26) return this.uint(4);
    if (additional === 27) return this.uint(8);
    throw new CborError(`reserved CBOR additional information ${additional}`);
  }

  private uint(width: number): bigint {
    let out = 0n;
    for (let i = 0; i < width; i++) out = (out << 8n) | BigInt(this.byte());
    return out;
  }

  private byte(): number {
    if (this.offset >= this.bytes.length) throw new CborError("truncated CBOR input");
    return this.bytes[this.offset++];
  }

  private take(length: bigint): Uint8Array {
    const n = this.count(length);
    const out = this.bytes.subarray(this.offset, this.offset + n);
    if (out.length !== n) throw new CborError("truncated CBOR input");
    this.offset += n;
    // subarray shares the backing buffer; copy so callers can't mutate input.
    return new Uint8Array(out);
  }
}

function simple(initial: number): boolean | null {
  switch (initial) {
    case 0xf4:
      return false;
    case 0xf5:
      return true;
    case 0xf6:
      return null;
    default:
      // Includes undefined (0xf7) and every float, none of which mDoc uses.
      throw new CborError(`unsupported CBOR simple value 0x${initial.toString(16)}`);
  }
}

/** Stay in `number` while it is lossless; hand back a bigint beyond that. */
function toNumber(value: bigint): number | bigint {
  return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(value)
    : value;
}
