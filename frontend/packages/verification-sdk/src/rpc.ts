import {
  keccak256,
  hexToBytes,
  bytesToHex,
  concatBytes,
} from "@sovrahq/holder-core/utils";

// ─── eth_call ────────────────────────────────────────

export async function ethCall(
  rpcUrl: string,
  to: string,
  data: string,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "eth_call",
        params: [{ to, data }, "latest"],
        id: 1,
      }),
      signal: controller.signal,
    });
    const json = (await res.json()) as {
      result?: string;
      error?: { message: string; data?: string };
    };
    if (json.error) {
      throw new RpcError(json.error.message, json.error.data);
    }
    return json.result ?? "0x";
  } finally {
    clearTimeout(timer);
  }
}

export class RpcError extends Error {
  constructor(
    message: string,
    public data?: string,
  ) {
    super(message);
    this.name = "RpcError";
  }
}

// ─── ABI Encoding ────────────────────────────────────

function padTo32(value: Uint8Array): Uint8Array {
  if (value.length === 32) return value;
  if (value.length > 32) throw new Error("Value exceeds 32 bytes");
  const padded = new Uint8Array(32);
  padded.set(value, 32 - value.length);
  return padded;
}

export function functionSelector(sig: string): Uint8Array {
  return keccak256(new TextEncoder().encode(sig)).slice(0, 4);
}

export function encodeAddress(address: string): Uint8Array {
  return padTo32(hexToBytes(address));
}

export function encodeFunctionCall(
  sig: string,
  params: Uint8Array[],
): string {
  const selector = functionSelector(sig);
  const encoded = concatBytes(selector, ...params.map(padTo32));
  return bytesToHex(encoded);
}

// ─── ABI Decoding ────────────────────────────────────

/** Extract 32 bytes from hex return data at the given slot index. */
export function decodeBytes32(data: string, slot: number): Uint8Array {
  const hex = stripPrefix(data);
  const start = slot * 64;
  return hexToBytes(hex.slice(start, start + 64));
}

/** Extract a boolean from a 32-byte ABI slot. */
export function decodeBool(data: string, slot: number): boolean {
  const bytes = decodeBytes32(data, slot);
  return bytes[31] !== 0;
}

/** Extract a uint32 from a 32-byte ABI slot. */
export function decodeUint32(data: string, slot: number): number {
  const bytes = decodeBytes32(data, slot);
  return (bytes[28] << 24) | (bytes[29] << 16) | (bytes[30] << 8) | bytes[31];
}

/** Extract a uint64 from a 32-byte ABI slot. */
export function decodeUint64(data: string, slot: number): number {
  const bytes = decodeBytes32(data, slot);
  // JS can safely handle integers up to 2^53, sufficient for timestamps
  let value = 0;
  for (let i = 24; i < 32; i++) {
    value = value * 256 + bytes[i];
  }
  return value;
}

/** Extract a uint8 from a 32-byte ABI slot. */
export function decodeUint8(data: string, slot: number): number {
  const bytes = decodeBytes32(data, slot);
  return bytes[31];
}

// ─── DID Registry resolve() Decoder ──────────────────

export interface DecodedVerificationMethod {
  id: Uint8Array;
  keyType: number;
  pubKeyX: Uint8Array;
  pubKeyY: Uint8Array;
  relationships: number;
}

export interface DecodedResolveResult {
  methods: DecodedVerificationMethod[];
  created: number;
  updated: number;
  versionId: number;
  deactivated: boolean;
}

/**
 * Decode the return value of SovraDIDRegistry.resolve(address).
 *
 * Return type: (VerificationMethod[] memory, ServiceEndpoint[] memory,
 *               uint64 created, uint64 updated, uint32 versionId, bool deactivated)
 *
 * ABI layout (slots):
 *   0: offset to VerificationMethod[]
 *   1: offset to ServiceEndpoint[]
 *   2: created (uint64)
 *   3: updated (uint64)
 *   4: versionId (uint32)
 *   5: deactivated (bool)
 *   Then dynamic data at the offsets.
 */
export function decodeResolveResult(data: string): DecodedResolveResult {
  const hex = stripPrefix(data);

  // Static values in slots 2-5
  const created = decodeUint64(data, 2);
  const updated = decodeUint64(data, 3);
  const versionId = decodeUint32(data, 4);
  const deactivated = decodeBool(data, 5);

  // Decode VerificationMethod[] at offset in slot 0
  const methodsOffset = decodeUint64(data, 0); // byte offset into the data
  const methodsStart = (methodsOffset * 2); // char offset in hex string
  const methodsCount = parseInt(hex.slice(methodsStart, methodsStart + 64), 16);

  const methods: DecodedVerificationMethod[] = [];
  for (let i = 0; i < methodsCount; i++) {
    // Each VerificationMethod is 5 × 32-byte words
    const elemStart = methodsStart + 64 + i * 5 * 64;
    const id = hexToBytes(hex.slice(elemStart, elemStart + 64));
    const keyType = parseInt(hex.slice(elemStart + 64 + 62, elemStart + 64 + 64), 16);
    const pubKeyX = hexToBytes(hex.slice(elemStart + 128, elemStart + 192));
    const pubKeyY = hexToBytes(hex.slice(elemStart + 192, elemStart + 256));
    const relationships = parseInt(hex.slice(elemStart + 256 + 62, elemStart + 256 + 64), 16);
    methods.push({ id, keyType, pubKeyX, pubKeyY, relationships });
  }

  return { methods, created, updated, versionId, deactivated };
}

function stripPrefix(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}
