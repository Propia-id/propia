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
  readonly data?: string;

  constructor(message: string, data?: string) {
    super(message);
    this.name = "RpcError";
    this.data = data;
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

// The decoders — including the SovraDIDRegistry `resolve(address)` return
// decoder — live in holder-core so the wallet can read the same registries
// this SDK does. Re-exported here because the SDK's public surface has always
// carried them.
export {
  decodeBytes32,
  decodeBool,
  decodeUint8,
  decodeUint32,
  decodeUint64,
  decodeResolveResult,
} from "@sovrahq/holder-core/utils";

export type {
  DecodedVerificationMethod,
  DecodedServiceEndpoint,
  DecodedResolveResult,
} from "@sovrahq/holder-core/utils";
