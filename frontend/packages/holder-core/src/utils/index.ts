import { p256 } from "@noble/curves/p256";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { sha256 as sha256Hash } from "@noble/hashes/sha256";

// ─── Hashing ──────────────────────────────────────────

export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

export function sha256(data: Uint8Array): Uint8Array {
  return sha256Hash(data);
}

// ─── Encoding ─────────────────────────────────────────

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error("Invalid hex string");
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array, prefix = true): string {
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return prefix ? `0x${hex}` : hex;
}

export function base64urlEncode(data: Uint8Array): string {
  let binary = "";
  for (const b of data) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

// ─── P256 Key Utilities ───────────────────────────────

/** Split an uncompressed P256 public key (65 bytes, 0x04 prefix) into x,y as 32-byte arrays. */
export function p256PublicKeyToXY(pubkey: Uint8Array): {
  x: Uint8Array;
  y: Uint8Array;
} {
  if (pubkey.length === 65 && pubkey[0] === 0x04) {
    return { x: pubkey.slice(1, 33), y: pubkey.slice(33, 65) };
  }
  if (pubkey.length === 64) {
    return { x: pubkey.slice(0, 32), y: pubkey.slice(32, 64) };
  }
  // Compressed: decompress first
  const point = p256.ProjectivePoint.fromHex(pubkey);
  const uncompressed = point.toRawBytes(false);
  return { x: uncompressed.slice(1, 33), y: uncompressed.slice(33, 65) };
}

/** Sign a message hash with a P256 private key. Returns r,s as 32-byte arrays. */
export function p256Sign(
  privateKey: Uint8Array,
  messageHash: Uint8Array,
): { r: Uint8Array; s: Uint8Array } {
  const sig = p256.sign(messageHash, privateKey, { lowS: true });
  const rBytes = sig.r.toString(16).padStart(64, "0");
  const sBytes = sig.s.toString(16).padStart(64, "0");
  return { r: hexToBytes(rBytes), s: hexToBytes(sBytes) };
}

/** Get the uncompressed public key (65 bytes) from a P256 private key. */
export function p256GetPublicKey(privateKey: Uint8Array): Uint8Array {
  return p256.getPublicKey(privateKey, false);
}

/**
 * Verify a P256 signature in raw `r||s` (64-byte) form against a message hash
 * and the public key's x/y coordinates.
 *
 * Low-S by default: ECDSA admits both `(r, s)` and `(r, n - s)` for the same
 * hash and key, and everything Sovra signs normalizes to low-S, so accepting
 * the malleable twin would let one logical signature travel under two distinct
 * byte-shapes. JOSE requires that canonical form.
 *
 * `lowS` is a parameter rather than a constant because it genuinely differs by
 * caller: a WebAuthn authenticator may emit either form, and rejecting high-S
 * there would fail legitimate passkeys. Pass `false` only for that.
 */
export function p256Verify(
  messageHash: Uint8Array,
  signature: Uint8Array,
  x: Uint8Array,
  y: Uint8Array,
  lowS = true,
): boolean {
  if (signature.length !== 64) return false;

  try {
    return p256.verify(
      signature,
      messageHash,
      concatBytes(new Uint8Array([0x04]), x, y),
      { lowS, format: "compact" },
    );
  } catch {
    return false;
  }
}

// ─── secp256k1 (throwaway EOA) ────────────────────────

export function generateSecp256k1KeyPair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
} {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return { privateKey, publicKey };
}

/** Derive Ethereum address from uncompressed secp256k1 public key (65 bytes). */
export function secp256k1AddressFromPublicKey(pubkey: Uint8Array): string {
  // Remove 0x04 prefix, hash remaining 64 bytes, take last 20
  const hash = keccak256(pubkey.slice(1));
  return bytesToHex(hash.slice(12), true);
}

// ─── ABI Encoding ─────────────────────────────────────

/** Pad a value to 32 bytes (left-padded for numbers/addresses, right for bytes). */
function padTo32(value: Uint8Array): Uint8Array {
  if (value.length === 32) return value;
  if (value.length > 32) throw new Error("Value exceeds 32 bytes");
  const padded = new Uint8Array(32);
  padded.set(value, 32 - value.length); // left-pad
  return padded;
}

/** Minimal ABI encode matching Solidity abi.encode for static types. */
export function encodeAbiValues(values: Uint8Array[]): Uint8Array {
  return concatBytes(...values.map(padTo32));
}

/** Encode an Ethereum address (20 bytes or hex string) as a 32-byte ABI value. */
export function encodeAddress(address: string): Uint8Array {
  return padTo32(hexToBytes(address));
}

/** Encode a bytes4 selector. */
export function encodeBytes4(data: Uint8Array): Uint8Array {
  const padded = new Uint8Array(32);
  padded.set(data.slice(0, 4), 0); // right-padded for bytes4
  return padded;
}

/** Encode a uint256 from a bigint. */
export function encodeUint256(value: bigint): Uint8Array {
  const hex = value.toString(16).padStart(64, "0");
  return hexToBytes(hex);
}

/** ABI-encode a function call: 4-byte selector + encoded params. */
export function encodeFunctionCall(
  functionSig: string,
  params: Uint8Array[],
): Uint8Array {
  const selector = keccak256(new TextEncoder().encode(functionSig)).slice(0, 4);
  return concatBytes(selector, ...params.map(padTo32));
}

// ─── ABI Decoding ─────────────────────────────────────

function stripPrefix(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}

/** Extract 32 bytes from hex return data at the given slot index. */
export function decodeBytes32(data: string, slot: number): Uint8Array {
  const hex = stripPrefix(data);
  const word = hex.slice(slot * 64, slot * 64 + 64);
  // A short slice used to yield a short array, and `bytes[31]` on it is
  // `undefined` — which reads as a set bool and a nonzero uint.
  if (word.length !== 64) {
    throw new Error(`ABI data ends before slot ${slot}`);
  }
  return hexToBytes(word);
}

/** Extract a boolean from a 32-byte ABI slot. */
export function decodeBool(data: string, slot: number): boolean {
  return decodeBytes32(data, slot)[31] !== 0;
}

/** Extract a uint8 from a 32-byte ABI slot. */
export function decodeUint8(data: string, slot: number): number {
  return decodeBytes32(data, slot)[31];
}

/** Extract a uint32 from a 32-byte ABI slot. */
export function decodeUint32(data: string, slot: number): number {
  const bytes = decodeBytes32(data, slot);
  return (bytes[28] << 24) | (bytes[29] << 16) | (bytes[30] << 8) | bytes[31];
}

/** Extract a uint64 from a 32-byte ABI slot. */
export function decodeUint64(data: string, slot: number): number {
  const bytes = decodeBytes32(data, slot);
  // JS handles integers up to 2^53 exactly, which covers every timestamp and
  // version counter the registries store.
  let value = 0;
  for (let i = 24; i < 32; i++) value = value * 256 + bytes[i];
  return value;
}

// ─── DID Registry resolve() decoder ───────────────────

export interface DecodedVerificationMethod {
  id: Uint8Array;
  keyType: number;
  pubKeyX: Uint8Array;
  pubKeyY: Uint8Array;
  relationships: number;
}

export interface DecodedServiceEndpoint {
  id: Uint8Array;
  /** keccak256 of the type string, e.g. keccak256("OpenID4VCIIssuer"). */
  serviceType: Uint8Array;
  endpoint: string;
}

export interface DecodedResolveResult {
  methods: DecodedVerificationMethod[];
  services: DecodedServiceEndpoint[];
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

  const created = decodeUint64(data, 2);
  const updated = decodeUint64(data, 3);
  const versionId = decodeUint32(data, 4);
  const deactivated = decodeBool(data, 5);

  const methodsOffset = decodeUint64(data, 0); // byte offset into the data
  const methodsStart = methodsOffset * 2; // char offset in the hex string
  // A short slice still parses: a response ending in the count word's first
  // two characters yields 0, the loop below does not run, and a truncated read
  // is reported as a DID that publishes no keys. `Number.isInteger` never
  // catches that, so the word is length-checked the way `decodeBytes32` is.
  const countWord = hex.slice(methodsStart, methodsStart + 64);
  if (countWord.length !== 64) {
    throw new Error("ABI data ends before the verification method count");
  }
  const methodsCount = parseInt(countWord, 16);
  if (!Number.isInteger(methodsCount)) {
    throw new Error("Verification method count is not a number");
  }

  const methods: DecodedVerificationMethod[] = [];
  for (let i = 0; i < methodsCount; i++) {
    // Each VerificationMethod is 5 x 32-byte words.
    const elemStart = methodsStart + 64 + i * 5 * 64;
    if (elemStart + 5 * 64 > hex.length) {
      throw new Error(`ABI data ends inside verification method ${i}`);
    }
    methods.push({
      id: hexToBytes(hex.slice(elemStart, elemStart + 64)),
      keyType: parseInt(hex.slice(elemStart + 64 + 62, elemStart + 64 + 64), 16),
      pubKeyX: hexToBytes(hex.slice(elemStart + 128, elemStart + 192)),
      pubKeyY: hexToBytes(hex.slice(elemStart + 192, elemStart + 256)),
      relationships: parseInt(
        hex.slice(elemStart + 256 + 62, elemStart + 256 + 64),
        16,
      ),
    });
  }

  const services = decodeServices(hex, decodeUint64(data, 1) * 2);

  return { methods, services, created, updated, versionId, deactivated };
}

/**
 * `ServiceEndpoint` carries a `string`, so the array is of dynamic tuples: a
 * count, then one offset per element (relative to the word after the count),
 * and each tuple holds its own offset to the string (relative to the tuple).
 */
function decodeServices(hex: string, start: number): DecodedServiceEndpoint[] {
  const wordAt = (at: number, what: string): string => {
    const w = hex.slice(at, at + 64);
    if (w.length !== 64) throw new Error(`ABI data ends before ${what}`);
    return w;
  };
  const intAt = (at: number, what: string): number => {
    const value = parseInt(wordAt(at, what), 16);
    if (!Number.isSafeInteger(value)) throw new Error(`${what} is not a number`);
    return value;
  };

  const count = intAt(start, "the service endpoint count");
  const elements = start + 64;
  const services: DecodedServiceEndpoint[] = [];
  for (let i = 0; i < count; i++) {
    const tuple = elements + intAt(elements + i * 64, `service ${i}'s offset`) * 2;
    const id = hexToBytes(wordAt(tuple, `service ${i}'s id`));
    const serviceType = hexToBytes(wordAt(tuple + 64, `service ${i}'s type`));
    const str = tuple + intAt(tuple + 128, `service ${i}'s endpoint offset`) * 2;
    const length = intAt(str, `service ${i}'s endpoint length`);
    const body = hex.slice(str + 64, str + 64 + length * 2);
    if (body.length !== length * 2) {
      throw new Error(`ABI data ends inside service ${i}'s endpoint`);
    }
    services.push({
      id,
      serviceType,
      endpoint: new TextDecoder().decode(hexToBytes(body)),
    });
  }
  return services;
}

// ─── EIP-712 ──────────────────────────────────────────

const DOMAIN_TYPEHASH = keccak256(
  new TextEncoder().encode(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
  ),
);
const NAME_HASH = keccak256(new TextEncoder().encode("SovraWallet"));
const VERSION_HASH = keccak256(new TextEncoder().encode("1"));

/** Build the EIP-712 domain separator matching SovraWalletV1._domainSeparator(). */
export function buildDomainSeparator(
  chainId: bigint,
  walletAddress: string,
): Uint8Array {
  return keccak256(
    encodeAbiValues([
      DOMAIN_TYPEHASH,
      NAME_HASH,
      VERSION_HASH,
      encodeUint256(chainId),
      encodeAddress(walletAddress),
    ]),
  );
}

/** Build the EIP-712 message hash matching SovraWalletV1._buildMessageHash(). */
export function buildEIP712MessageHash(
  domainSeparator: Uint8Array,
  operationHash: Uint8Array,
  nonce: bigint,
): Uint8Array {
  return keccak256(
    encodeAbiValues([domainSeparator, operationHash, encodeUint256(nonce)]),
  );
}

/** Build the init hash matching SovraWalletV1.initialize(). */
export function buildInitHash(
  walletAddress: string,
  chainId: bigint,
  passkeyX: Uint8Array,
  passkeyY: Uint8Array,
  recoveryKeyX: Uint8Array,
  recoveryKeyY: Uint8Array,
): Uint8Array {
  return keccak256(
    encodeAbiValues([
      encodeAddress(walletAddress),
      encodeUint256(chainId),
      passkeyX,
      passkeyY,
      recoveryKeyX,
      recoveryKeyY,
    ]),
  );
}

/** Build operation hash for initiateRecovery(newKeyX, newKeyY, keyToReplace). */
export function buildInitiateRecoveryOpHash(
  newKeyX: Uint8Array,
  newKeyY: Uint8Array,
  keyToReplace: bigint,
): Uint8Array {
  const opSelector = keccak256(new TextEncoder().encode("initiateRecovery")).slice(0, 4);
  return keccak256(concatBytes(encodeBytes4(opSelector), padTo32(newKeyX), padTo32(newKeyY), encodeUint256(keyToReplace)));
}

/** Build operation hash for finalizeRecovery. */
export function buildFinalizeRecoveryOpHash(): Uint8Array {
  const opSelector = keccak256(new TextEncoder().encode("finalizeRecovery")).slice(0, 4);
  return keccak256(encodeBytes4(opSelector));
}

/** Build operation hash for rotatePasskey/rotateRecoveryKey. */
export function buildRotateOpHash(
  operation: "rotatePasskey" | "rotateRecoveryKey",
  newX: Uint8Array,
  newY: Uint8Array,
): Uint8Array {
  const opSelector = keccak256(new TextEncoder().encode(operation)).slice(0, 4);
  return keccak256(concatBytes(encodeBytes4(opSelector), padTo32(newX), padTo32(newY)));
}

/** Build operation hash for deactivate. */
export function buildDeactivateOpHash(): Uint8Array {
  const opSelector = keccak256(
    new TextEncoder().encode("deactivate"),
  ).slice(0, 4);
  return keccak256(encodeBytes4(opSelector));
}

/** Build operation hash for execute(target, value, data). */
export function buildExecuteOpHash(
  target: string,
  value: bigint,
  data: Uint8Array,
): Uint8Array {
  // The contract does: keccak256(abi.encode(target, value, data))
  // For abi.encode with bytes, the encoding is more complex (offset + length + data)
  // We need to match Solidity's abi.encode(address, uint256, bytes)
  return keccak256(
    abiEncodeWithDynamicBytes(encodeAddress(target), encodeUint256(value), data),
  );
}

/** ABI encode (address, uint256, bytes) matching Solidity abi.encode with dynamic bytes. */
function abiEncodeWithDynamicBytes(
  addressEncoded: Uint8Array,
  valueEncoded: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  // abi.encode(address, uint256, bytes) layout:
  // slot 0: address (32 bytes)
  // slot 1: uint256 (32 bytes)
  // slot 2: offset to bytes data = 96 (0x60)
  // slot 3: length of bytes
  // slot 4+: bytes data (padded to 32-byte boundary)
  const offset = encodeUint256(96n);
  const length = encodeUint256(BigInt(data.length));
  const paddedData = new Uint8Array(Math.ceil(data.length / 32) * 32);
  paddedData.set(data);
  return concatBytes(
    padTo32(addressEncoded),
    padTo32(valueEncoded),
    offset,
    length,
    paddedData,
  );
}

// ─── EIP-7702 ─────────────────────────────────────────

/** Sign an EIP-7702 authorization tuple with a secp256k1 key. */
export function signEIP7702AuthTuple(
  privateKey: Uint8Array,
  chainId: bigint,
  implementationAddress: string,
  nonce: bigint,
): {
  chainId: bigint;
  address: string;
  nonce: bigint;
  yParity: number;
  r: string;
  s: string;
} {
  // EIP-7702 authorization: sign(keccak256(0x05 || rlp([chain_id, address, nonce])))
  const rlpEncoded = rlpEncodeAuthTuple(chainId, implementationAddress, nonce);
  const magic = new Uint8Array([0x05]);
  const msgHash = keccak256(concatBytes(magic, rlpEncoded));

  const sig = secp256k1.sign(msgHash, privateKey, { lowS: true });
  const r = sig.r.toString(16).padStart(64, "0");
  const s = sig.s.toString(16).padStart(64, "0");

  return {
    chainId,
    address: implementationAddress,
    nonce,
    yParity: sig.recovery,
    r: `0x${r}`,
    s: `0x${s}`,
  };
}

// ─── RLP Encoding (minimal, for EIP-7702) ─────────────

function rlpEncodeAuthTuple(
  chainId: bigint,
  address: string,
  nonce: bigint,
): Uint8Array {
  const items = [
    rlpEncodeInteger(chainId),
    rlpEncodeBytes(hexToBytes(address)),
    rlpEncodeInteger(nonce),
  ];
  return rlpEncodeList(items);
}

function rlpEncodeInteger(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array([0x80]); // empty string
  const hex = value.toString(16);
  const padded = hex.length % 2 ? `0${hex}` : hex;
  const bytes = hexToBytes(padded);
  return rlpEncodeBytes(bytes);
}

function rlpEncodeBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
  if (bytes.length <= 55) {
    return concatBytes(new Uint8Array([0x80 + bytes.length]), bytes);
  }
  const lenBytes = intToBytes(bytes.length);
  return concatBytes(
    new Uint8Array([0xb7 + lenBytes.length]),
    lenBytes,
    bytes,
  );
}

function rlpEncodeList(items: Uint8Array[]): Uint8Array {
  const payload = concatBytes(...items);
  if (payload.length <= 55) {
    return concatBytes(new Uint8Array([0xc0 + payload.length]), payload);
  }
  const lenBytes = intToBytes(payload.length);
  return concatBytes(
    new Uint8Array([0xf7 + lenBytes.length]),
    lenBytes,
    payload,
  );
}

function intToBytes(value: number): Uint8Array {
  const hex = value.toString(16);
  const padded = hex.length % 2 ? `0${hex}` : hex;
  return hexToBytes(padded);
}

// ─── ABI Calldata Builders ────────────────────────────

/** Build initialize() calldata matching ISovraWallet.initialize. */
export function buildInitializeCalldata(
  passkeyX: Uint8Array,
  passkeyY: Uint8Array,
  recoveryKeyX: Uint8Array,
  recoveryKeyY: Uint8Array,
  passkeyR: Uint8Array,
  passkeyS: Uint8Array,
): Uint8Array {
  return encodeFunctionCall(
    "initialize(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)",
    [passkeyX, passkeyY, recoveryKeyX, recoveryKeyY, passkeyR, passkeyS],
  );
}
