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
  passkeyX: Uint8Array,
  passkeyY: Uint8Array,
  recoveryKeyX: Uint8Array,
  recoveryKeyY: Uint8Array,
): Uint8Array {
  return keccak256(
    encodeAbiValues([
      encodeAddress(walletAddress),
      passkeyX,
      passkeyY,
      recoveryKeyX,
      recoveryKeyY,
    ]),
  );
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
