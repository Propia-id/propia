import { ErrorCode, type HolderKeyData, type HolderPasskey } from "./types";
import { VerificationError, validateEthAddress } from "./errors";
import {
  ethCall,
  RpcError,
  encodeFunctionCall,
  decodeBytes32,
  decodeUint8,
  decodeUint64,
} from "./rpc";

/** AlignedAccount Key.keyType enum value for WebAuthn P-256 keys. */
const KEY_TYPE_WEBAUTHN_P256 = 2;

/** Cap on keys enumerated, to bound RPC work against a hostile account. */
const MAX_HOLDER_KEYS = 32;

/**
 * Resolve the holder's active WebAuthn passkeys from their on-chain AlignedAccount.
 *
 * The holder's DID address is an EOA delegated (EIP-7702) to Aligned's
 * `AlignedAccount`. Keys are enumerated via `getUserKeysCount()` /
 * `getKeyHashAt(uint256)` / `getUserKeyByHash(bytes32)`, then filtered to active
 * WebAuthnP256 keys (`keyType == 2`, `validAt <= now`). Mirrors the backend
 * reference resolver `Sovra.Ethereum.WalletReader.read_aligned_keys/1`.
 *
 * Returns every currently-usable passkey; the caller accepts a holder proof
 * that verifies against any of them. Throws HOLDER_NOT_FOUND when the account
 * has no code on this chain (e.g. not yet EIP-7702-delegated) or exposes no
 * active WebAuthnP256 key.
 */
export async function resolveHolderKeys(
  rpcUrl: string,
  holderAddress: string,
): Promise<HolderKeyData> {
  let countHex: string;
  try {
    countHex = await ethCall(
      rpcUrl,
      holderAddress,
      encodeFunctionCall("getUserKeysCount()", []),
    );
  } catch (e) {
    if (e instanceof RpcError) {
      throw new VerificationError(
        `Holder DID not found: ${holderAddress}`,
        ErrorCode.HOLDER_NOT_FOUND,
      );
    }
    throw e;
  }

  // No contract code at the address (e.g. account not delegated on this chain)
  // returns empty "0x" calldata.
  if (!countHex || countHex === "0x" || countHex.length < 66) {
    throw new VerificationError(
      `Holder DID not found: ${holderAddress}`,
      ErrorCode.HOLDER_NOT_FOUND,
    );
  }

  const count = Math.min(decodeUint64(countHex, 0), MAX_HOLDER_KEYS);
  const nowSeconds = Math.floor(Date.now() / 1000);

  const resolved = await Promise.all(
    Array.from({ length: count }, (_, i) =>
      resolveKeyAtIndex(rpcUrl, holderAddress, i, nowSeconds),
    ),
  );

  const passkeys = resolved.filter((k): k is HolderPasskey => k !== null);

  if (passkeys.length === 0) {
    throw new VerificationError(
      `Holder DID has no active passkey: ${holderAddress}`,
      ErrorCode.HOLDER_NOT_FOUND,
    );
  }

  return { passkeys };
}

async function resolveKeyAtIndex(
  rpcUrl: string,
  holderAddress: string,
  index: number,
  nowSeconds: number,
): Promise<HolderPasskey | null> {
  try {
    const keyHashHex = await ethCall(
      rpcUrl,
      holderAddress,
      encodeFunctionCall("getKeyHashAt(uint256)", [uint256Bytes(index)]),
    );
    if (!keyHashHex || keyHashHex.length < 66) return null;
    const keyHash = decodeBytes32(keyHashHex, 0);

    const keyHex = await ethCall(
      rpcUrl,
      holderAddress,
      encodeFunctionCall("getUserKeyByHash(bytes32)", [keyHash]),
    );
    return decodeActiveWebAuthnKey(keyHex, nowSeconds);
  } catch (e) {
    if (e instanceof RpcError) return null;
    throw e;
  }
}

/**
 * Decode `getUserKeyByHash` → `Key { uint8 keyType; uint48 validAt; bytes publicKey }`.
 * Returns the {x,y} coordinates iff the key is an active WebAuthnP256 key, else null.
 *
 * ABI return layout (32-byte words):
 *   0: struct offset (0x20)   1: keyType   2: validAt
 *   3: publicKey offset (0x60)   4: publicKey length (== 64)   5: x   6: y
 */
function decodeActiveWebAuthnKey(
  keyHex: string,
  nowSeconds: number,
): HolderPasskey | null {
  const hex = keyHex.startsWith("0x") ? keyHex.slice(2) : keyHex;
  // Need the full 7-word return (struct header + x + y).
  if (hex.length < 7 * 64) return null;

  const keyType = decodeUint8(keyHex, 1);
  if (keyType !== KEY_TYPE_WEBAUTHN_P256) return null;

  const validAt = decodeUint64(keyHex, 2);
  if (validAt > nowSeconds) return null; // timelock not yet elapsed

  const pkLen = decodeUint64(keyHex, 4);
  if (pkLen !== 64) return null; // expect abi.encode(bytes32 x, bytes32 y)

  return {
    x: decodeBytes32(keyHex, 5),
    y: decodeBytes32(keyHex, 6),
  };
}

/** Encode a non-negative integer as minimal big-endian bytes (at least 1 byte). */
function uint256Bytes(n: number): Uint8Array {
  const bytes: number[] = [];
  let v = n;
  do {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  } while (v > 0);
  return new Uint8Array(bytes);
}

/**
 * Extract the holder address from a cnf.kid field.
 * Format: "did:sovra:0xABCD...#passkey" → "0xABCD..."
 */
export function extractHolderAddress(cnfKid: string): string {
  if (!cnfKid.startsWith("did:sovra:")) {
    throw new VerificationError(
      `Invalid cnf.kid format: ${cnfKid}`,
      ErrorCode.PARSE_ERROR,
    );
  }
  const afterPrefix = cnfKid.slice("did:sovra:".length);
  const hashIndex = afterPrefix.indexOf("#");
  const address = hashIndex >= 0 ? afterPrefix.slice(0, hashIndex) : afterPrefix;
  validateEthAddress(address, "cnf.kid");
  return address;
}
