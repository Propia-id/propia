import { keccak256, bytesToHex, hexToBytes } from "@sovra/wallet-core/utils";
import { ErrorCode, type HolderKeyData } from "./types";
import { VerificationError } from "./parse";
import { ethCall, RpcError, decodeBytes32, decodeBool, decodeUint32 } from "./rpc";

/**
 * Resolve holder keys from the on-chain wallet contract.
 *
 * The holder's address is their EIP-7702 wallet contract.
 * We read the public key coordinates and DID state directly.
 */
export async function resolveHolderKeys(
  rpcUrl: string,
  holderAddress: string,
): Promise<HolderKeyData> {
  // Build calldata for each view function (just the 4-byte selector, no params)
  const selectors = {
    passkeyX: selectorHex("passkeyX()"),
    passkeyY: selectorHex("passkeyY()"),
    recoveryKeyX: selectorHex("recoveryKeyX()"),
    recoveryKeyY: selectorHex("recoveryKeyY()"),
    didDeactivated: selectorHex("didDeactivated()"),
    didVersionId: selectorHex("didVersionId()"),
  };

  // Execute all calls in parallel
  let results: string[];
  try {
    results = await Promise.all([
      ethCall(rpcUrl, holderAddress, selectors.passkeyX),
      ethCall(rpcUrl, holderAddress, selectors.passkeyY),
      ethCall(rpcUrl, holderAddress, selectors.recoveryKeyX),
      ethCall(rpcUrl, holderAddress, selectors.recoveryKeyY),
      ethCall(rpcUrl, holderAddress, selectors.didDeactivated),
      ethCall(rpcUrl, holderAddress, selectors.didVersionId),
    ]);
  } catch (e) {
    if (e instanceof RpcError) {
      throw new VerificationError(
        `Holder DID not found: ${holderAddress}`,
        ErrorCode.HOLDER_NOT_FOUND,
      );
    }
    throw e;
  }

  // Check for empty results (no contract at address)
  if (results.some((r) => !r || r === "0x" || r.length < 66)) {
    throw new VerificationError(
      `Holder DID not found: ${holderAddress}`,
      ErrorCode.HOLDER_NOT_FOUND,
    );
  }

  const deactivated = decodeBool(results[4], 0);
  if (deactivated) {
    throw new VerificationError(
      `Holder DID deactivated: ${holderAddress}`,
      ErrorCode.HOLDER_DEACTIVATED,
    );
  }

  return {
    passkeyX: decodeBytes32(results[0], 0),
    passkeyY: decodeBytes32(results[1], 0),
    recoveryKeyX: decodeBytes32(results[2], 0),
    recoveryKeyY: decodeBytes32(results[3], 0),
    versionId: decodeUint32(results[5], 0),
  };
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
  return hashIndex >= 0 ? afterPrefix.slice(0, hashIndex) : afterPrefix;
}

function selectorHex(sig: string): string {
  const bytes = keccak256(new TextEncoder().encode(sig)).slice(0, 4);
  return bytesToHex(bytes);
}
