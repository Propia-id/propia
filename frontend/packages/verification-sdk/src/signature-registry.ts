import { ErrorCode } from "./types.js";
import { VerificationError } from "./errors.js";
import {
  ethCall,
  RpcError,
  encodeAddress,
  encodeFunctionCall,
  decodeBytes32,
  decodeUint64,
} from "./rpc.js";

export interface SignatureRecord {
  /** r component, 32 bytes */
  r: Uint8Array;
  /** s component, 32 bytes */
  s: Uint8Array;
  /** Block timestamp of the recording transaction. 0 means no record. */
  recordedAt: number;
}

/**
 * Read a signature record from the on-chain signature registry.
 *
 * `getRecord(address,bytes32)` returns a struct of three static members, so the
 * ABI encodes it inline: slots 0 (r), 1 (s), 2 (recordedAt). Absent records come
 * back zeroed, which is how `recordedAt === 0` signals "not recorded".
 */
export async function readSignatureRecord(
  rpcUrl: string,
  signatureRegistryAddress: string,
  signerAddress: string,
  digest: Uint8Array,
): Promise<SignatureRecord> {
  const calldata = encodeFunctionCall("getRecord(address,bytes32)", [
    encodeAddress(signerAddress),
    digest,
  ]);

  let result: string;
  try {
    result = await ethCall(rpcUrl, signatureRegistryAddress, calldata);
  } catch (e) {
    if (e instanceof RpcError) {
      throw new VerificationError(
        `Failed to read the signature record for ${signerAddress}`,
        ErrorCode.PARSE_ERROR,
      );
    }
    throw e;
  }

  // 3 slots × 64 hex chars + "0x"
  if (!result || result.length < 2 + 3 * 64) {
    return { r: new Uint8Array(32), s: new Uint8Array(32), recordedAt: 0 };
  }

  return {
    r: decodeBytes32(result, 0),
    s: decodeBytes32(result, 1),
    recordedAt: decodeUint64(result, 2),
  };
}
