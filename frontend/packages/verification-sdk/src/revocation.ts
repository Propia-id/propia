import { hexToBytes, concatBytes, bytesToHex } from "@sovrahq/holder-core/utils";
import { ErrorCode } from "./types";
import { VerificationError } from "./errors";
import { ethCall, RpcError, functionSelector, decodeBool } from "./rpc";

const REVOCATION = 0;

/**
 * Check a single credential's revocation status by calling
 * getStatus(address,uint8,uint256) on the RevocationRegistry contract.
 *
 * Returns true if the credential is revoked/suspended.
 */
export async function checkRevocation(
  rpcUrl: string,
  registryAddress: string,
  issuerAddress: string,
  statusListIndex: number,
  purpose: number = REVOCATION,
): Promise<boolean> {
  const selector = functionSelector("getStatus(address,uint8,uint256)");

  // ABI-encode: address (32 bytes) + uint8 (32 bytes) + uint256 (32 bytes)
  const addressParam = padTo32(hexToBytes(issuerAddress));
  const purposeParam = padTo32(new Uint8Array([purpose]));
  const indexParam = numberToUint256(statusListIndex);

  const calldata = bytesToHex(
    concatBytes(selector, addressParam, purposeParam, indexParam),
  );

  let result: string;
  try {
    result = await ethCall(rpcUrl, registryAddress, calldata);
  } catch (e) {
    if (e instanceof RpcError) {
      throw new VerificationError(
        "Failed to check revocation status",
        ErrorCode.CREDENTIAL_REVOKED,
      );
    }
    throw e;
  }

  return decodeBool(result, 0);
}

function padTo32(value: Uint8Array): Uint8Array {
  if (value.length === 32) return value;
  if (value.length > 32) throw new Error("Value exceeds 32 bytes");
  const padded = new Uint8Array(32);
  padded.set(value, 32 - value.length);
  return padded;
}

function numberToUint256(n: number): Uint8Array {
  const buf = new Uint8Array(32);
  // Write as big-endian. JS numbers are safe up to 2^53.
  let remaining = n;
  for (let i = 31; i >= 0 && remaining > 0; i--) {
    buf[i] = remaining & 0xff;
    remaining = Math.floor(remaining / 256);
  }
  return buf;
}
