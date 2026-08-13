import { keccak256 } from "@sovrahq/holder-core/utils";
import { ErrorCode, type IssuerKeyData } from "./types";
import { VerificationError } from "./errors";
import {
  ethCall,
  RpcError,
  encodeAddress,
  encodeFunctionCall,
  decodeResolveResult,
  decodeBool,
} from "./rpc";

/**
 * Resolve an issuer's DID from the on-chain DID Registry.
 * Returns the P256 assertionMethod public key.
 */
export async function resolveIssuerDID(
  rpcUrl: string,
  didRegistryAddress: string,
  issuerAddress: string,
): Promise<IssuerKeyData> {
  const calldata = encodeFunctionCall(
    "resolve(address)",
    [encodeAddress(issuerAddress)],
  );

  let result: string;
  try {
    result = await ethCall(rpcUrl, didRegistryAddress, calldata);
  } catch (e) {
    if (e instanceof RpcError) {
      throw new VerificationError(
        `Issuer DID not found: ${issuerAddress}`,
        ErrorCode.ISSUER_NOT_FOUND,
      );
    }
    throw e;
  }

  // Empty result or just 0x means no DID
  if (!result || result === "0x" || result.length < 66) {
    throw new VerificationError(
      `Issuer DID not found: ${issuerAddress}`,
      ErrorCode.ISSUER_NOT_FOUND,
    );
  }

  const decoded = decodeResolveResult(result);

  if (decoded.deactivated) {
    throw new VerificationError(
      `Issuer DID deactivated: ${issuerAddress}`,
      ErrorCode.ISSUER_DEACTIVATED,
    );
  }

  if (decoded.methods.length === 0) {
    throw new VerificationError(
      `Issuer DID has no verification methods: ${issuerAddress}`,
      ErrorCode.ISSUER_NOT_FOUND,
    );
  }

  // Find the P256 assertionMethod key
  // keyType 0 = P256, relationships bit 1 = assertionMethod (0x02)
  const assertionKey = decoded.methods.find(
    (m) => m.keyType === 0 && (m.relationships & 0x02) !== 0,
  );

  if (!assertionKey) {
    throw new VerificationError(
      `Issuer DID has no P256 assertionMethod key: ${issuerAddress}`,
      ErrorCode.ISSUER_NOT_FOUND,
    );
  }

  return {
    pubKeyX: assertionKey.pubKeyX,
    pubKeyY: assertionKey.pubKeyY,
    versionId: decoded.versionId,
  };
}

/**
 * Check whether an issuer is trusted for a given credential type
 * by querying the on-chain Issuer Registry.
 */
export async function checkIssuerTrust(
  rpcUrl: string,
  issuerRegistryAddress: string,
  issuerAddress: string,
  vct: string,
): Promise<void> {
  // credentialTypeId = keccak256(utf8(vct))
  const credentialTypeId = keccak256(new TextEncoder().encode(vct));

  const calldata = encodeFunctionCall(
    "isTrusted(address,bytes32)",
    [encodeAddress(issuerAddress), credentialTypeId],
  );

  let result: string;
  try {
    result = await ethCall(rpcUrl, issuerRegistryAddress, calldata);
  } catch (e) {
    if (e instanceof RpcError) {
      throw new VerificationError(
        `Failed to check issuer trust: ${issuerAddress}`,
        ErrorCode.ISSUER_NOT_TRUSTED,
      );
    }
    throw e;
  }

  const trusted = decodeBool(result, 0);
  if (!trusted) {
    throw new VerificationError(
      `Issuer not trusted for credential type ${vct}: ${issuerAddress}`,
      ErrorCode.ISSUER_NOT_TRUSTED,
    );
  }
}
