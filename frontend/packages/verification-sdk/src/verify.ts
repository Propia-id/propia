import { sha256, base64urlEncode, keccak256, bytesToHex } from "@sovra/wallet-core/utils";
import type { VerifyOptions, VerificationResult } from "./types";
import { ErrorCode } from "./types";
import { parsePresentation, VerificationError } from "./parse";
import { verifyES256, verifyCompoundSignature } from "./signature";
import { verifyDisclosures } from "./disclosure";
import { resolveIssuerDID, checkIssuerTrust } from "./resolve-issuer";
import { resolveHolderKeys, extractHolderAddress } from "./resolve-holder";
import { VerificationCache } from "./cache";

/** Module-level default cache shared across calls. */
export const _defaultCache = new VerificationCache();

/**
 * Verify an SD-JWT credential presentation.
 *
 * Runs the full 12-step verification pipeline:
 * 1. Parse SD-JWT presentation
 * 2. Decode issuer JWT (iss, sub, vct, cnf, exp, iat, _sd)
 * 3. Resolve issuer DID → assertionMethod public key
 * 4. Verify issuer signature (ES256)
 * 5. Check issuer trust → IssuerRegistry.isTrusted()
 * 6. Verify disclosures → hash each, check against _sd array
 * 7. Check credential expiry
 * 8. Check revocation (TBD)
 * 9. Resolve holder DID → passkey + server public keys
 * 10. Verify KB-JWT compound signature (2-of-2)
 * 11. Validate KB-JWT claims (aud, nonce, iat, sd_hash)
 * 12. Return result
 */
export async function verify(
  sdJwt: string,
  options: VerifyOptions,
  cache: VerificationCache = _defaultCache,
): Promise<VerificationResult> {
  const maxClockSkew = options.maxClockSkew ?? 60;

  try {
    // Step 1-2: Parse presentation
    const presentation = parsePresentation(sdJwt);
    const { issuerPayload, issuerJwtRaw, kbJwtRaw, kbPayload, disclosures } = presentation;

    const iss = issuerPayload.iss as string;
    const vct = issuerPayload.vct as string;
    const iat = issuerPayload.iat as number;
    const exp = issuerPayload.exp as number | undefined;
    const sdArray = (issuerPayload._sd as string[]) ?? [];
    const sdAlg = (issuerPayload._sd_alg as string) ?? "sha-256";
    const cnf = issuerPayload.cnf as { kid: string } | undefined;

    // Extract issuer address from DID
    const issuerAddress = extractDIDAddress(iss);

    // Step 3: Resolve issuer DID
    let issuerKeys = cache.getIssuerKeys(issuerAddress);
    if (!issuerKeys) {
      issuerKeys = await resolveIssuerDID(
        options.l2RpcUrl,
        options.didRegistryAddress,
        issuerAddress,
      );
      cache.setIssuerKeys(issuerAddress, issuerKeys);
    }

    // Step 4: Verify issuer signature
    if (!verifyES256(issuerJwtRaw, issuerKeys.pubKeyX, issuerKeys.pubKeyY)) {
      throw new VerificationError(
        "Issuer signature verification failed",
        ErrorCode.ISSUER_SIG_INVALID,
      );
    }

    // Step 5: Check issuer trust
    const typeId = bytesToHex(keccak256(new TextEncoder().encode(vct)), false);
    const cachedTrust = cache.getIssuerTrust(issuerAddress, typeId);
    if (cachedTrust === null) {
      await checkIssuerTrust(
        options.l2RpcUrl,
        options.issuerRegistryAddress,
        issuerAddress,
        vct,
      );
      cache.setIssuerTrust(issuerAddress, typeId, true);
    } else if (!cachedTrust) {
      throw new VerificationError(
        `Issuer not trusted for credential type ${vct}`,
        ErrorCode.ISSUER_NOT_TRUSTED,
      );
    }

    // Step 6: Verify disclosures
    const claims = verifyDisclosures(disclosures, sdArray, sdAlg, issuerPayload);

    // Step 7: Check credential expiry
    const now = Math.floor(Date.now() / 1000);
    if (exp !== undefined && exp < now - maxClockSkew) {
      throw new VerificationError(
        `Credential expired at ${new Date(exp * 1000).toISOString()}`,
        ErrorCode.CREDENTIAL_EXPIRED,
      );
    }

    // Step 8: Check revocation (TBD - not implemented yet)
    // if (options.checkRevocation !== false) { ... }

    // Step 9: Resolve holder DID
    if (!cnf?.kid) {
      throw new VerificationError("Missing cnf.kid in credential", ErrorCode.PARSE_ERROR);
    }
    const holderAddress = extractHolderAddress(cnf.kid);

    let holderKeys = cache.getHolderKeys(holderAddress);
    if (!holderKeys) {
      holderKeys = await resolveHolderKeys(options.l2RpcUrl, holderAddress);
      cache.setHolderKeys(holderAddress, holderKeys);
    }

    // Step 10: Verify compound KB-JWT signature
    verifyCompoundSignature(
      kbJwtRaw,
      holderKeys.passkeyX,
      holderKeys.passkeyY,
      holderKeys.serverKeyX,
      holderKeys.serverKeyY,
    );

    // Step 11: Validate KB-JWT claims
    const kbAud = kbPayload.aud as string;
    const kbNonce = kbPayload.nonce as string;
    const kbIat = kbPayload.iat as number;
    const kbSdHash = kbPayload.sd_hash as string;

    if (kbAud !== options.expectedAudience) {
      throw new VerificationError(
        `KB-JWT audience mismatch: expected ${options.expectedAudience}, got ${kbAud}`,
        ErrorCode.KB_AUDIENCE_MISMATCH,
      );
    }

    if (kbNonce !== options.expectedNonce) {
      throw new VerificationError(
        `KB-JWT nonce mismatch: expected ${options.expectedNonce}, got ${kbNonce}`,
        ErrorCode.KB_NONCE_MISMATCH,
      );
    }

    if (Math.abs(kbIat - now) > maxClockSkew) {
      throw new VerificationError(
        "KB-JWT iat is too old or in the future",
        ErrorCode.KB_EXPIRED,
      );
    }

    // Verify sd_hash: SHA-256 of everything before the KB-JWT
    // Format: issuerJwt~disc1~disc2~...~
    const disclosurePart = disclosures.map((d) => d.encoded).join("~");
    const hashInput = `${issuerJwtRaw}~${disclosurePart}~`;
    const expectedSdHash = base64urlEncode(
      sha256(new TextEncoder().encode(hashInput)),
    );

    if (kbSdHash !== expectedSdHash) {
      throw new VerificationError(
        "KB-JWT sd_hash does not match presentation content",
        ErrorCode.KB_SD_HASH_MISMATCH,
      );
    }

    // Step 12: Return success
    return {
      valid: true,
      claims,
      issuer: iss,
      holder: `did:sovra:${holderAddress}`,
      credentialType: vct,
      issuedAt: iat,
      expiresAt: exp,
    };
  } catch (e) {
    if (e instanceof VerificationError) {
      return {
        valid: false,
        error: e.message,
        errorCode: e.code,
      };
    }
    return {
      valid: false,
      error: e instanceof Error ? e.message : "Unknown verification error",
    };
  }
}

function extractDIDAddress(did: string): string {
  if (!did.startsWith("did:sovra:")) {
    throw new VerificationError(`Invalid DID format: ${did}`, ErrorCode.PARSE_ERROR);
  }
  return did.slice("did:sovra:".length);
}
