import { sha256, base64urlEncode, keccak256, bytesToHex } from "@sovra/wallet-core/utils";
import type { VerifyOptions, VerificationResult } from "./types";
import { ErrorCode } from "./types";
import { parsePresentation } from "./parse";
import { VerificationError, validateEthAddress } from "./errors";
import { verifyES256 } from "./signature";
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
 * 9. Resolve holder DID → passkey + recovery public keys
 * 10. Verify KB-JWT passkey signature (ES256)
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

    const { iss, vct, iat, exp, sdArray, sdAlg, cnf, sub } = validateIssuerPayload(issuerPayload);

    // Extract issuer address from DID
    const issuerAddress = extractDIDAddress(iss);

    // Validate sub vs cnf.kid consistency
    if (sub && cnf?.kid) {
      const subAddr = extractDIDAddress(sub);
      const cnfAddr = extractHolderAddress(cnf.kid);
      if (subAddr.toLowerCase() !== cnfAddr.toLowerCase()) {
        throw new VerificationError(
          "Credential subject (sub) does not match holder key (cnf.kid)",
          ErrorCode.SUBJECT_KEY_MISMATCH,
        );
      }
    }

    // Steps 3-5: On-chain issuer verification (skipped in offline mode)
    if (!options.offlineMode) {
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
    }

    // Step 6: Verify disclosures
    const claims = verifyDisclosures(disclosures, sdArray, sdAlg, issuerPayload);

    // Step 7: Check credential timestamps
    const now = Math.floor(Date.now() / 1000);
    if (iat > now + maxClockSkew) {
      throw new VerificationError(
        `Credential iat is in the future: ${new Date(iat * 1000).toISOString()}`,
        ErrorCode.IAT_INVALID,
      );
    }
    if (exp !== undefined && exp < now - maxClockSkew) {
      throw new VerificationError(
        `Credential expired at ${new Date(exp * 1000).toISOString()}`,
        ErrorCode.CREDENTIAL_EXPIRED,
      );
    }

    // Step 8: Check revocation (TBD - not implemented yet)
    // if (options.checkRevocation !== false) { ... }

    // Steps 9-10: On-chain holder verification (skipped in offline mode)
    let holderAddress: string | undefined;
    if (!options.offlineMode) {
      // Step 9: Resolve holder DID
      if (!cnf?.kid) {
        throw new VerificationError("Missing cnf.kid in credential", ErrorCode.PARSE_ERROR);
      }
      holderAddress = extractHolderAddress(cnf.kid);

      let holderKeys = cache.getHolderKeys(holderAddress);
      if (!holderKeys) {
        holderKeys = await resolveHolderKeys(options.l2RpcUrl, holderAddress);
        cache.setHolderKeys(holderAddress, holderKeys);
      }

      // Step 10: Verify KB-JWT passkey signature
      if (!verifyES256(kbJwtRaw, holderKeys.passkeyX, holderKeys.passkeyY)) {
        throw new VerificationError("KB-JWT signature verification failed", ErrorCode.KB_PASSKEY_SIG_INVALID);
      }
    } else if (cnf?.kid) {
      holderAddress = extractHolderAddress(cnf.kid);
    }

    // Step 11: Validate KB-JWT claims
    const { aud: kbAud, nonce: kbNonce, iat: kbIat, sd_hash: kbSdHash } = validateKbPayload(kbPayload);

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
      holder: holderAddress ? `did:sovra:${holderAddress}` : undefined,
      credentialType: vct,
      issuedAt: iat,
      expiresAt: exp,
      ...(options.offlineMode && { offlineMode: true, trustNotVerified: true }),
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
  const address = did.slice("did:sovra:".length);
  validateEthAddress(address, "DID");
  return address;
}

function validateIssuerPayload(p: Record<string, unknown>) {
  if (typeof p.iss !== "string") throw new VerificationError("iss must be a string", ErrorCode.PARSE_ERROR);
  if (typeof p.vct !== "string") throw new VerificationError("vct must be a string", ErrorCode.PARSE_ERROR);
  if (typeof p.iat !== "number") throw new VerificationError("iat must be a number", ErrorCode.PARSE_ERROR);
  if (p.exp !== undefined && typeof p.exp !== "number") throw new VerificationError("exp must be a number", ErrorCode.PARSE_ERROR);
  if (p._sd !== undefined && (!Array.isArray(p._sd) || !p._sd.every((v: unknown) => typeof v === "string"))) {
    throw new VerificationError("_sd must be a string array", ErrorCode.PARSE_ERROR);
  }
  if (p._sd_alg !== undefined && typeof p._sd_alg !== "string") throw new VerificationError("_sd_alg must be a string", ErrorCode.PARSE_ERROR);
  if (p.cnf !== undefined && (typeof p.cnf !== "object" || p.cnf === null || typeof (p.cnf as Record<string, unknown>).kid !== "string")) {
    throw new VerificationError("cnf must be an object with a string kid", ErrorCode.PARSE_ERROR);
  }
  if (p.sub !== undefined && typeof p.sub !== "string") throw new VerificationError("sub must be a string", ErrorCode.PARSE_ERROR);

  return {
    iss: p.iss as string,
    vct: p.vct as string,
    iat: p.iat as number,
    exp: p.exp as number | undefined,
    sdArray: (p._sd as string[]) ?? [],
    sdAlg: (p._sd_alg as string) ?? "sha-256",
    cnf: p.cnf as { kid: string } | undefined,
    sub: p.sub as string | undefined,
  };
}

function validateKbPayload(p: Record<string, unknown>) {
  if (typeof p.aud !== "string") throw new VerificationError("KB-JWT aud must be a string", ErrorCode.PARSE_ERROR);
  if (typeof p.nonce !== "string") throw new VerificationError("KB-JWT nonce must be a string", ErrorCode.PARSE_ERROR);
  if (typeof p.iat !== "number") throw new VerificationError("KB-JWT iat must be a number", ErrorCode.PARSE_ERROR);
  if (typeof p.sd_hash !== "string") throw new VerificationError("KB-JWT sd_hash must be a string", ErrorCode.PARSE_ERROR);

  return {
    aud: p.aud as string,
    nonce: p.nonce as string,
    iat: p.iat as number,
    sd_hash: p.sd_hash as string,
  };
}
