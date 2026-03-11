import { p256 } from "@noble/curves/p256";
import {
  sha256,
  base64urlDecode,
  concatBytes,
} from "@sovra/wallet-core/utils";
import { ErrorCode } from "./types";
import { VerificationError } from "./parse";

/**
 * Verify an ES256 (P-256) signature on a JWT.
 * Splits the JWT at the last "." to get signingInput and signature.
 */
export function verifyES256(
  jwtRaw: string,
  pubKeyX: Uint8Array,
  pubKeyY: Uint8Array,
): boolean {
  const lastDot = jwtRaw.lastIndexOf(".");
  const signingInput = jwtRaw.slice(0, lastDot);
  const sigB64 = jwtRaw.slice(lastDot + 1);

  const messageHash = sha256(new TextEncoder().encode(signingInput));
  const sigBytes = base64urlDecode(sigB64);

  if (sigBytes.length !== 64) {
    return false;
  }

  const pubKey = concatBytes(new Uint8Array([0x04]), pubKeyX, pubKeyY);

  try {
    return p256.verify(sigBytes, messageHash, pubKey, { lowS: true, format: "compact" });
  } catch {
    return false;
  }
}

/**
 * Verify the compound 2-of-2 signature on a KB-JWT.
 *
 * The signature is 128 bytes: passkey_sig (64) || server_sig (64).
 * Each 64-byte half is r (32) || s (32).
 */
export function verifyCompoundSignature(
  kbJwtRaw: string,
  passkeyX: Uint8Array,
  passkeyY: Uint8Array,
  serverKeyX: Uint8Array,
  serverKeyY: Uint8Array,
): void {
  const lastDot = kbJwtRaw.lastIndexOf(".");
  const signingInput = kbJwtRaw.slice(0, lastDot);
  const sigB64 = kbJwtRaw.slice(lastDot + 1);

  const messageHash = sha256(new TextEncoder().encode(signingInput));
  const sigBytes = base64urlDecode(sigB64);

  if (sigBytes.length !== 128) {
    throw new VerificationError(
      `Expected 128-byte compound signature, got ${sigBytes.length}`,
      ErrorCode.KB_PASSKEY_SIG_INVALID,
    );
  }

  // First 64 bytes: passkey signature
  const passkeySig = sigBytes.slice(0, 64);
  const passkeyPub = concatBytes(new Uint8Array([0x04]), passkeyX, passkeyY);

  try {
    if (!p256.verify(passkeySig, messageHash, passkeyPub, { lowS: true, format: "compact" })) {
      throw new VerificationError("Passkey signature verification failed", ErrorCode.KB_PASSKEY_SIG_INVALID);
    }
  } catch (e) {
    if (e instanceof VerificationError) throw e;
    throw new VerificationError("Passkey signature verification failed", ErrorCode.KB_PASSKEY_SIG_INVALID);
  }

  // Last 64 bytes: server signature
  const serverSig = sigBytes.slice(64, 128);
  const serverPub = concatBytes(new Uint8Array([0x04]), serverKeyX, serverKeyY);

  try {
    if (!p256.verify(serverSig, messageHash, serverPub, { lowS: true, format: "compact" })) {
      throw new VerificationError("Server signature verification failed", ErrorCode.KB_SERVER_SIG_INVALID);
    }
  } catch (e) {
    if (e instanceof VerificationError) throw e;
    throw new VerificationError("Server signature verification failed", ErrorCode.KB_SERVER_SIG_INVALID);
  }
}
