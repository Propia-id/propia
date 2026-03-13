import { p256 } from "@noble/curves/p256";
import {
  sha256,
  base64urlDecode,
  concatBytes,
} from "@sovra/wallet-core/utils";

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
  } catch (e) {
    console.warn("[verification-sdk] ES256 verify error:", e);
    return false;
  }
}
