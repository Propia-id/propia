import { p256 } from "@noble/curves/p256";
import {
  sha256,
  base64urlDecode,
  base64urlEncode,
  concatBytes,
  hexToBytes,
} from "@sovrahq/holder-core/utils";

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

// ─── WebAuthn (passkey) KB-JWT verification ──────────────

// authenticatorData flag bits (WebAuthn Level 3, §6.1).
const FLAG_UP = 0x01; // User Present
const FLAG_UV = 0x04; // User Verified
const FLAG_BE = 0x08; // Backup Eligible
const FLAG_BS = 0x10; // Backup State

interface WebAuthnAssertion {
  r: string;
  s: string;
  authenticator_data: string;
  client_data_json: string;
  challenge_index: number;
  type_index: number;
}

/**
 * Verify a WebAuthn (passkey) key-binding JWT.
 *
 * Unlike an ES256 KB-JWT, the passkey does NOT sign the JWT signing input
 * directly. The third JWT segment is `base64url(JSON)` of a WebAuthn assertion,
 * and the authenticator signs `authenticatorData || SHA256(clientDataJSON)`,
 * where clientDataJSON embeds `challenge = base64url(SHA256(signingInput))`.
 *
 * This is a faithful port of the backend reference verifier
 * `Sovra.Crypto.WebAuthn.valid?/3` (backend/lib/sovra/crypto/web_authn.ex):
 * auth-data length, `type` prefix, `challenge` prefix, UP/UV/backup-state
 * flags, then ECDSA-P256 over the reconstructed message.
 *
 * Low-S is deliberately NOT enforced, matching the backend and the on-chain
 * OpenZeppelin WebAuthn verifier: WebAuthn authenticators may emit high-S
 * signatures. (The wallet's Aligned adapter normalizes to low-S, so this only
 * affects interoperability with other conformant signers, never the wallet.)
 *
 * @param pubKeyX/pubKeyY the holder's on-chain passkey coordinates (the trust
 *   anchor). The `jwk` embedded in the KB-JWT header is self-asserted and is
 *   intentionally not used, matching the backend.
 */
export function verifyWebAuthn(
  jwtRaw: string,
  pubKeyX: Uint8Array,
  pubKeyY: Uint8Array,
): boolean {
  const lastDot = jwtRaw.lastIndexOf(".");
  const signingInput = jwtRaw.slice(0, lastDot);
  const segB64 = jwtRaw.slice(lastDot + 1);

  // Decode the assertion segment (base64url JSON).
  let assertion: WebAuthnAssertion;
  try {
    const parsed = JSON.parse(
      new TextDecoder().decode(base64urlDecode(segB64)),
    ) as Partial<WebAuthnAssertion>;
    if (
      typeof parsed.r !== "string" ||
      typeof parsed.s !== "string" ||
      typeof parsed.authenticator_data !== "string" ||
      typeof parsed.client_data_json !== "string" ||
      !Number.isInteger(parsed.challenge_index) ||
      (parsed.challenge_index as number) < 0 ||
      !Number.isInteger(parsed.type_index) ||
      (parsed.type_index as number) < 0
    ) {
      return false;
    }
    assertion = parsed as WebAuthnAssertion;
  } catch {
    return false;
  }

  // Decode r, s (each exactly 32 bytes) and authenticatorData.
  let r: Uint8Array;
  let s: Uint8Array;
  let authData: Uint8Array;
  try {
    r = hexToBytes(assertion.r);
    s = hexToBytes(assertion.s);
    authData = hexToBytes(assertion.authenticator_data);
  } catch {
    return false;
  }
  if (r.length !== 32 || s.length !== 32) return false;

  // authenticatorData = rpIdHash(32) || flags(1) || signCount(4) [|| extensions]
  if (authData.length < 37) return false;

  const cdjBytes = new TextEncoder().encode(assertion.client_data_json);

  // The assertion type must be "webauthn.get" at the declared offset.
  if (!bytesHasAsciiAt(cdjBytes, assertion.type_index, '"type":"webauthn.get"')) {
    return false;
  }

  // The challenge must bind to THIS KB-JWT: base64url(SHA256(signingInput)).
  const expectedChallenge = base64urlEncode(
    sha256(new TextEncoder().encode(signingInput)),
  );
  if (!bytesHasAsciiAt(cdjBytes, assertion.challenge_index, `"challenge":"${expectedChallenge}"`)) {
    return false;
  }

  // Flag checks on the authenticatorData flags byte (index 32).
  const flags = authData[32];
  if ((flags & FLAG_UP) === 0) return false; // user must be present
  if ((flags & FLAG_UV) === 0) return false; // user must be verified
  // Backup-state consistency: cannot be "backed up" without being "backup eligible".
  if ((flags & FLAG_BS) !== 0 && (flags & FLAG_BE) === 0) return false;

  // Reconstruct the WebAuthn signed message and verify the ECDSA-P256 signature.
  const messageHash = sha256(concatBytes(authData, sha256(cdjBytes)));
  const sig = concatBytes(r, s);
  const pubKey = concatBytes(new Uint8Array([0x04]), pubKeyX, pubKeyY);

  try {
    return p256.verify(sig, messageHash, pubKey, { lowS: false, format: "compact" });
  } catch (e) {
    console.warn("[verification-sdk] WebAuthn verify error:", e);
    return false;
  }
}

/**
 * True if the ASCII string `expected` appears in `bytes` starting exactly at
 * byte offset `at`. Mirrors the backend's `binary_part` offset comparison.
 */
function bytesHasAsciiAt(bytes: Uint8Array, at: number, expected: string): boolean {
  if (at < 0 || at + expected.length > bytes.length) return false;
  for (let i = 0; i < expected.length; i++) {
    if (bytes[at + i] !== expected.charCodeAt(i)) return false;
  }
  return true;
}
