import { p256 } from "@noble/curves/p256";
import {
  sha256,
  base64urlDecode,
  base64urlEncode,
  concatBytes,
  hexToBytes,
  p256Verify,
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

  return p256Verify(
    sha256(new TextEncoder().encode(signingInput)),
    base64urlDecode(sigB64),
    pubKeyX,
    pubKeyY,
  );
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
 * Checked in order: auth-data length, `type` prefix, `challenge` prefix,
 * UP/UV/backup-state flags, then ECDSA-P256 over the reconstructed message.
 *
 * Low-S is deliberately NOT enforced, matching the on-chain OpenZeppelin
 * WebAuthn verifier: WebAuthn authenticators may emit high-S signatures.
 *
 * @param pubKeyX/pubKeyY the holder's on-chain passkey coordinates (the trust
 *   anchor). The `jwk` embedded in the KB-JWT header is self-asserted and is
 *   intentionally not used.
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

  // The KB-JWT's challenge binds to its signing input.
  return verifyWebAuthnAssertion(
    { ...assertion, r, s, authenticatorData: authData },
    new TextEncoder().encode(signingInput),
    pubKeyX,
    pubKeyY,
  );
}

/** A WebAuthn assertion with its hex fields already decoded. */
export interface DecodedWebAuthnAssertion {
  r: Uint8Array;
  s: Uint8Array;
  authenticatorData: Uint8Array;
  client_data_json: string;
  challenge_index: number;
  type_index: number;
}

/**
 * Verify a WebAuthn assertion against the bytes it should be bound to.
 *
 * Shared by the SD-JWT key-binding JWT and by mdoc device authentication, which
 * differ only in *what* the challenge covers: a JWT signing input in one case,
 * a COSE `Sig_structure` in the other. Keeping one implementation matters — if
 * these two drifted, one of them would become exploitable and nothing would say
 * which.
 *
 * The authenticator does not sign `challengeInput`. It signs
 * `authenticatorData || SHA-256(clientDataJSON)`, and the binding comes from
 * requiring `base64url(SHA-256(challengeInput))` to appear at the declared
 * offset inside that signed `clientDataJSON`.
 */
export function verifyWebAuthnAssertion(
  assertion: DecodedWebAuthnAssertion,
  challengeInput: Uint8Array,
  pubKeyX: Uint8Array,
  pubKeyY: Uint8Array,
): boolean {
  const { r, s, authenticatorData: authData } = assertion;

  if (r.length !== 32 || s.length !== 32) return false;
  // authenticatorData = rpIdHash(32) || flags(1) || signCount(4) [|| extensions]
  if (authData.length < 37) return false;

  const cdjBytes = new TextEncoder().encode(assertion.client_data_json);

  // The assertion type must be "webauthn.get" at the declared offset.
  if (!bytesHasAsciiAt(cdjBytes, assertion.type_index, '"type":"webauthn.get"')) {
    return false;
  }

  const expectedChallenge = base64urlEncode(sha256(challengeInput));
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
  return verifyP256Raw(concatBytes(r, s), messageHash, pubKeyX, pubKeyY, false);
}

/**
 * Raw ECDSA-P256 verification over an already-computed message hash.
 *
 * `lowS` differs by caller and is not a detail to unify away: JOSE requires the
 * canonical low-S form, while a WebAuthn authenticator may emit either.
 */
export function verifyP256Raw(
  signature: Uint8Array,
  messageHash: Uint8Array,
  pubKeyX: Uint8Array,
  pubKeyY: Uint8Array,
  lowS: boolean,
): boolean {
  return p256Verify(messageHash, signature, pubKeyX, pubKeyY, lowS);
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
