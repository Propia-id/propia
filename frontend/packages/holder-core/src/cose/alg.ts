/**
 * COSE algorithm identifiers.
 *
 * This file is one half of the device-auth retrofit seam: the wallet declares
 * an algorithm here, the verifier dispatches on the same value, and swapping
 * the holder's signing key from a WebAuthn passkey to a raw Secure Enclave key
 * later means adding an `ES256` path on both sides and changing nothing else.
 * The backend must mirror these literals exactly.
 */

export const COSE_ALG = {
  /** RFC 9053 §2.1 — ECDSA w/ SHA-256. The standards-conformant device-auth path. */
  ES256: -7,

  /**
   * A WebAuthn-wrapped P-256 signature. Private Use, so no IANA collision.
   *
   * Our holder key is a WebAuthn passkey, which does not sign the payload: it
   * signs `authenticatorData || SHA256(clientDataJSON)`, with the payload
   * appearing only as the `challenge` inside `clientDataJSON`. That is a
   * different signature computation from ES256, so it needs a different
   * identifier — labelling it `-7` would be a lie that a conformant reader
   * fails on with no diagnostic.
   *
   * IANA assigns Private Use to integers *less than* -65536 — -65536 itself
   * falls in the Specification Required band — so -65537 is the first value we
   * can take without registering anything.
   */
  SOVRA_WEBAUTHN_P256: -65537,
} as const;

export type CoseAlg = (typeof COSE_ALG)[keyof typeof COSE_ALG];

/** COSE header parameter labels (RFC 9052 §3.1). */
export const COSE_HEADER = {
  ALG: 1,
  KID: 4,
} as const;

/**
 * The unprotected-header label carrying the WebAuthn envelope.
 *
 * A text label, not an integer: the integer space is IANA-registered (33 is
 * `x5chain`, which we would be squatting on), and the private-use boundary for
 * header parameters is murkier than for algorithms.
 *
 * The envelope sits in the *unprotected* header, which the signature does not
 * cover — and that is correct. Integrity comes from the challenge binding: the
 * authenticator signs over `clientDataJSON`, which embeds
 * `challenge = base64url(SHA256(ToBeSigned))`. A verifier recomputes
 * `Sig_structure`, hashes it, and checks that value appears at
 * `challenge_index`. Tampering with the envelope therefore breaks verification
 * even though the bytes are unsigned.
 */
export const SOVRA_WEBAUTHN_LABEL = "sovra_webauthn";
