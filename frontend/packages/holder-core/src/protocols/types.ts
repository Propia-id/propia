/**
 * The holder signing seam, in its own module so the mdoc code can depend on it
 * without a cycle back through the protocol flows.
 */

/**
 * A WebAuthn authenticator assertion.
 *
 * Field shapes match what the wallet's passkey adapter returns and what the
 * backend's `Sovra.Crypto.WebAuthn.parse_assertion/1` expects: `r`, `s` and
 * `authenticatorData` as `0x`-prefixed hex, and `clientDataJson` as raw text
 * rather than bytes.
 *
 * That asymmetry is load-bearing. The verifier hashes `clientDataJSON` exactly
 * as received; converting it to bytes and back would risk changing it, and
 * would silently break every existing SD-JWT presentation as well as mdoc.
 */
export interface WebAuthnAssertion {
  kind: "webauthn";
  r: string;
  s: string;
  authenticatorData: string;
  clientDataJson: string;
  challengeIndex: number;
  typeIndex: number;
}

/** A plain ECDSA signature, for a device key that signs the payload directly. */
export interface RawEs256Signature {
  kind: "es256";
  r: string;
  s: string;
}

export type HolderAssertion = WebAuthnAssertion | RawEs256Signature;

/**
 * Signs the holder's proofs: the OID4VCI proof of possession, the OID4VP
 * key-binding JWT, and mdoc device authentication.
 *
 * The concrete implementation lives in the app — an Aligned passkey signer —
 * so holder-core stays agnostic of the wallet SDK.
 */
export interface HolderSigner {
  /** The JWT `alg` header value this signer produces (e.g. "WebAuthn"). */
  readonly alg: string;
  /** The COSE algorithm identifier for the same signature construction. */
  readonly coseAlg: number;

  /**
   * Sign `hash` — the 32-byte SHA-256 of whatever is being signed — with the
   * holder's key `credentialId`, returning the raw assertion.
   *
   * Returning the assertion rather than a finished JWT segment is what lets one
   * signature construction serve both JWT and COSE encodings.
   */
  sign(hash: Uint8Array, credentialId: string): Promise<HolderAssertion>;
}

/**
 * Serialise an assertion into a JWT's third segment.
 *
 * The key order and hex formatting here are the wire format the backend already
 * parses, so this must stay byte-identical to what the wallet produced before
 * the signer interface was widened. `test/holder-signer.test.ts` is the guard.
 */
export function assertionToJwtSegment(
  assertion: HolderAssertion,
  base64urlEncode: (data: Uint8Array) => string,
): string {
  if (assertion.kind === "es256") {
    throw new Error("raw ES256 assertions are not carried in a JWT segment");
  }

  const segment = {
    r: assertion.r,
    s: assertion.s,
    challenge_index: assertion.challengeIndex,
    type_index: assertion.typeIndex,
    authenticator_data: assertion.authenticatorData,
    client_data_json: assertion.clientDataJson,
  };

  return base64urlEncode(new TextEncoder().encode(JSON.stringify(segment)));
}
