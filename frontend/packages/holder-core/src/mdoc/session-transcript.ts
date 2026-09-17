/**
 * The `SessionTranscript` that binds an mdoc presentation to one verifier and
 * one request.
 *
 * ## This is a wire contract, not an implementation detail
 *
 * The wallet and the verifier build this independently from the same inputs and
 * never exchange it. If the two disagree by a single byte, the device signature
 * verifies against nothing and the failure looks like a crypto bug rather than a
 * disagreement about a string. `test/session-transcript.test.ts` pins a hex
 * vector, and the backend's `Sovra.Mdoc.SessionTranscript` pins the same one —
 * a diff to either is a deliberate protocol change.
 *
 * ## Profile
 *
 * OpenID4VP 1.0, the `direct_post` variant:
 *
 *     SessionTranscript      = [null, null, OpenID4VPHandover]
 *     OpenID4VPHandover      = ["OpenID4VPHandover", SHA-256(cbor(HandoverInfo))]
 *     OpenID4VPHandoverInfo  = [client_id, nonce, jwk_thumbprint, response_uri]
 *
 * `client_id`, `nonce` and `response_uri` are text strings; `jwk_thumbprint` is
 * a byte string or null, never text.
 *
 * ISO/IEC TS 18013-7 Annex B defines a different shape whose hashes each cover an
 * `mdocGeneratedNonce`. That nonce exists to bind the wallet's ephemeral
 * *encryption* key, and it travels in the JWE `apu` header — which an
 * unencrypted `direct_post` response does not have, so carrying it would mean
 * inventing a private extension. The verifier's `nonce` remains the freshness
 * anchor, exactly as it is for the SD-JWT key-binding JWT today.
 *
 * `jwk_thumbprint` is therefore null for us. It identifies the response
 * encryption key, and there is none. If we ever adopt `direct_post.jwt` it
 * becomes the RFC 7638 SHA-256 thumbprint of the verifier's encryption key,
 * which the spec requires "encoded as a Byte String" — hence `Uint8Array` and
 * not a base64url string, which would encode as CBOR text and hash to
 * something no conformant verifier rebuilds.
 */

import { encode, type CborValue } from "../cbor/index.js";
import { sha256 } from "../utils/index.js";

/** Bump only alongside a reviewed change to the structures below. */
export const SESSION_TRANSCRIPT_PROFILE = "openid4vp-1.0";

export interface HandoverInput {
  /** The verifier's `client_id` from the authorization request. */
  clientId: string;
  /** The verifier's one-time `nonce`. */
  nonce: string;
  /** The `response_uri` the presentation is posted to. */
  responseUri: string;
  /**
   * Raw RFC 7638 SHA-256 thumbprint of the response-encryption key — the digest
   * bytes, not a base64url encoding of them.
   *
   * Null for `direct_post`, which is unencrypted. Present only if we ever adopt
   * `direct_post.jwt`.
   */
  jwkThumbprint?: Uint8Array | null;
}

export function openId4VpHandoverInfo(input: HandoverInput): CborValue {
  return [input.clientId, input.nonce, input.jwkThumbprint ?? null, input.responseUri];
}

/** The `SessionTranscript` value, ready to nest inside `DeviceAuthentication`. */
export function sessionTranscript(input: HandoverInput): CborValue {
  const infoHash = sha256(encode(openId4VpHandoverInfo(input)));
  return [null, null, ["OpenID4VPHandover", infoHash]];
}
