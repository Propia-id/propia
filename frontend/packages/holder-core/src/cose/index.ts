/**
 * COSE structures for ISO/IEC 18013-5 mDoc.
 *
 * Deliberately free of any WebAuthn or DID knowledge: this layer shapes and
 * verifies structures, and who signed them and how is the caller's business.
 * That separation is what keeps both mDoc retrofit seams — swapping the issuer
 * trust reference for an `x5chain`, and swapping the holder's WebAuthn passkey
 * for a raw Secure Enclave key — local changes.
 */

export { COSE_ALG, COSE_HEADER, SOVRA_WEBAUTHN_LABEL, type CoseAlg } from "./alg.js";
export {
  decodeSign1,
  encodeSign1,
  parseSign1,
  sig1ToBeSigned,
  sign1Alg,
  type CoseSign1,
} from "./sign1.js";
export { coseKeyToXY, xyToCoseKey, type P256Point } from "./key.js";
