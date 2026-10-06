export { verify } from "./verify.js";
export { buildPresentationRequestUri } from "./request.js";
export type { PresentationRequestInput } from "./request.js";
export { verifyMdoc } from "./mdoc/verify-mdoc.js";
export type { VerifyMdocOptions } from "./mdoc/verify-mdoc.js";
export { verifyDocument, decodeDocument } from "./verify-document.js";
export { checkRevocation } from "./revocation.js";
/** Read a holder's active on-chain passkeys — the preflight `verify` runs internally. */
export { resolveHolderKeys } from "./resolve-holder.js";
export { VerificationError } from "./errors.js";
export { VerificationCache } from "./cache.js";
export { ErrorCode } from "./types.js";
// A verifier configures `trustAnchors` from whatever its authority published,
// which is PEM — so `pemToDer` has to be reachable, or every integrator writes
// the same base64 loop. The rest is exported because an mDL reader sometimes
// needs to inspect a chain rather than only accept or reject one.
export {
  parseCertificate,
  pemToDer,
  validateDocumentSignerChain,
  CertificateError,
  MAX_DOCUMENT_SIGNER_DAYS,
  OID_MDL_DOCUMENT_SIGNER,
} from "./x509.js";
export type { Certificate, DistinguishedName } from "./x509.js";
export type { VerifyOptions, VerificationResult } from "./types.js";
export type { HolderKeyData, HolderPasskey } from "./types.js";
export type {
  VerifyDocumentOptions,
  DocumentVerificationResult,
  DocumentCheck,
  CheckSource,
} from "./verify-document.js";
