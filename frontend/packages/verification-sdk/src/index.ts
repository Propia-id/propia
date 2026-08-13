export { verify } from "./verify.js";
export { verifyDocument, decodeDocument } from "./verify-document.js";
export { checkRevocation } from "./revocation.js";
export { VerificationError } from "./errors.js";
export { VerificationCache } from "./cache.js";
export { ErrorCode } from "./types.js";
export type { VerifyOptions, VerificationResult } from "./types.js";
export type {
  VerifyDocumentOptions,
  DocumentVerificationResult,
  DocumentCheck,
  CheckSource,
} from "./verify-document.js";
