export { verify } from "./verify";
export { verifyDocument, decodeDocument } from "./verify-document";
export { checkRevocation } from "./revocation";
export { VerificationError } from "./errors";
export { VerificationCache } from "./cache";
export { ErrorCode } from "./types";
export type { VerifyOptions, VerificationResult } from "./types";
export type {
  VerifyDocumentOptions,
  DocumentVerificationResult,
  DocumentCheck,
  CheckSource,
} from "./verify-document";
