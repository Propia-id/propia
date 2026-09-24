// Platform interfaces
export type {
  SecureStorage,
  AssetStorage,
  PasskeyProvider,
  PasskeyResult,
  PasskeySignature,
  CameraScanner,
} from "./platform/index.js";

// API client
export { ApiClient } from "./api/index.js";
export type {
  ApiClientConfig,
  TokenResponse,
  IssuerMetadata,
  AuthServerMetadata,
  CredentialDisplay,
  CredentialMetadata,
  ClaimDescription,
  ClaimDisplay,
  DisplayImage,
} from "./api/index.js";

// State stores
export {
  attachmentAssetKey,
  attachmentDisclosureAssetKey,
  createCredentialStore,
  isMdoc,
  isSdJwt,
  logoAssetKey,
} from "./state/index.js";
// The member types and guards are exported alongside the union so downstream
// consumers can narrow without reimplementing the discriminant.
export type {
  CredentialStore,
  CredentialDisplayMetadata,
  CredentialFormat,
  MdocElementMeta,
  StoredCredential,
  StoredMdocCredential,
  StoredSdJwtCredential,
  StoredLogo,
  PendingLogo,
  StoredAttachment,
} from "./state/index.js";
export { createApprovalStore } from "./state/approval-store.js";
export type { ApprovalStore } from "./state/approval-store.js";

// Credential manager
export { CredentialManager } from "./credentials/index.js";
export { isEnvelopeClaim } from "./credentials/envelope.js";
// A credential's attached document is kept out of `claims` for the same reason
// an mdoc portrait is — see `isAttachmentDescriptor`, and `AssetStorage`.
export {
  ATTACHMENT_MEDIA_TYPES,
  isAttachmentDescriptor,
  MAX_ATTACHMENT_BASE64_LENGTH,
  parseAttachmentValue,
} from "./credentials/attachment.js";
export type { AttachmentDescriptor, AttachmentUri } from "./credentials/attachment.js";

// COSE / mdoc surface, for apps that need the algorithm identifiers.
export { COSE_ALG, COSE_HEADER, SOVRA_WEBAUTHN_LABEL } from "./cose/index.js";
// A wallet rendering an mDL needs the portrait bytes, which `claims` carries
// only a descriptor for — see `readElementBytes`.
export {
  drivingPrivilegeCategories,
  isBytesDescriptor,
  ISO_MDL_NAMESPACE,
  PORTRAIT_ELEMENT,
  portraitDataUri,
  readElementBytes,
} from "./mdoc/index.js";
export type { BytesDescriptor } from "./mdoc/index.js";
export type { ParsedCredential, IssuerInfo } from "./credentials/index.js";

// Protocol flows
export {
  IssuanceProtocol,
  PresentationProtocol,
  credentialMetadataFor,
  pickCredentialDisplay,
  pickClaimLabels,
  pickLogo,
  toStoredDisplay,
} from "./protocols/index.js";
export { assertionToJwtSegment } from "./protocols/index.js";
export type {
  CredentialOffer,
  ClaimRef,
  DCQLQuery,
  VPRequest,
  ApprovalData,
  HolderAssertion,
  HolderSigner,
  RawEs256Signature,
  WebAuthnAssertion,
} from "./protocols/index.js";

// DID resolution
export {
  resolveAssertionKey,
  parseDidUrl,
  didSovraAddress,
  DidResolutionError,
} from "./did/index.js";
export type { ResolvedKey, EthCall } from "./did/index.js";

// Utilities
export {
  keccak256,
  sha256,
  hexToBytes,
  bytesToHex,
  base64urlEncode,
  base64urlDecode,
  p256Sign,
  p256Verify,
  p256GetPublicKey,
  p256PublicKeyToXY,
  buildDomainSeparator,
  buildEIP712MessageHash,
  buildInitHash,
  buildInitializeCalldata,
} from "./utils/index.js";
