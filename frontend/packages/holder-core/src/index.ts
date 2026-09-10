// Platform interfaces
export type {
  SecureStorage,
  PasskeyProvider,
  PasskeyResult,
  PasskeySignature,
  CameraScanner,
} from "./platform/index";

// API client
export { ApiClient } from "./api/index";
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
} from "./api/index";

// State stores
export { createCredentialStore } from "./state/index";
export type {
  CredentialStore,
  StoredCredential,
  CredentialDisplayMetadata,
} from "./state/index";
export { createApprovalStore } from "./state/approval-store";
export type { ApprovalStore } from "./state/approval-store";

// Credential manager
export { CredentialManager } from "./credentials/index";
export type { ParsedCredential, IssuerInfo } from "./credentials/index";

// Protocol flows
export {
  IssuanceProtocol,
  PresentationProtocol,
  credentialMetadataFor,
  pickCredentialDisplay,
  pickClaimLabels,
  toStoredDisplay,
} from "./protocols/index";
export type {
  CredentialOffer,
  DCQLQuery,
  VPRequest,
  ApprovalData,
  HolderSigner,
} from "./protocols/index";

// DID resolution
export {
  resolveAssertionKey,
  parseDidUrl,
  didSovraAddress,
  DidResolutionError,
} from "./did/index";
export type { ResolvedKey, EthCall } from "./did/index";

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
} from "./utils/index";
