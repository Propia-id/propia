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
export { createCredentialStore, logoAssetKey } from "./state/index.js";
export type {
  CredentialStore,
  StoredCredential,
  CredentialDisplayMetadata,
  StoredLogo,
  PendingLogo,
} from "./state/index.js";
export { createApprovalStore } from "./state/approval-store.js";
export type { ApprovalStore } from "./state/approval-store.js";

// Credential manager
export { CredentialManager } from "./credentials/index.js";
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
export type {
  CredentialOffer,
  DCQLQuery,
  VPRequest,
  ApprovalData,
  HolderSigner,
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
