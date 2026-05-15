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
  OnboardResponse,
  SignResponse,
  AuthResponse,
  RecoverySignatureResponse,
  TokenResponse,
  IssuerMetadata,
  AuthServerMetadata,
} from "./api/index";

// State stores
export {
  createIdentityStore,
  createCredentialStore,
} from "./state/index";
export type {
  IdentityStore,
  IdentityState,
  PendingRecovery,
  CredentialStore,
  StoredCredential,
} from "./state/index";
export { createApprovalStore } from "./state/approval-store";
export type { ApprovalStore } from "./state/approval-store";

// Guardian client
export { GuardianClient } from "./guardian/index";

// Identity manager
export { IdentityManager } from "./identity/index";
export type { OnboardingResult } from "./identity/index";

// Credential manager
export { CredentialManager } from "./credentials/index";
export type { ParsedCredential, IssuerInfo } from "./credentials/index";

// Protocol flows
export { IssuanceProtocol, PresentationProtocol } from "./protocols/index";
export type {
  CredentialOffer,
  DCQLQuery,
  VPRequest,
  ApprovalData,
} from "./protocols/index";

// Utilities
export {
  keccak256,
  sha256,
  hexToBytes,
  bytesToHex,
  base64urlEncode,
  base64urlDecode,
  p256Sign,
  p256GetPublicKey,
  p256PublicKeyToXY,
  buildDomainSeparator,
  buildEIP712MessageHash,
  buildInitHash,
  buildInitializeCalldata,
} from "./utils/index";
