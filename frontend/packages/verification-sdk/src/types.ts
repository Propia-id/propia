// ─── Error Codes ─────────────────────────────────────

export const ErrorCode = {
  PARSE_ERROR: "PARSE_ERROR",
  NOT_A_DOCUMENT: "NOT_A_DOCUMENT",
  NOT_ANCHORED: "NOT_ANCHORED",
  ISSUER_SIG_INVALID: "ISSUER_SIG_INVALID",
  ISSUER_NOT_FOUND: "ISSUER_NOT_FOUND",
  ISSUER_NOT_TRUSTED: "ISSUER_NOT_TRUSTED",
  ISSUER_DEACTIVATED: "ISSUER_DEACTIVATED",
  DISCLOSURE_MISMATCH: "DISCLOSURE_MISMATCH",
  CREDENTIAL_EXPIRED: "CREDENTIAL_EXPIRED",
  CREDENTIAL_REVOKED: "CREDENTIAL_REVOKED",
  HOLDER_NOT_FOUND: "HOLDER_NOT_FOUND",
  HOLDER_DEACTIVATED: "HOLDER_DEACTIVATED",
  KB_JWT_MISSING: "KB_JWT_MISSING",
  KB_PASSKEY_SIG_INVALID: "KB_PASSKEY_SIG_INVALID",
  KB_NONCE_MISMATCH: "KB_NONCE_MISMATCH",
  KB_AUDIENCE_MISMATCH: "KB_AUDIENCE_MISMATCH",
  KB_SD_HASH_MISMATCH: "KB_SD_HASH_MISMATCH",
  KB_EXPIRED: "KB_EXPIRED",
  IAT_INVALID: "IAT_INVALID",
  SUBJECT_KEY_MISMATCH: "SUBJECT_KEY_MISMATCH",
  INVALID_ADDRESS: "INVALID_ADDRESS",
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

// ─── Public Types ────────────────────────────────────

export interface VerifyOptions {
  expectedNonce: string;
  expectedAudience: string;
  /** Endpoint for the DID / issuer / revocation registries. */
  l2RpcUrl: string;
  didRegistryAddress: string;
  issuerRegistryAddress: string;
  revocationRegistryAddress?: string;
  /**
   * Endpoint for reading the holder's on-chain AlignedAccount keys. Defaults to
   * `l2RpcUrl`. Set it only when holder smart accounts are delegated on a
   * different chain than the registries: the holder's key material is read from
   * the account contract itself, so it must be resolved on the chain where that
   * account has code.
   */
  holderRpcUrl?: string;
  maxClockSkew?: number;
  checkRevocation?: boolean;
  offlineMode?: boolean;
}

export interface VerificationResult {
  valid: boolean;
  error?: string;
  errorCode?: ErrorCode;
  claims?: Record<string, unknown>;
  issuer?: string;
  holder?: string;
  credentialType?: string;
  issuedAt?: number;
  expiresAt?: number;
  offlineMode?: boolean;
  trustNotVerified?: boolean;
  revocationChecked?: boolean;
}

// ─── Internal Types ──────────────────────────────────

export interface ParsedDisclosure {
  encoded: string;
  salt: string;
  key: string;
  value: unknown;
}

export interface ParsedPresentation {
  issuerJwtRaw: string;
  issuerHeader: Record<string, unknown>;
  issuerPayload: Record<string, unknown>;
  disclosures: ParsedDisclosure[];
  kbJwtRaw: string;
  kbHeader: Record<string, unknown>;
  kbPayload: Record<string, unknown>;
}

export interface IssuerKeyData {
  pubKeyX: Uint8Array;
  pubKeyY: Uint8Array;
  versionId: number;
}

export interface HolderPasskey {
  x: Uint8Array;
  y: Uint8Array;
}

export interface HolderKeyData {
  /** Active WebAuthnP256 passkeys read from the holder's on-chain AlignedAccount. */
  passkeys: HolderPasskey[];
}
