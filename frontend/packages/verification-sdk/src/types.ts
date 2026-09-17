// Type-only, and `x509.ts` imports nothing from here, so there is no cycle.
import type { DistinguishedName } from "./x509.js";

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

  // mdoc-specific. Additive, so existing consumers are unaffected.
  MDOC_PARSE_ERROR: "MDOC_PARSE_ERROR",
  MSO_DIGEST_MISMATCH: "MSO_DIGEST_MISMATCH",
  DEVICE_AUTH_INVALID: "DEVICE_AUTH_INVALID",
  DOCTYPE_MISMATCH: "DOCTYPE_MISMATCH",
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
   * Endpoint for reading the holder's on-chain account keys. Defaults to
   * `l2RpcUrl`. Set it only when holder smart accounts are delegated on a
   * different chain than the registries: the holder's key material is read from
   * the account contract itself, so it must be resolved on the chain where that
   * account has code.
   */
  holderRpcUrl?: string;
  maxClockSkew?: number;
  checkRevocation?: boolean;
  /**
   * Skip every on-chain read. Only the structure of the presentation is
   * checked: no issuer signature, no issuer trust, no holder proof.
   *
   * A result can come back `valid: true` for a credential nobody signed, so
   * never treat it as proof of anything. Intended for offline demos and tests.
   * Check `trustNotVerified` to tell such a result apart.
   */
  offlineMode?: boolean;
}

export interface VerificationResult {
  valid: boolean;
  error?: string;
  errorCode?: ErrorCode;
  claims?: Record<string, unknown>;
  /**
   * The issuer, as a `did:sovra:` DID, when something actually attests it.
   *
   * Present on every SD-JWT result and on an mdoc carrying a generated docType,
   * where the address selected the key the signature was then verified against
   * — so a wrong address cannot produce a valid result.
   *
   * **Absent on the certificate route**, where nothing attests an address: the
   * docType names nobody, and an ISO Document Signer Certificate names a key
   * and a subject, never a Sovra workspace. What that route establishes is in
   * `issuingAuthority` and `documentSigner`; the address the issuer *claims* is
   * in `assertedIssuerAddress`.
   */
  issuer?: string;
  holder?: string;
  /**
   * The credential type the issuer registered on-chain — an SD-JWT's `vct`, or
   * an mdoc's `credential_type` from the Sovra meta namespace.
   *
   * Deliberately not an mdoc's docType, which is derived from the schema and is
   * not what the Issuer Trust Registry is keyed by. That is `docType`.
   */
  credentialType?: string;
  /** An mdoc's docType. Absent for SD-JWT, which has no equivalent. */
  docType?: string;
  /**
   * The common name of the IACA root that vouched for the issuer's document
   * signer, when the credential was trusted through a certificate chain.
   *
   * Present only on that route. A verifier holding a trust list needs to be
   * able to say *which* authority it accepted, not only that one of them was
   * acceptable — "a licence issued under the Spanish root" is a different
   * statement from "a licence".
   */
  issuingAuthority?: string;
  /**
   * The subject of the Document Signer Certificate that signed this credential.
   *
   * Present only on the certificate route, and together with `issuingAuthority`
   * it is the whole of what that route attests about the issuer: this named
   * signer, vouched for by that named authority.
   */
  documentSigner?: DistinguishedName;
  /**
   * The workspace address the issuer signed into the Sovra meta namespace, on
   * the certificate route where nothing attests it.
   *
   * Issuer-signed, so it cannot be rewritten in transit — and worth exactly
   * that much. Any workspace holding a document signer under an authority this
   * verifier admitted can write any address here, so it names who the issuer
   * *says* they are, never who they are. `issuingAuthority` and
   * `documentSigner` are the attested facts.
   *
   * It is still what revocation is keyed by, because the bitmaps are keyed by
   * address and the credential carries no other. That check is therefore only
   * as good as the issuer: a revocation lookup against an address the issuer
   * chose is worth nothing against an issuer who chose it in bad faith, and is
   * correct for every issuer who did not.
   */
  assertedIssuerAddress?: string;
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
  /** Active WebAuthnP256 passkeys read from the holder's on-chain account. */
  passkeys: HolderPasskey[];
}
