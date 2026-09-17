/**
 * Typed factories for credentials and storage.
 *
 * Fully typed with no casts, on purpose. `as StoredCredential` on an object
 * literal is a widening assertion TypeScript permits, so against a union it
 * keeps compiling while silently producing a credential with no `format` — and
 * hides exactly the breakage a discriminated union exists to surface. Building
 * these concretely means an omitted field is a compile error.
 */

import type {
  MdocElementMeta,
  SecureStorage,
  StoredMdocCredential,
  StoredSdJwtCredential,
} from "../src/index";

const YEAR = 365 * 86400;

export function sdJwtCredential(
  overrides: Partial<StoredSdJwtCredential> = {},
): StoredSdJwtCredential {
  return {
    id: "cred-sd-jwt-1",
    format: "vc+sd-jwt",
    sdJwt: "header.payload.sig~",
    issuerDid: "did:sovra:0x00000000000000000000000000000000000000b2",
    credentialType: "NationalIdCredential",
    issuerName: "Test Issuer",
    issuedAt: 1_700_000_000,
    expiresAt: 1_700_000_000 + YEAR,
    claims: {
      given_name: "Maria",
      family_name: "Rossi",
      birth_date: "1990-07-15",
    },
    ...overrides,
  };
}

export function mdocCredential(
  overrides: Partial<StoredMdocCredential> = {},
): StoredMdocCredential {
  const docType = overrides.docType ?? "io.sovra.0xab34cd09f9.membership-card.1";

  const elements: MdocElementMeta[] = [
    { namespace: docType, elementIdentifier: "member_name", claimKey: "member_name", mandatory: false },
    { namespace: docType, elementIdentifier: "tier", claimKey: "tier", mandatory: true },
  ];

  return {
    id: "cred-mdoc-1",
    format: "mso_mdoc",
    issuerSigned: "omppc3N1ZXJBdXRo",
    docType,
    // credentialType carries the docType, so type-based lookups work for both.
    credentialType: docType,
    issuerDid: "did:sovra:0xab34cd09f9",
    issuerName: "Test Issuer",
    issuedAt: 1_700_000_000,
    expiresAt: 1_700_000_000 + YEAR,
    claims: { member_name: "Ada Lovelace", tier: "gold" },
    elements,
    ...overrides,
  };
}

/** An in-memory `SecureStorage`, with the stored keys exposed for assertions. */
export function memoryStorage(initial: Record<string, string> = {}) {
  const map = new Map<string, string>(Object.entries(initial));

  const storage: SecureStorage = {
    async get(key) {
      return map.get(key) ?? null;
    },
    async set(key, value) {
      map.set(key, value);
    },
    async delete(key) {
      map.delete(key);
    },
  };

  return { storage, map };
}
