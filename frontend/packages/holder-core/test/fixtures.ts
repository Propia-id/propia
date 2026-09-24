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
  AssetStorage,
  MdocElementMeta,
  SecureStorage,
  StoredMdocCredential,
  StoredSdJwtCredential,
} from "../src/index";
import { sha256 } from "../src/index";
import { bytesToHex } from "../src/utils/index";

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

/**
 * An in-memory `AssetStorage` with the platform's semantics, and the stored
 * bytes exposed for assertions.
 *
 * `put` decodes standard base64 and refuses anything else — base64url, missing
 * padding — as iOS's decoder does; `text` reads the stored bytes back as UTF-8,
 * as `ExpoAssetStorage` does. A fake that kept the string it was given would
 * pass a caller that writes base64url and reads it back, which is exactly the
 * mistake that fails on a device.
 */
export function memoryAssetStorage(): { assets: AssetStorage; map: Map<string, Uint8Array> } {
  const map = new Map<string, Uint8Array>();

  const assets: AssetStorage = {
    async put(key, base64) {
      if (base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
        throw new Error(`Not standard base64: ${key}`);
      }
      map.set(key, new Uint8Array(Buffer.from(base64, "base64")));
    },
    uriFor(key) {
      return `file:///assets/${key}`;
    },
    async text(key) {
      const bytes = map.get(key);
      return bytes ? new TextDecoder().decode(bytes) : null;
    },
    async delete(key) {
      map.delete(key);
    },
  };

  return { assets, map };
}

/**
 * A real SD-JWT carrying one attachment, with a correct `_sd` digest.
 *
 * Built rather than stubbed because the digest check in `attachmentUri` is one
 * of the things worth testing: a fixture whose digests do not match what the
 * payload claims would let that check pass by never being exercised.
 */
export function sdJwtWithAttachment(
  options: { claim?: string; pdf?: string } = {},
): { sdJwt: string; claim: string; pdf: string; disclosure: string } {
  const claim = options.claim ?? "licence_scan";
  const pdf =
    options.pdf ?? `data:application/pdf;base64,${b64(utf8("%PDF-1.7 a scanned licence"))}`;

  const name = discloseOf("sALT-1", "family_name", "Rossi");
  const scan = discloseOf("sALT-2", claim, pdf);

  const payload = {
    iss: "https://issuer.example/did:sovra:0xb2",
    vct: "DrivingLicenceCredential",
    iat: 1_700_000_000,
    exp: 1_700_000_000 + YEAR,
    _sd: [digestOf(name), digestOf(scan)],
    _sd_alg: "sha-256",
  };

  const jwt = `${b64u(utf8(JSON.stringify({ alg: "ES256", typ: "vc+sd-jwt" })))}.${b64u(
    utf8(JSON.stringify(payload)),
  )}.signature`;

  return { sdJwt: `${jwt}~${name}~${scan}~`, claim, pdf, disclosure: scan };
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function discloseOf(salt: string, key: string, value: unknown): string {
  return b64u(utf8(JSON.stringify([salt, key, value])));
}

function digestOf(disclosure: string): string {
  return b64u(sha256(utf8(disclosure)));
}

export interface ResolveDocument {
  methods?: {
    id: Uint8Array;
    keyType: number;
    pubKeyX: Uint8Array;
    pubKeyY: Uint8Array;
    relationships: number;
  }[];
  services?: { id: Uint8Array; serviceType: Uint8Array; endpoint: string }[];
  created?: number;
  updated?: number;
  versionId?: number;
  deactivated?: boolean;
}

/**
 * ABI-encode a SovraDIDRegistry `resolve(address)` return value — the inverse
 * of `decodeResolveResult`, for tests that stand in for the registry.
 */
export function encodeResolveResult(doc: ResolveDocument = {}): string {
  const { methods = [], services = [], deactivated = false } = doc;
  const word = (value: number | Uint8Array): string =>
    (typeof value === "number" ? value.toString(16) : bytesToHex(value, false)).padStart(64, "0");

  const methodsData =
    word(methods.length) +
    methods
      .map((m) => word(m.id) + word(m.keyType) + word(m.pubKeyX) + word(m.pubKeyY) + word(m.relationships))
      .join("");

  // Each tuple: id, serviceType, offset to the string (three words in), then
  // the string's length and its bytes right-padded to a word boundary.
  const tuples = services.map((s) => {
    const bytes = bytesToHex(new TextEncoder().encode(s.endpoint), false);
    const padded = bytes.padEnd(Math.ceil(bytes.length / 64) * 64, "0");
    return word(s.id) + word(s.serviceType) + word(3 * 32) + word(bytes.length / 2) + padded;
  });
  let offset = services.length * 32;
  const offsets = tuples.map((t) => {
    const at = offset;
    offset += t.length / 2;
    return word(at);
  });
  const servicesData = word(services.length) + offsets.join("") + tuples.join("");

  const methodsOffset = 6 * 32;
  return (
    "0x" +
    word(methodsOffset) +
    word(methodsOffset + methodsData.length / 2) +
    word(doc.created ?? 1) +
    word(doc.updated ?? 1) +
    word(doc.versionId ?? 1) +
    word(deactivated ? 1 : 0) +
    methodsData +
    servicesData
  );
}
