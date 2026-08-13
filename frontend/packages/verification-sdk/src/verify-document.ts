import {
  sha256,
  keccak256,
  bytesToHex,
  base64urlDecode,
} from "@sovrahq/holder-core/utils";
import { verifyES256 } from "./signature";
import { resolveIssuerDID, checkIssuerTrust } from "./resolve-issuer";
import { readSignatureRecord } from "./signature-registry";
import { VerificationError } from "./errors";
import { ErrorCode } from "./types";

/**
 * Verification for signed documents: issued directly by an issuer, with no holder
 * and no wallet.
 *
 * Runs entirely on the verifier's side: the only thing that has to come from the
 * issuer's API is the JWS itself. Everything else is read from the chain or
 * computed locally, so the issuer can fail to respond but cannot lie.
 */

export interface VerifyDocumentOptions {
  l2RpcUrl: string;
  didRegistryAddress: string;
  issuerRegistryAddress: string;
  signatureRegistryAddress: string;
  /** Seconds of tolerance on `exp`. Defaults to 60. */
  maxClockSkew?: number;
  /** Unix seconds to evaluate `exp` against. Defaults to now. */
  now?: number;
}

/** Where a check's answer came from, surfaced so a UI can show it. */
export type CheckSource = "document" | "chain" | "computed";

export interface DocumentCheck {
  id: string;
  label: string;
  ok: boolean;
  detail?: string;
  source: CheckSource;
}

export interface DocumentVerificationResult {
  valid: boolean;
  error?: string;
  errorCode?: ErrorCode;
  /** Every check that ran, in order, including the one that failed. */
  checks: DocumentCheck[];
  claims?: Record<string, unknown>;
  issuer?: { iss: string; address: string };
  credentialType?: string;
  /** 0x-prefixed sha-256 of the JWS signing input, the key the record is under. */
  digest?: string;
  /** keccak256(vct), the type id the authorization registry is keyed by. */
  typeId?: string;
  /** Block timestamp of the anchoring transaction. */
  recordedAt?: number;
  issuedAt?: number;
  expiresAt?: number;
}

const DEFAULT_CLOCK_SKEW = 60;

// One message for every parse failure. What is wrong with the bytes is the
// caller's problem, and naming the field only tells whoever crafted it more.
const UNREADABLE = "This is not a readable document";

/**
 * Verify a signed document.
 *
 * @param credential SD-JWT VC serialization: `<jwt>~`. Documents have no
 *                   disclosures and no key binding.
 */
export async function verifyDocument(
  credential: string,
  options: VerifyDocumentOptions,
): Promise<DocumentVerificationResult> {
  const checks: DocumentCheck[] = [];
  const result: DocumentVerificationResult = { valid: false, checks };

  const add = (
    id: string,
    label: string,
    ok: boolean,
    source: CheckSource,
    detail?: string,
  ) => {
    checks.push({ id, label, ok, source, detail });
  };

  try {
    // ── 1. Parse ──────────────────────────────────────
    const doc = parse(credential);
    const { payload, iss, vct, iat, exp } = doc;

    result.claims = payload;
    result.credentialType = vct;
    result.typeId = bytesToHex(keccak256(new TextEncoder().encode(vct)));
    result.issuedAt = iat;
    result.expiresAt = exp;

    add("parse", "Well-formed, readable document", true, "document", `vct=${vct}`);

    // ── 2. The digest, the key the signature is stored under ──
    const digest = computeDigest(doc);
    const digestHex = bytesToHex(digest);
    result.digest = digestHex;

    add("digest", "Digest recomputed from the document", true, "computed", digestHex);

    // ── 3. Who signed it ─────────────────────────────
    const issuerAddress = extractDIDAddress(iss);
    result.issuer = { iss, address: issuerAddress };

    add("issuer", "Issuer identified", true, "document", issuerAddress);

    // ── 4. The public key, from the chain ────────────
    const issuerKeys = await resolveIssuerDID(
      options.l2RpcUrl,
      options.didRegistryAddress,
      issuerAddress,
    );

    add("key", "Issuer public key resolved", true, "chain",
      `versionId=${issuerKeys.versionId}`);

    // From here on, checks record their outcome instead of aborting, so a
    // failure still shows everything else that was or was not true.
    const failures: { message: string; code: ErrorCode }[] = [];

    const fail = (message: string, code: ErrorCode) => failures.push({ message, code });

    // ── 5. The signature ─────────────────────────────
    // `doc.jwt`, not `credential`: verifyES256 splits at the last dot, and a
    // trailing `~` would end up inside the signature segment.
    const signatureValid = verifyES256(doc.jwt, issuerKeys.pubKeyX, issuerKeys.pubKeyY);
    add("signature", "Signature valid", signatureValid, "computed");
    if (!signatureValid) {
      // ECDSA only says yes or no: an altered payload, an altered signature and
      // a different key are indistinguishable here. Name the likely cause.
      fail(
        "The content does not match its signature. It was altered, or it was not signed by this issuer",
        ErrorCode.ISSUER_SIG_INVALID,
      );
    }

    // ── 6. Is the issuer allowed to sign this type ───
    try {
      await checkIssuerTrust(
        options.l2RpcUrl,
        options.issuerRegistryAddress,
        issuerAddress,
        vct,
      );
      add("trust", `Issuer authorized for ${vct}`, true, "chain");
    } catch (e) {
      add("trust", `Issuer authorized for ${vct}`, false, "chain");
      fail(
        e instanceof Error ? e.message : "The issuer is not authorized for this type",
        ErrorCode.ISSUER_NOT_TRUSTED,
      );
    }

    // ── 7. Is the signature anchored, and when ───────
    const record = await readSignatureRecord(
      options.l2RpcUrl,
      options.signatureRegistryAddress,
      issuerAddress,
      digest,
    );

    if (record.recordedAt === 0) {
      add("anchor", "Signature anchored on-chain", false, "chain",
        "no record for this content");
      fail("No signature is anchored on-chain for this content", ErrorCode.NOT_ANCHORED);
    } else {
      result.recordedAt = record.recordedAt;
      add("anchor", "Signature anchored on-chain", true, "chain",
        new Date(record.recordedAt * 1000).toISOString());

      const sameSignature = anchorMatches(record, doc);
      add("anchor-match", "Anchored signature matches this document", sameSignature, "computed");
      if (!sameSignature) {
        fail("The anchored signature belongs to a different document", ErrorCode.ISSUER_SIG_INVALID);
      }
    }

    // ── 8. Still valid ───────────────────────────────
    const now = options.now ?? Math.floor(Date.now() / 1000);
    const skew = options.maxClockSkew ?? DEFAULT_CLOCK_SKEW;

    if (exp !== undefined) {
      const expired = now > exp + skew;
      add("expiry", "Still valid", !expired, "document",
        new Date(exp * 1000).toISOString());
      if (expired) fail("The document has expired", ErrorCode.CREDENTIAL_EXPIRED);
    } else {
      add("expiry", "No expiry", true, "document");
    }

    if (failures.length > 0) {
      result.error = failures[0].message;
      result.errorCode = failures[0].code;
      return result;
    }

    result.valid = true;
    return result;
  } catch (e) {
    if (e instanceof VerificationError) {
      result.error = e.message;
      result.errorCode = e.code;
      return result;
    }
    result.error = e instanceof Error ? e.message : "Unknown verification error";
    return result;
  }
}

// ─── Helpers ─────────────────────────────────────────

/**
 * The claims inside a document, without checking anything. Decoding proves
 * nothing: it says what the bytes claim, not that anyone signed them.
 */
export function decodeDocument(credential: string): Record<string, unknown> {
  return parse(credential).payload;
}

/** A document taken apart, with the registered claims it must carry. */
interface ParsedDocument {
  /** The JWS without the disclosure tail. */
  jwt: string;
  headerB64: string;
  payloadB64: string;
  signatureB64: string;
  payload: Record<string, unknown>;
  iss: string;
  vct: string;
  iat: number;
  exp?: number;
}

function parse(credential: string): ParsedDocument {
  // SD-JWT serialization: `<jwt>~<disclosure>~…`. The tail is empty for a
  // document, but split it off anyway so one with disclosures still parses.
  const [jwt] = credential.split("~");

  const segments = jwt.split(".");
  if (segments.length !== 3) throw new VerificationError(UNREADABLE, ErrorCode.PARSE_ERROR);
  const [headerB64, payloadB64, signatureB64] = segments;

  const header = decodeJson(headerB64);
  const payload = decodeJson(payloadB64);

  // The algorithm is asserted, never taken as instruction: reading `alg` to
  // decide how to verify is how algorithm-confusion attacks work.
  if (header.alg !== "ES256") {
    throw new VerificationError(
      "This document was not signed with an algorithm we verify",
      ErrorCode.PARSE_ERROR,
    );
  }

  // `cnf` is holder key binding, so this is a wallet credential. It belongs to
  // `verify`, which also checks the holder's proof of possession.
  if (payload.cnf !== undefined) {
    throw new VerificationError(
      "This is a holder credential, not a document",
      ErrorCode.NOT_A_DOCUMENT,
    );
  }

  return {
    jwt,
    headerB64,
    payloadB64,
    signatureB64,
    payload,
    iss: requireString(payload, "iss"),
    vct: requireString(payload, "vct"),
    iat: requireNumber(payload, "iat"),
    exp: payload.exp === undefined ? undefined : requireNumber(payload, "exp"),
  };
}

/** What the signature covers, and the key the record is stored under. */
function computeDigest(doc: ParsedDocument): Uint8Array {
  return sha256(new TextEncoder().encode(`${doc.headerB64}.${doc.payloadB64}`));
}

/** The anchored `r ‖ s` must be byte-identical to the signature inside the JWS. */
function anchorMatches(record: { r: Uint8Array; s: Uint8Array }, doc: ParsedDocument): boolean {
  const anchored = new Uint8Array(64);
  anchored.set(record.r, 0);
  anchored.set(record.s, 32);

  return bytesEqual(base64urlDecode(doc.signatureB64), anchored);
}

/** Accepts `did:sovra:0x…` and the URL form, `https://host/did:sovra:0x…`. */
function extractDIDAddress(input: string): string {
  const marker = "did:sovra:";
  const at = input.indexOf(marker);
  if (at === -1) {
    throw new VerificationError(`Invalid DID format: ${input}`, ErrorCode.PARSE_ERROR);
  }
  const address = input.slice(at + marker.length);
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new VerificationError(`Invalid address in DID: ${address}`, ErrorCode.INVALID_ADDRESS);
  }
  return address;
}


function decodeJson(segment: string): Record<string, unknown> {
  try {
    const bytes = base64urlDecode(segment);
    return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
  } catch {
    throw new VerificationError(UNREADABLE, ErrorCode.PARSE_ERROR);
  }
}

function requireString(payload: Record<string, unknown>, key: string): string {
  const value = payload[key];
  if (typeof value !== "string") throw new VerificationError(UNREADABLE, ErrorCode.PARSE_ERROR);
  return value;
}

function requireNumber(payload: Record<string, unknown>, key: string): number {
  const value = payload[key];
  if (typeof value !== "number") throw new VerificationError(UNREADABLE, ErrorCode.PARSE_ERROR);
  return value;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
