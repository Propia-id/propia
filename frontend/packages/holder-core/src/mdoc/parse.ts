/**
 * Parses the `IssuerSigned` structure OID4VCI delivers for an `mso_mdoc`
 * credential.
 *
 * Not a full `DeviceResponse` — the holder has nothing to sign at issuance,
 * because device authentication is bound to a verifier's session that does not
 * exist yet.
 */

import {
  CborTagged,
  CBOR_TAG,
  decode,
  embedEncoded,
  encode,
  unwrapEmbedded,
  type CborMap,
  type CborValue,
} from "../cbor/index.js";
import { decodeSign1, type CoseSign1 } from "../cose/index.js";
import { base64urlDecode, bytesToHex } from "../utils/index.js";

export const SOVRA_META_NAMESPACE = "io.sovra.meta.1";

/** Where an ISO 18013-5 mDL's data elements live — not its docType. */
export const ISO_MDL_NAMESPACE = "org.iso.18013.5.1";

/** ISO 18013-5's element for the holder's photograph. */
export const PORTRAIT_ELEMENT = "portrait";

export interface ParsedMdocItem {
  namespace: string;
  digestId: number;
  elementIdentifier: string;
  elementValue: CborValue;
  /**
   * The `#6.24(bstr .cbor IssuerSignedItem)` bytes the MSO digest covers.
   *
   * Rebuilt around the payload the decoder hands back untouched, not re-encoded
   * from the decoded item — which would not reproduce them. The rebuild is
   * normalising, so it lands on exactly the bytes the issuer signed. See
   * `embedEncoded`.
   */
  raw: Uint8Array;
}

export interface ParsedMdoc {
  docType: string;
  /**
   * Where this credential's data elements live.
   *
   * Not derivable from the docType: ISO pairs `org.iso.18013.5.1.mDL` with
   * `org.iso.18013.5.1`, and a document may carry further namespaces beside it.
   * Read from the Sovra meta namespace, falling back to the docType — which is
   * what a Sovra-generated schema means by it.
   */
  namespace: string;
  issuerAuth: CoseSign1;
  /** Decoded MSO. Its digests are checked at verification, not here. */
  mso: CborMap;
  items: ParsedMdocItem[];
  validFrom: number;
  validUntil: number;
  /**
   * From the Sovra meta namespace: per namespace, the element identifiers the
   * holder may not withhold.
   *
   * Keyed by namespace because an element identifier is only unique within one
   * — a document carrying an ISO namespace and a domestic one can hold two
   * `document_number`s.
   */
  mandatoryElements: Record<string, string[]>;
  holderDid: string | null;
  /**
   * From the Sovra meta namespace: the credential's bit in its issuer's
   * revocation and suspension lists, and the address those lists are kept
   * under. An mdoc has no `credentialStatus` field, so this is where the issuer
   * signs them. Null on a document that carries no such namespace.
   */
  statusListIndex: number | null;
  issuerAddress: string | null;
}

export function parseIssuerSigned(issuerSignedB64u: string): ParsedMdoc {
  const issuerSigned = expectMap(decode(base64urlDecode(issuerSignedB64u)));

  const issuerAuth = decodeSign1(encode(expectPresent(issuerSigned.get("issuerAuth"))));
  const mso = decodeMso(issuerAuth);

  const nameSpaces = expectMap(expectPresent(issuerSigned.get("nameSpaces")));
  const items: ParsedMdocItem[] = [];

  for (const [namespace, rawItems] of nameSpaces.entries()) {
    if (typeof namespace !== "string" || !Array.isArray(rawItems)) continue;

    for (const tagged of rawItems) {
      const raw = unwrapEmbedded(tagged);
      if (!raw) continue;

      const item = expectMap(decode(raw));
      items.push({
        namespace,
        digestId: Number(item.get("digestID")),
        elementIdentifier: String(item.get("elementIdentifier")),
        elementValue: item.get("elementValue") ?? null,
        // `encode` of a decoded tag-24 wrapper reproduces the original bytes,
        // since the inner value is an opaque byte string.
        raw: encode(embedEncoded(raw)),
      });
    }
  }

  const validity = expectMap(expectPresent(mso.get("validityInfo")));
  const meta = metaElements(items);
  const docType = String(mso.get("docType"));
  const namespace = typeof meta.namespace === "string" ? meta.namespace : docType;

  return {
    docType,
    namespace,
    issuerAuth,
    mso,
    items,
    validFrom: toUnixSeconds(validity.get("validFrom")),
    validUntil: toUnixSeconds(validity.get("validUntil")),
    mandatoryElements: mandatoryElements(meta.mandatory_elements),
    holderDid: typeof meta.holder_did === "string" ? meta.holder_did : null,
    statusListIndex: statusListIndex(meta.status_list_index),
    issuerAddress: typeof meta.issuer_address === "string" ? meta.issuer_address : null,
  };
}

function statusListIndex(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** Narrow the decoded `%{namespace => [element]}` map, dropping anything malformed. */
function mandatoryElements(value: unknown): Record<string, string[]> {
  if (typeof value !== "object" || value === null) return {};

  const out: Record<string, string[]> = {};
  for (const [namespace, elements] of Object.entries(value as Record<string, unknown>)) {
    if (!Array.isArray(elements)) continue;
    out[namespace] = elements.filter((v): v is string => typeof v === "string");
  }
  return out;
}

/**
 * Flatten mdoc elements into the display-ready `claims` map.
 *
 * Two rules matter here. Elements from the Sovra meta namespace are dropped —
 * they are plumbing with nothing to render. And values are normalised: a
 * portrait left as raw bytes would otherwise reach `JSON.stringify` in the card
 * renderer and the search index as a twenty-thousand-character array.
 */
export function flattenClaims(
  items: ParsedMdocItem[],
  namespace: string,
): Record<string, unknown> {
  const claims: Record<string, unknown> = {};

  for (const item of items) {
    if (item.namespace === SOVRA_META_NAMESPACE) continue;
    claims[claimKeyFor(item, namespace)] = displayValue(item.elementValue);
  }
  return claims;
}

/**
 * The key an element is flattened to.
 *
 * Unqualified for the credential's own namespace. ISO permits several per
 * document — a real mDL pairs `org.iso.18013.5.1` with a domestic namespace —
 * so anything else is qualified rather than allowed to collide.
 *
 * Takes the namespace rather than the docType. They are the same string for a
 * Sovra-generated schema, and passing the docType for an ISO credential would
 * qualify every claim, turning `family_name` into
 * `org.iso.18013.5.1.family_name` across the card face.
 */
export function claimKeyFor(item: ParsedMdocItem, namespace: string): string {
  return item.namespace === namespace
    ? item.elementIdentifier
    : `${item.namespace}.${item.elementIdentifier}`;
}

/**
 * What `displayValue` leaves in place of a byte string.
 *
 * A portrait is tens of kilobytes and `claims` is persisted to secure storage
 * on every write, so keeping the bytes there would store the photograph twice
 * and re-serialise it on every change. `readElementBytes` gets them back out
 * of the credential blob, which is where they already are.
 */
export interface BytesDescriptor {
  __bytes: number;
  __preview: string;
}

/** Whether a flattened claim value stands in for a byte string. */
export function isBytesDescriptor(value: unknown): value is BytesDescriptor {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as BytesDescriptor).__bytes === "number" &&
    typeof (value as BytesDescriptor).__preview === "string"
  );
}

/**
 * The bytes of a byte-string element, read back from the credential itself.
 *
 * For the one thing an mDL is mostly for: showing the holder's photograph.
 * `claims` carries only a descriptor, so this re-parses the `IssuerSigned`
 * blob — cheap enough for a detail screen, and the bytes are never held in two
 * places where they could disagree.
 *
 * `null` when the element is absent, or is not a byte string.
 */
export function readElementBytes(
  issuerSignedB64u: string,
  namespace: string,
  elementIdentifier: string,
): Uint8Array | null {
  const parsed = parseIssuerSigned(issuerSignedB64u);

  const item = parsed.items.find(
    (candidate) =>
      candidate.namespace === namespace && candidate.elementIdentifier === elementIdentifier,
  );

  return item?.elementValue instanceof Uint8Array ? item.elementValue : null;
}

/**
 * A `data:` URI for an mDL's portrait, or `undefined` when it carries none.
 *
 * Here rather than in a renderer because every question it answers is about
 * the format: which element holds the photograph, where the bytes live, and
 * what kind of image they are. What a wallet does with the URI is the
 * renderer's business.
 */
export function portraitDataUri(
  issuerSignedB64u: string,
  namespace = ISO_MDL_NAMESPACE,
): string | undefined {
  try {
    const bytes = readElementBytes(issuerSignedB64u, namespace, PORTRAIT_ELEMENT);
    if (!bytes || bytes.length === 0) return undefined;

    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return `data:${imageMediaType(bytes)};base64,${btoa(binary)}`;
  } catch {
    // A credential that will not re-parse is not a reason to fail a whole
    // screen; every other claim still renders.
    return undefined;
  }
}

/**
 * The media type from the bytes themselves, never from a declaration.
 *
 * ISO says a portrait is JPEG or JPEG 2000, and issuers ship PNG anyway. The
 * magic number is the only thing that is actually true about the bytes.
 */
function imageMediaType(bytes: Uint8Array): string {
  if (bytes[0] === 0x89 && bytes[1] === 0x50) return "image/png";
  if (bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x00 && bytes[3] === 0x0c) {
    return "image/jp2";
  }
  return "image/jpeg";
}

/**
 * The vehicle categories in an ISO `driving_privileges` value, or `null` when
 * the value is not one.
 *
 * A structured array is the one claim shape a renderer cannot do anything
 * sensible with generically, and this is the only one an mDL carries. Deciding
 * *whether* a value is a driving-privileges array is a question about the
 * format, so it is answered here; how to lay the categories out is not.
 *
 * `null` rather than an empty array for a non-match, so a caller can tell "not
 * this shape" from "this shape, no categories" — the second cannot happen in a
 * conformant credential and would be worth rendering as an anomaly.
 */
export function drivingPrivilegeCategories(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;

  const categories = value.map((entry) =>
    typeof entry === "object" && entry !== null
      ? (entry as { vehicle_category_code?: unknown }).vehicle_category_code
      : undefined,
  );

  if (!categories.every((code): code is string => typeof code === "string" && code !== "")) {
    return null;
  }
  return categories;
}

/** Turn a CBOR value into something safe to render, search and JSON-encode. */
export function displayValue(value: CborValue): unknown {
  if (value instanceof Uint8Array) {
    // Descriptor rather than content: the bytes stay in the credential blob,
    // and `readElementBytes` is how a renderer gets them.
    return { __bytes: value.length, __preview: bytesToHex(value.subarray(0, 4), false) };
  }

  if (value instanceof CborTagged) {
    switch (value.tag) {
      case CBOR_TAG.FULL_DATE:
      case CBOR_TAG.DATE_TIME:
        return value.value;
      default:
        return displayValue(value.value);
    }
  }

  if (Array.isArray(value)) return value.map(displayValue);

  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of value.entries()) out[String(k)] = displayValue(v);
    return out;
  }

  if (typeof value === "bigint") return value.toString();

  return value;
}

// ─── Internals ────────────────────────────────────────

function decodeMso(issuerAuth: CoseSign1): CborMap {
  if (!issuerAuth.payload) throw new Error("mdoc issuerAuth has no payload");
  const inner = unwrapEmbedded(decode(issuerAuth.payload));
  if (!inner) throw new Error("mdoc MSO is not embedded CBOR");
  return expectMap(decode(inner));
}

function metaElements(items: ParsedMdocItem[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const item of items) {
    if (item.namespace !== SOVRA_META_NAMESPACE) continue;
    out[item.elementIdentifier] = displayValue(item.elementValue);
  }
  return out;
}

function toUnixSeconds(value: CborValue | undefined): number {
  if (value instanceof CborTagged && typeof value.value === "string") {
    return Math.floor(Date.parse(value.value) / 1000);
  }
  return 0;
}

function expectMap(value: CborValue): CborMap {
  if (!(value instanceof Map)) throw new Error("expected a CBOR map");
  return value;
}

function expectPresent<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("missing required mdoc field");
  return value;
}
