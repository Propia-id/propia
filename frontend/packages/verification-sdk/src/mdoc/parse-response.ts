/**
 * Parses an ISO 18013-5 `DeviceResponse` for verification.
 *
 * Separate from the holder's `parseIssuerSigned` because the two see different
 * things: a wallet parses a credential it was issued, a verifier parses a
 * presentation someone sent it. The verifier's version is stricter — everything
 * here is attacker-controlled.
 */

import {
  CborTagged,
  decode,
  embedEncoded,
  encode,
  unwrapEmbedded,
  type CborMap,
  type CborValue,
} from "@sovrahq/holder-core/cbor";
import { parseSign1, type CoseSign1 } from "@sovrahq/holder-core/cose";
import { base64urlDecode } from "@sovrahq/holder-core/utils";

import { VerificationError } from "../errors.js";
import { ErrorCode } from "../types.js";

export const SOVRA_META_NAMESPACE = "io.sovra.meta.1";

/** RFC 9360's `x5chain` COSE header parameter. */
export const X5CHAIN_LABEL = 33;

export interface ParsedMdocItem {
  namespace: string;
  digestId: number;
  elementIdentifier: string;
  elementValue: CborValue;
  /** The `#6.24(...)` bytes the MSO digest covers, rebuilt around the received payload. */
  raw: Uint8Array;
}

export interface MdocMeta {
  holderDid: string;
  statusListIndex: number;
  /**
   * Per namespace, the element identifiers the holder may not withhold.
   *
   * Keyed by namespace because an element identifier is only unique within one,
   * so a flat list could not say which namespace's `document_number` it meant.
   */
  mandatoryElements: Record<string, string[]>;
  /** Where this credential's data elements live; not derivable from the docType. */
  namespace: string;
  credentialType: string;
  /**
   * The issuer's workspace address, which the revocation bitmaps and the Issuer
   * Trust Registry are keyed by.
   *
   * Read from here rather than from the docType because an ISO docType embeds
   * no address, and this verifier has no database to look one up in. A
   * generated docType carries one too; both are issuer-signed, and
   * `verifyMdoc` requires them to agree.
   */
  issuerAddress: string;
}

export interface ParsedMdocPresentation {
  docType: string;
  issuerAuth: CoseSign1;
  mso: CborMap;
  deviceAuth: CoseSign1;
  deviceNameSpacesBytes: CborValue;
  items: ParsedMdocItem[];
  meta: MdocMeta;
  claims: Record<string, unknown>;
  validFrom: number;
  validUntil: number;
}

export function parseDeviceResponse(b64: string): ParsedMdocPresentation {
  // Everything below parses attacker-controlled bytes, and the codec throws its
  // own error type. Converting here keeps the promise `verifyMdoc` makes: a
  // malformed presentation is a result, never an exception the caller has to
  // catch.
  try {
    return parse(b64);
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    throw new VerificationError(
      `Malformed mdoc presentation: ${error instanceof Error ? error.message : String(error)}`,
      ErrorCode.MDOC_PARSE_ERROR,
    );
  }
}

function parse(b64: string): ParsedMdocPresentation {
  const response = expectMap(decode(base64urlDecode(b64)), "DeviceResponse");

  if (response.get("status") !== 0) {
    throw new VerificationError("DeviceResponse status is not OK", ErrorCode.MDOC_PARSE_ERROR);
  }

  const documents = response.get("documents");
  if (!Array.isArray(documents) || documents.length !== 1) {
    // More than one would mean the holder answered a question we did not ask,
    // and choosing among them is the kind of guess that becomes a bug.
    throw new VerificationError(
      "Expected exactly one document in the DeviceResponse",
      ErrorCode.MDOC_PARSE_ERROR,
    );
  }

  const document = expectMap(documents[0], "Document");
  const docType = expectString(document.get("docType"), "docType");

  const issuerSigned = expectMap(document.get("issuerSigned"), "issuerSigned");
  const issuerAuth = parseSign1(issuerSigned.get("issuerAuth") as CborValue);
  const mso = decodeMso(issuerAuth);

  const deviceSigned = expectMap(document.get("deviceSigned"), "deviceSigned");
  const deviceAuthMap = expectMap(deviceSigned.get("deviceAuth"), "deviceAuth");

  if (deviceAuthMap.has("deviceMac")) {
    // A MAC is keyed by an ECDH exchange from device engagement, which an
    // online presentation has never performed. There is no key to check it with.
    throw new VerificationError(
      "deviceMac is not supported for online presentations",
      ErrorCode.DEVICE_AUTH_INVALID,
    );
  }

  const deviceAuth = parseSign1(deviceAuthMap.get("deviceSignature") as CborValue);
  const items = parseItems(issuerSigned.get("nameSpaces"));
  const validity = parseValidity(mso);

  return {
    docType,
    issuerAuth,
    mso,
    deviceAuth,
    deviceNameSpacesBytes: expectEmbedded(deviceSigned.get("nameSpaces")),
    items,
    meta: parseMeta(items),
    claims: flattenClaims(items),
    ...validity,
  };
}

// ── Internals ───────────────────────────────────────────

function parseItems(nameSpaces: CborValue | undefined): ParsedMdocItem[] {
  const map = expectMap(nameSpaces, "nameSpaces");
  const items: ParsedMdocItem[] = [];
  const seen = new Set<string>();

  for (const [namespace, list] of map.entries()) {
    if (typeof namespace !== "string" || !Array.isArray(list)) {
      throw new VerificationError("Malformed nameSpaces", ErrorCode.MDOC_PARSE_ERROR);
    }

    for (const tagged of list) {
      const raw = unwrapEmbedded(tagged);
      if (!raw) {
        throw new VerificationError(
          "IssuerSignedItem is not embedded CBOR",
          ErrorCode.MDOC_PARSE_ERROR,
        );
      }

      const item = expectMap(decode(raw), "IssuerSignedItem");
      const digestId = item.get("digestID");
      const elementIdentifier = item.get("elementIdentifier");

      if (typeof digestId !== "number" || typeof elementIdentifier !== "string") {
        throw new VerificationError("Malformed IssuerSignedItem", ErrorCode.MDOC_PARSE_ERROR);
      }

      // Two items claiming one digest slot would let a holder present a value
      // and a verifier read a different one.
      const key = `${namespace}/${digestId}`;
      if (seen.has(key)) {
        throw new VerificationError("Duplicate digestID", ErrorCode.MDOC_PARSE_ERROR);
      }
      seen.add(key);

      items.push({
        namespace,
        digestId,
        elementIdentifier,
        elementValue: item.get("elementValue") ?? null,
        raw: encode(embedEncoded(raw)),
      });
    }
  }
  return items;
}

function parseMeta(items: ParsedMdocItem[]): MdocMeta {
  const meta: Record<string, unknown> = {};
  for (const item of items) {
    if (item.namespace === SOVRA_META_NAMESPACE) {
      meta[item.elementIdentifier] = item.elementValue;
    }
  }

  const holderDid = meta.holder_did;
  const statusListIndex = meta.status_list_index;
  const mandatory = namespacedElements(meta.mandatory_elements);
  const credentialType = meta.credential_type;
  const namespace = meta.namespace;
  const issuerAddress = meta.issuer_address;

  if (
    typeof holderDid !== "string" ||
    typeof statusListIndex !== "number" ||
    mandatory === null ||
    typeof credentialType !== "string" ||
    typeof namespace !== "string" ||
    typeof issuerAddress !== "string" ||
    // Lowercase only, the single form the issuer writes. Accepting a
    // checksummed spelling too would make two credentials from one issuer
    // disagree about whether they came from the same place.
    !/^0x[0-9a-f]{40}$/.test(issuerAddress)
  ) {
    // These are enforcement inputs supplied by the party being enforced
    // against, so an incomplete set is a hard failure rather than absent
    // metadata — safe because the issuer signed the whole namespace.
    throw new VerificationError(
      "The credential is missing its Sovra metadata",
      ErrorCode.MDOC_PARSE_ERROR,
    );
  }

  return {
    holderDid,
    statusListIndex,
    mandatoryElements: mandatory,
    credentialType,
    namespace,
    issuerAddress,
  };
}

/**
 * The leaf certificate from `IssuerAuth`'s `x5chain`, or `null` when there is
 * none.
 *
 * RFC 9360 §2: one certificate travels as a bare byte string, several as an
 * array of them, leaf first. Both are the conformant way to say their own
 * thing, so both are read.
 *
 * Only the unprotected header, because that is where 18013-5 puts the chain.
 * And only the leaf: our chains are two levels by construction, the root is one
 * the caller supplied rather than one the credential did, and reading a
 * sender-supplied root is how a chain-validating reader gets talked into
 * trusting the sender.
 */
export function x5chainLeaf(issuerAuth: CoseSign1): Uint8Array | null {
  const value = issuerAuth.unprotectedHeader.get(X5CHAIN_LABEL);

  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value) && value[0] instanceof Uint8Array) return value[0];
  return null;
}

/**
 * Normalise the decoded `{namespace => [element]}` structure, or `null` if it is
 * anything else.
 *
 * CBOR maps decode to a JS `Map`, not a plain object — unlike holder-core, this
 * parser keeps element values raw rather than passing them through a display
 * conversion, so the `Map` arrives here as-is. Treating it as a record yields an
 * empty set and, since an empty mandatory set trivially passes, a presentation
 * that withheld a required element would verify.
 */
function namespacedElements(value: unknown): Record<string, string[]> | null {
  const entries =
    value instanceof Map
      ? [...value.entries()]
      : typeof value === "object" && value !== null && !Array.isArray(value)
        ? Object.entries(value as Record<string, unknown>)
        : null;

  if (entries === null) return null;

  const out: Record<string, string[]> = {};
  for (const [namespace, elements] of entries) {
    if (typeof namespace !== "string") return null;
    if (!Array.isArray(elements) || !elements.every((e) => typeof e === "string")) return null;
    out[namespace] = elements as string[];
  }
  return out;
}

/**
 * Claims keyed `<namespace>.<element_identifier>`, always.
 *
 * Namespace-qualified even for the credential's own docType, for two reasons.
 * DCQL asks for claims as `path: [namespace, element_identifier]`, so keying the
 * response the same way means request and response line up with no rule to
 * remember. And mdoc namespaces exist precisely so two of them can carry an
 * element of the same name — bare identifiers would collide.
 *
 * `Sovra.Verification.Verifier.match_mdoc_entry/3` builds the same keys. A
 * divergence here means an integrator's `claims[...]` lookup silently returns
 * undefined when they move between the hosted flow and chain-only verification.
 */
function flattenClaims(items: ParsedMdocItem[]): Record<string, unknown> {
  const claims: Record<string, unknown> = {};

  for (const item of items) {
    if (item.namespace === SOVRA_META_NAMESPACE) continue;
    claims[`${item.namespace}.${item.elementIdentifier}`] = displayValue(item.elementValue);
  }
  return claims;
}

/**
 * A decoded CBOR value as something an integrator can use.
 *
 * Byte strings come back as the bytes. They used to come back as
 * `{ __bytes: length }`, which was harmless while nothing carried meaningful
 * ones — and is not, now that an mDL's `portrait` is a byte string and showing
 * the photograph is the entire reason a verifier asked for it.
 *
 * This is the one place the SDK's claim values differ from the backend's, which
 * base64url-encodes bytes because `presentation_data` is a jsonb column and
 * JSON has no byte type. A JS library returning JS values has no such
 * constraint, and converting anyway would lose the type for no gain. The
 * *keys* are identical, which is what an integrator's lookup depends on.
 */
function displayValue(value: CborValue): unknown {
  if (value instanceof Uint8Array) return value;
  if (value instanceof CborTagged) return displayValue(value.value);
  if (Array.isArray(value)) return value.map(displayValue);
  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of value.entries()) out[String(k)] = displayValue(v);
    return out;
  }
  if (typeof value === "bigint") return value.toString();
  return value;
}

function decodeMso(issuerAuth: CoseSign1): CborMap {
  if (!issuerAuth.payload) {
    throw new VerificationError("issuerAuth has no payload", ErrorCode.MDOC_PARSE_ERROR);
  }
  const inner = unwrapEmbedded(decode(issuerAuth.payload));
  if (!inner) {
    throw new VerificationError("MSO is not embedded CBOR", ErrorCode.MDOC_PARSE_ERROR);
  }
  return expectMap(decode(inner), "MSO");
}

function parseValidity(mso: CborMap): { validFrom: number; validUntil: number } {
  const info = expectMap(mso.get("validityInfo"), "validityInfo");
  return {
    validFrom: toUnixSeconds(info.get("validFrom")),
    validUntil: toUnixSeconds(info.get("validUntil")),
  };
}

function toUnixSeconds(value: CborValue | undefined): number {
  if (value instanceof CborTagged && typeof value.value === "string") {
    const parsed = Date.parse(value.value);
    if (!Number.isNaN(parsed)) return Math.floor(parsed / 1000);
  }
  throw new VerificationError("Malformed validityInfo", ErrorCode.MDOC_PARSE_ERROR);
}

function expectMap(value: CborValue | undefined, what: string): CborMap {
  if (!(value instanceof Map)) {
    throw new VerificationError(`Malformed ${what}`, ErrorCode.MDOC_PARSE_ERROR);
  }
  return value;
}

function expectString(value: CborValue | undefined, what: string): string {
  if (typeof value !== "string") {
    throw new VerificationError(`Malformed ${what}`, ErrorCode.MDOC_PARSE_ERROR);
  }
  return value;
}

// `DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)`. Checked here
// because `verifyDeviceAuth` encodes it, and an unencodable value would throw
// past `verifyMdoc`'s contract to return a result rather than raise.
function expectEmbedded(value: CborValue | undefined): CborValue {
  if (value === undefined || unwrapEmbedded(value) === null) {
    throw new VerificationError(
      "Malformed deviceSigned.nameSpaces",
      ErrorCode.MDOC_PARSE_ERROR,
    );
  }
  return value;
}
