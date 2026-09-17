/**
 * Just enough X.509 to check an ISO/IEC 18013-5 mDL certificate chain.
 *
 * The SDK has no Node `crypto.X509Certificate` to lean on — it runs in a
 * browser, in a React Native verifier app, and on a server — so the parsing is
 * here. Scoped hard to what 18013-5 Annex B actually profiles: two levels, one
 * curve, one signature algorithm.
 *
 * ## What this deliberately is not
 *
 * Not a general X.509 implementation. It has no CRL fetching, no name
 * constraints, no policy processing, no RSA, and no path building — the chain
 * is two certificates because Annex B forbids intermediates, so "path building"
 * is finding the anchor whose subject matches the leaf's issuer.
 *
 * Writing less is the point. A general implementation would need the parts of
 * RFC 5280 this profile does not use, and every one of them is somewhere to be
 * wrong about a certificate a real authority issued.
 *
 * ## What the chain does and does not establish
 *
 * It establishes that a trust anchor the *caller* chose vouches for the key
 * that signed the credential. It does not establish that the credential is
 * good — the signature check does that, afterwards, against the key this
 * returns. Reversing the order is the classic way to accept a forgery.
 */

import { p256 } from "@noble/curves/p256";
import { sha256 } from "@sovrahq/holder-core/utils";

// ── DER ─────────────────────────────────────────────────

const enum Tag {
  BOOLEAN = 0x01,
  INTEGER = 0x02,
  BIT_STRING = 0x03,
  OCTET_STRING = 0x04,
  NULL = 0x05,
  OID = 0x06,
  UTF8_STRING = 0x0c,
  SEQUENCE = 0x30,
  SET = 0x31,
  PRINTABLE_STRING = 0x13,
  T61_STRING = 0x14,
  IA5_STRING = 0x16,
  UTC_TIME = 0x17,
  GENERALIZED_TIME = 0x18,
  BMP_STRING = 0x1e,
}

interface Element {
  tag: number;
  /** The contents, without the tag and length octets. */
  value: Uint8Array;
  /** Tag, length and contents — what a signature is computed over. */
  raw: Uint8Array;
  /** Offset just past this element in the buffer it was read from. */
  end: number;
}

export class CertificateError extends Error {}

function fail(message: string): never {
  throw new CertificateError(message);
}

/** Read one TLV starting at `offset`. */
function readElement(buffer: Uint8Array, offset: number): Element {
  if (offset + 2 > buffer.length) fail("truncated DER element");

  const tag = buffer[offset]!;
  const first = buffer[offset + 1]!;
  let length: number;
  let headerLength: number;

  if (first < 0x80) {
    length = first;
    headerLength = 2;
  } else {
    // Long form: the low seven bits say how many octets carry the length.
    // Indefinite length (0x80) is a BER encoding and never valid in DER.
    const lengthOctets = first & 0x7f;
    if (lengthOctets === 0 || lengthOctets > 4) fail("unsupported DER length");
    if (offset + 2 + lengthOctets > buffer.length) fail("truncated DER length");

    length = 0;
    for (let i = 0; i < lengthOctets; i++) {
      length = length * 256 + buffer[offset + 2 + i]!;
    }
    headerLength = 2 + lengthOctets;
  }

  const start = offset + headerLength;
  const end = start + length;
  if (end > buffer.length) fail("DER element runs past the end of the buffer");

  return {
    tag,
    value: buffer.subarray(start, end),
    raw: buffer.subarray(offset, end),
    end,
  };
}

/** Every direct child of a constructed element. */
function readChildren(value: Uint8Array): Element[] {
  const children: Element[] = [];
  let offset = 0;
  while (offset < value.length) {
    const element = readElement(value, offset);
    children.push(element);
    offset = element.end;
  }
  return children;
}

function expect(element: Element | undefined, tag: number, what: string): Element {
  if (!element || element.tag !== tag) fail(`expected ${what}`);
  return element;
}

/** Decode an OID's contents into dotted-decimal form. */
function decodeOid(value: Uint8Array): string {
  if (value.length === 0) fail("empty OID");

  // The first two arcs are packed into one octet: 40 * first + second.
  const first = value[0]!;
  const arcs = [Math.floor(first / 40), first % 40];

  let current = 0;
  for (let i = 1; i < value.length; i++) {
    const byte = value[i]!;
    current = current * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(current);
      current = 0;
    }
  }
  return arcs.join(".");
}

function decodeString(element: Element): string {
  if (element.tag === Tag.BMP_STRING) {
    // UTF-16BE. Rare, but a national authority's name is exactly where it turns
    // up, so decoding it beats rendering a name as mojibake.
    let out = "";
    for (let i = 0; i + 1 < element.value.length; i += 2) {
      out += String.fromCharCode((element.value[i]! << 8) | element.value[i + 1]!);
    }
    return out;
  }
  return new TextDecoder().decode(element.value);
}

/**
 * Seconds since the epoch from a UTCTime or GeneralizedTime.
 *
 * RFC 5280 pins both to UTC with seconds present, and UTCTime's two-digit year
 * to 1950-2049.
 */
function decodeTime(element: Element): number {
  const text = new TextDecoder().decode(element.value);

  let rest: string;
  let year: number;

  if (element.tag === Tag.UTC_TIME) {
    if (text.length < 13) fail("malformed UTCTime");
    const yy = Number(text.slice(0, 2));
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = text.slice(2);
  } else if (element.tag === Tag.GENERALIZED_TIME) {
    if (text.length < 15) fail("malformed GeneralizedTime");
    year = Number(text.slice(0, 4));
    rest = text.slice(4);
  } else {
    fail("expected a time");
  }

  const month = Number(rest.slice(0, 2));
  const day = Number(rest.slice(2, 4));
  const hour = Number(rest.slice(4, 6));
  const minute = Number(rest.slice(6, 8));
  const second = Number(rest.slice(8, 10));

  if (!rest.endsWith("Z")) fail("certificate time is not UTC");
  if ([month, day, hour, minute, second].some(Number.isNaN)) fail("malformed certificate time");

  return Math.floor(Date.UTC(year, month - 1, day, hour, minute, second) / 1000);
}

// ── OIDs ────────────────────────────────────────────────

const OID_COMMON_NAME = "2.5.4.3";
const OID_COUNTRY = "2.5.4.6";
const OID_STATE = "2.5.4.8";
const OID_ORGANIZATION = "2.5.4.10";

const OID_KEY_USAGE = "2.5.29.15";
const OID_EXTENDED_KEY_USAGE = "2.5.29.37";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";

const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_P256 = "1.2.840.10045.3.1.7";
const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";

/** ISO/IEC 18013-5 Annex B: the EKU a Document Signer Certificate carries. */
export const OID_MDL_DOCUMENT_SIGNER = "1.0.18013.5.1.2";

/** Annex B caps a Document Signer Certificate at 457 days. */
export const MAX_DOCUMENT_SIGNER_DAYS = 457;

// KeyUsage is a BIT STRING; these are its bit positions in RFC 5280 order.
const KEY_USAGE_DIGITAL_SIGNATURE = 0;
const KEY_USAGE_KEY_CERT_SIGN = 5;
const KEY_USAGE_CRL_SIGN = 6;

export interface DistinguishedName {
  country?: string;
  state?: string;
  organization?: string;
  commonName?: string;
}

export interface Certificate {
  der: Uint8Array;
  /** The TBSCertificate bytes, verbatim — what the issuer's signature covers. */
  tbsBytes: Uint8Array;
  signature: Uint8Array;
  signatureAlgorithm: string;
  subject: DistinguishedName;
  issuer: DistinguishedName;
  /** The subject's DER, compared byte for byte against a child's issuer DER. */
  subjectBytes: Uint8Array;
  issuerBytes: Uint8Array;
  notBefore: number;
  notAfter: number;
  publicKey: { x: Uint8Array; y: Uint8Array };
  version: number;
  keyUsage: number[];
  extendedKeyUsage: string[];
  basicConstraints?: { ca: boolean; pathLength?: number };
}

/** Parse a DER certificate. */
export function parseCertificate(der: Uint8Array): Certificate {
  const certificate = expect(readElement(der, 0), Tag.SEQUENCE, "Certificate");
  const [tbs, algorithm, signatureBits] = readChildren(certificate.value);

  expect(tbs, Tag.SEQUENCE, "TBSCertificate");
  expect(algorithm, Tag.SEQUENCE, "AlgorithmIdentifier");
  expect(signatureBits, Tag.BIT_STRING, "signature");

  const fields = readChildren(tbs!.value);
  let index = 0;

  // [0] EXPLICIT Version, optional and defaulting to v1. Only v3 carries
  // extensions, so anything else fails the profile checks later anyway.
  let version = 1;
  if (fields[0]?.tag === 0xa0) {
    const versionInteger = expect(readChildren(fields[0].value)[0], Tag.INTEGER, "Version");
    version = decodeInteger(versionInteger.value) + 1;
    index = 1;
  }

  index++; // serialNumber
  index++; // signature AlgorithmIdentifier (repeated inside the TBS)

  const issuerElement = expect(fields[index++], Tag.SEQUENCE, "issuer");
  const validity = expect(fields[index++], Tag.SEQUENCE, "validity");
  const subjectElement = expect(fields[index++], Tag.SEQUENCE, "subject");
  const spki = expect(fields[index++], Tag.SEQUENCE, "subjectPublicKeyInfo");

  const [notBeforeElement, notAfterElement] = readChildren(validity.value);
  if (!notBeforeElement || !notAfterElement) fail("malformed validity");

  // Extensions are [3] EXPLICIT, after the optional issuer/subject unique ids.
  const extensionsElement = fields.slice(index).find((field) => field.tag === 0xa3);
  const extensions = extensionsElement
    ? readChildren(expect(readChildren(extensionsElement.value)[0], Tag.SEQUENCE, "Extensions").value)
    : [];

  const parsed = parseExtensions(extensions);

  return {
    der,
    tbsBytes: tbs!.raw,
    // A BIT STRING's first content octet counts unused trailing bits; for a
    // signature it is always zero, and the DER ECDSA-Sig-Value follows.
    signature: signatureBits!.value.subarray(1),
    signatureAlgorithm: decodeOid(
      expect(readChildren(algorithm!.value)[0], Tag.OID, "signature OID").value,
    ),
    subject: parseName(subjectElement),
    issuer: parseName(issuerElement),
    subjectBytes: subjectElement.raw,
    issuerBytes: issuerElement.raw,
    notBefore: decodeTime(notBeforeElement),
    notAfter: decodeTime(notAfterElement),
    publicKey: parsePublicKey(spki),
    version,
    ...parsed,
  };
}

function decodeInteger(value: Uint8Array): number {
  let result = 0;
  for (const byte of value) result = result * 256 + byte;
  return result;
}

function parseName(element: Element): DistinguishedName {
  const name: DistinguishedName = {};

  for (const rdn of readChildren(element.value)) {
    for (const attribute of readChildren(rdn.value)) {
      const [type, value] = readChildren(attribute.value);
      if (!type || !value) continue;

      const text = decodeString(value);
      switch (decodeOid(type.value)) {
        case OID_COUNTRY:
          name.country = text;
          break;
        case OID_STATE:
          name.state = text;
          break;
        case OID_ORGANIZATION:
          name.organization = text;
          break;
        case OID_COMMON_NAME:
          name.commonName = text;
          break;
      }
    }
  }
  return name;
}

/**
 * The subject's P-256 point.
 *
 * Uncompressed only. 18013-5 requires it, and a compressed point would need
 * curve arithmetic to decompress — arithmetic whose only purpose would be to
 * accept an encoding the profile forbids.
 */
function parsePublicKey(spki: Element): { x: Uint8Array; y: Uint8Array } {
  const [algorithm, keyBits] = readChildren(spki.value);
  if (!algorithm || !keyBits) fail("malformed subjectPublicKeyInfo");

  const [algorithmOid, parameters] = readChildren(algorithm.value);
  if (decodeOid(expect(algorithmOid, Tag.OID, "key algorithm").value) !== OID_EC_PUBLIC_KEY) {
    fail("certificate does not carry an EC public key");
  }
  if (!parameters || decodeOid(expect(parameters, Tag.OID, "curve").value) !== OID_P256) {
    fail("certificate key is not on P-256");
  }

  const point = keyBits.value.subarray(1); // drop the unused-bits octet
  if (point.length !== 65 || point[0] !== 0x04) fail("expected an uncompressed P-256 point");

  return { x: point.subarray(1, 33), y: point.subarray(33, 65) };
}

function parseExtensions(extensions: Element[]): {
  keyUsage: number[];
  extendedKeyUsage: string[];
  basicConstraints?: { ca: boolean; pathLength?: number };
} {
  let keyUsage: number[] = [];
  let extendedKeyUsage: string[] = [];
  let basicConstraints: { ca: boolean; pathLength?: number } | undefined;

  for (const extension of extensions) {
    const children = readChildren(extension.value);
    const oidElement = children[0];
    if (!oidElement) continue;

    // The optional `critical` BOOLEAN sits between the OID and the value.
    const valueElement = children.find((child) => child.tag === Tag.OCTET_STRING);
    if (!valueElement) continue;

    const inner = readElement(valueElement.value, 0);

    switch (decodeOid(oidElement.value)) {
      case OID_KEY_USAGE:
        keyUsage = decodeBitPositions(inner.value);
        break;
      case OID_EXTENDED_KEY_USAGE:
        extendedKeyUsage = readChildren(inner.value).map((usage) => decodeOid(usage.value));
        break;
      case OID_BASIC_CONSTRAINTS: {
        const parts = readChildren(inner.value);
        const ca = parts[0]?.tag === Tag.BOOLEAN ? parts[0].value[0] !== 0 : false;
        const pathElement = parts.find((part) => part.tag === Tag.INTEGER);
        basicConstraints = {
          ca,
          ...(pathElement ? { pathLength: decodeInteger(pathElement.value) } : {}),
        };
        break;
      }
    }
  }
  return { keyUsage, extendedKeyUsage, ...(basicConstraints ? { basicConstraints } : {}) };
}

/** The set bit positions of a BIT STRING, counting from the most significant. */
function decodeBitPositions(value: Uint8Array): number[] {
  const unused = value[0] ?? 0;
  const bits = value.subarray(1);
  const positions: number[] = [];

  for (let byteIndex = 0; byteIndex < bits.length; byteIndex++) {
    const byte = bits[byteIndex]!;
    const lastBit = byteIndex === bits.length - 1 ? 7 - unused : 7;
    for (let bit = 0; bit <= lastBit; bit++) {
      if (byte & (0x80 >> bit)) positions.push(byteIndex * 8 + bit);
    }
  }
  return positions;
}

// ── Verification ────────────────────────────────────────

/** Whether `certificate` was signed by `issuer`'s key. */
export function verifySignedBy(certificate: Certificate, issuer: Certificate): boolean {
  if (certificate.signatureAlgorithm !== OID_ECDSA_SHA256) return false;

  const publicKey = new Uint8Array(65);
  publicKey[0] = 0x04;
  publicKey.set(issuer.publicKey.x, 1);
  publicKey.set(issuer.publicKey.y, 33);

  try {
    // The DER ECDSA-Sig-Value as it sits in the certificate. `@noble/curves`
    // reads both encodings; saying which removes the guess.
    return p256.verify(certificate.signature, sha256(certificate.tbsBytes), publicKey, {
      format: "der",
      prehash: false,
    });
  } catch {
    return false;
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

export interface ChainOptions {
  /** Seconds since the epoch to check validity windows against. Defaults to now. */
  now?: number;
}

/**
 * Validate a Document Signer Certificate against a set of trust anchors.
 *
 * Returns the anchor that vouched for it, so a caller can say *which* authority
 * the credential came from rather than only that some accepted anchor did.
 *
 * The anchor is matched by issuer name and then required to have actually
 * signed the leaf. Matching by name alone would let anyone who names their root
 * `C=ES, CN=Spain` be checked against Spain's — and then the signature check is
 * what refuses them, which is why the name is a lookup and never a decision.
 */
export function validateDocumentSignerChain(
  leafDer: Uint8Array,
  anchorDers: Uint8Array[],
  options: ChainOptions = {},
): { leaf: Certificate; anchor: Certificate } {
  const now = options.now ?? Math.floor(Date.now() / 1000);

  if (anchorDers.length === 0) fail("no trust anchors supplied");

  const leaf = parseCertificate(leafDer);
  checkDocumentSignerProfile(leaf, now);

  const candidates = anchorDers
    .map((der) => parseCertificate(der))
    .filter((anchor) => sameBytes(anchor.subjectBytes, leaf.issuerBytes));

  if (candidates.length === 0) fail("no trust anchor matches the certificate's issuer");

  for (const anchor of candidates) {
    if (!verifySignedBy(leaf, anchor)) continue;

    checkIacaProfile(anchor, now);
    checkSubjectAgreement(leaf, anchor);
    return { leaf, anchor };
  }

  fail("no trust anchor signed this certificate");
}

function checkWindow(certificate: Certificate, now: number, what: string): void {
  if (now < certificate.notBefore) fail(`${what} is not valid yet`);
  if (now >= certificate.notAfter) fail(`${what} has expired`);
}

function checkDocumentSignerProfile(leaf: Certificate, now: number): void {
  checkWindow(leaf, now, "document signer certificate");

  if (leaf.version !== 3) fail("document signer certificate is not X.509 v3");
  if (leaf.basicConstraints?.ca) fail("document signer certificate is a CA");

  // Exactly digitalSignature. A document signer that could also sign
  // certificates would be an intermediate CA, which Annex B does not have.
  if (leaf.keyUsage.length !== 1 || leaf.keyUsage[0] !== KEY_USAGE_DIGITAL_SIGNATURE) {
    fail("document signer certificate key usage is not digitalSignature");
  }

  if (!leaf.extendedKeyUsage.includes(OID_MDL_DOCUMENT_SIGNER)) {
    fail("document signer certificate does not carry the mDL extended key usage");
  }

  const days = (leaf.notAfter - leaf.notBefore) / 86400;
  if (days > MAX_DOCUMENT_SIGNER_DAYS) {
    fail(`document signer certificate is valid for more than ${MAX_DOCUMENT_SIGNER_DAYS} days`);
  }
}

function checkIacaProfile(anchor: Certificate, now: number): void {
  checkWindow(anchor, now, "issuing authority certificate");

  if (!anchor.basicConstraints?.ca) fail("trust anchor is not a CA");

  // 18013-5's PKI is two levels: an IACA signs document signers, never another
  // CA. A path length above zero would be claiming otherwise.
  const pathLength = anchor.basicConstraints.pathLength;
  if (pathLength !== undefined && pathLength !== 0) fail("trust anchor allows intermediate CAs");

  if (
    !anchor.keyUsage.includes(KEY_USAGE_KEY_CERT_SIGN) ||
    !anchor.keyUsage.includes(KEY_USAGE_CRL_SIGN)
  ) {
    fail("trust anchor key usage is not keyCertSign + cRLSign");
  }
}

/**
 * The subject rules that let one national root certify a signer per region.
 *
 * Country must match the anchor's, and `stateOrProvinceName` is constrained
 * only when the anchor declares one — so a root naming no state can certify
 * signers that each name their own.
 */
function checkSubjectAgreement(leaf: Certificate, anchor: Certificate): void {
  if (!leaf.subject.country) fail("document signer certificate names no country");

  if (leaf.subject.country !== anchor.subject.country) {
    fail("document signer certificate's country does not match its issuing authority's");
  }

  if (anchor.subject.state && leaf.subject.state !== anchor.subject.state) {
    fail("document signer certificate's state does not match its issuing authority's");
  }
}

// ── PEM ─────────────────────────────────────────────────

const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;

/**
 * Every certificate in a PEM bundle, as DER.
 *
 * Trust anchors reach a verifier as PEM, because that is what an authority
 * publishes and what fits in a config file.
 */
export function pemToDer(pem: string): Uint8Array[] {
  const out: Uint8Array[] = [];

  for (const match of pem.matchAll(PEM_CERTIFICATE)) {
    const base64 = match[1]!.replace(/\s+/g, "");
    const binary = atob(base64);
    const der = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) der[i] = binary.charCodeAt(i);
    out.push(der);
  }

  if (out.length === 0) fail("no PEM certificate found");
  return out;
}
