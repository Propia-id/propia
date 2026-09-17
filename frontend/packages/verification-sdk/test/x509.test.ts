/**
 * `src/x509.ts` against certificates this repo's Elixir minter produced.
 *
 * Deliberately not against certificates built by the TypeScript under test —
 * there is no X.509 writer here, and if there were, a parser tested only
 * against its own writer proves that two halves of one misreading agree.
 * `mix sovra.mdl_certificate_fixture` mints these; `Sovra.X509.Certificate`
 * validates the same ones on the backend, so a rule that diverges between the
 * two verifiers shows up as a test that disagrees with its sibling.
 *
 * The clock is pinned to `validAt`. Annex B caps a document signer at 457 days,
 * so a fixture checked against the real clock would start failing about a year
 * after it was generated, looking exactly like a regression.
 */

import { describe, expect, it } from "vitest";

import fixtures from "./fixtures/mdl-certificates.json";
import {
  CertificateError,
  MAX_DOCUMENT_SIGNER_DAYS,
  OID_MDL_DOCUMENT_SIGNER,
  parseCertificate,
  pemToDer,
  validateDocumentSignerChain,
  verifySignedBy,
} from "../src/x509.js";

const NOW = fixtures.validAt;

function der(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const iaca = der(fixtures.iaca.der);
const documentSigner = der(fixtures.documentSigner.der);
const anchors = [iaca];

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

describe("parseCertificate", () => {
  it("reads the fields Annex B constrains", () => {
    const certificate = parseCertificate(documentSigner);

    expect(certificate.version).toBe(3);
    expect(certificate.subject.country).toBe("ES");
    expect(certificate.subject.commonName).toBe("Test Document Signer");
    expect(certificate.issuer.commonName).toBe("Test IACA");
    expect(certificate.extendedKeyUsage).toContain(OID_MDL_DOCUMENT_SIGNER);
    expect(certificate.basicConstraints?.ca).toBe(false);
  });

  it("reads the public key the certificate certifies", () => {
    // The load-bearing field: this is the key the credential's signature is
    // then checked against, so a parser that got it subtly wrong would reject
    // every genuine credential.
    const certificate = parseCertificate(documentSigner);

    expect(hex(certificate.publicKey.x)).toBe(fixtures.documentSigner.publicKey.x);
    expect(hex(certificate.publicKey.y)).toBe(fixtures.documentSigner.publicKey.y);
  });

  it("decodes validity as UTC seconds", () => {
    const certificate = parseCertificate(documentSigner);

    expect(new Date(certificate.notBefore * 1000).toISOString()).toBe("2026-01-01T00:00:00.000Z");
    expect(new Date(certificate.notAfter * 1000).toISOString()).toBe("2027-01-01T00:00:00.000Z");
  });

  it("reads a root's key usage bits", () => {
    // keyCertSign is bit 5 and cRLSign bit 6, counted from the most significant
    // bit of the first content octet — the direction it is easy to get exactly
    // backwards, and which would then accept a certificate with none of the
    // usages it needs.
    const root = parseCertificate(iaca);

    expect(root.keyUsage).toEqual([5, 6]);
    expect(root.basicConstraints).toEqual({ ca: true, pathLength: 0 });
  });

  it("refuses a truncated certificate", () => {
    expect(() => parseCertificate(documentSigner.subarray(0, 40))).toThrow(CertificateError);
  });

  it("refuses bytes that are not a certificate", () => {
    expect(() => parseCertificate(new Uint8Array([1, 2, 3, 4]))).toThrow(CertificateError);
  });
});

describe("verifySignedBy", () => {
  it("accepts a certificate its issuer actually signed", () => {
    expect(verifySignedBy(parseCertificate(documentSigner), parseCertificate(iaca))).toBe(true);
  });

  it("rejects one signed by somebody else", () => {
    expect(
      verifySignedBy(parseCertificate(documentSigner), parseCertificate(der(fixtures.strangerIaca.der))),
    ).toBe(false);
  });

  it("rejects a certificate whose TBS has been altered", () => {
    // The signature covers the TBS bytes verbatim. Flipping one byte inside
    // them has to break it, or the parser is not hashing what it thinks.
    const tampered = Uint8Array.from(documentSigner);
    tampered[60] ^= 0xff;

    let broken = false;
    try {
      broken = !verifySignedBy(parseCertificate(tampered), parseCertificate(iaca));
    } catch {
      broken = true; // a mangled field can fail parsing first, which is also a rejection
    }
    expect(broken).toBe(true);
  });
});

describe("validateDocumentSignerChain", () => {
  it("accepts a conformant chain and names the anchor that vouched", () => {
    const { leaf, anchor } = validateDocumentSignerChain(documentSigner, anchors, { now: NOW });

    expect(leaf.subject.commonName).toBe("Test Document Signer");
    expect(anchor.subject.commonName).toBe("Test IACA");
  });

  it("accepts anchors supplied as PEM", () => {
    // What an authority publishes and what fits in a config file.
    const { anchor } = validateDocumentSignerChain(documentSigner, pemToDer(fixtures.iaca.pem), {
      now: NOW,
    });

    expect(anchor.subject.commonName).toBe("Test IACA");
  });

  it("rejects a chain from a root the caller did not supply", () => {
    // The whole trust decision. A self-signed root and a certificate under it
    // are structurally indistinguishable from the real pair; what separates
    // them is the caller having chosen the anchor.
    expect(() =>
      validateDocumentSignerChain(der(fixtures.strangerSigner.der), anchors, { now: NOW }),
    ).toThrow(/no trust anchor/);
  });

  it("rejects when no anchors are supplied at all", () => {
    // An empty anchor list must never read as "nothing to check against, so
    // fine" — that is the failure mode that silently accepts everything.
    expect(() => validateDocumentSignerChain(documentSigner, [], { now: NOW })).toThrow(
      /no trust anchors/,
    );
  });

  it("rejects an expired document signer", () => {
    expect(() =>
      validateDocumentSignerChain(der(fixtures.expiredSigner.der), anchors, { now: NOW }),
    ).toThrow(/expired/);
  });

  it("rejects one not valid yet", () => {
    // Same fixture, read from before its own window.
    expect(() =>
      validateDocumentSignerChain(documentSigner, anchors, { now: 1_700_000_000 }),
    ).toThrow(/not valid yet/);
  });

  it(`rejects a validity window longer than ${MAX_DOCUMENT_SIGNER_DAYS} days`, () => {
    expect(() =>
      validateDocumentSignerChain(der(fixtures.tooLongSigner.der), anchors, { now: NOW }),
    ).toThrow(/more than 457 days/);
  });

  it("rejects one without the mDL extended key usage", () => {
    expect(() =>
      validateDocumentSignerChain(der(fixtures.noEkuSigner.der), anchors, { now: NOW }),
    ).toThrow(/extended key usage/);
  });

  it("rejects a document signer that is also a CA", () => {
    // 18013-5's PKI is two levels. A signer that could issue certificates would
    // be an intermediate, which Annex B does not have.
    expect(() =>
      validateDocumentSignerChain(der(fixtures.caSigner.der), anchors, { now: NOW }),
    ).toThrow(/is a CA/);
  });

  it("rejects key usage beyond digitalSignature", () => {
    expect(() =>
      validateDocumentSignerChain(der(fixtures.wrongKeyUsageSigner.der), anchors, { now: NOW }),
    ).toThrow(/key usage/);
  });

  it("rejects a country that disagrees with the root's", () => {
    // The rule that lets one national root certify a signer per region: the
    // country has to match, and only the state is allowed to differ.
    expect(() =>
      validateDocumentSignerChain(der(fixtures.wrongCountrySigner.der), anchors, { now: NOW }),
    ).toThrow(/country/);
  });

  it("rejects a chain whose root only claims the admitted name", () => {
    // The case the name match must never decide. This root's subject DER is
    // byte-identical to the admitted one — same country, same common name — so
    // it is found by the lookup, and only the signature check separates it from
    // the real thing. Anyone can mint a root calling itself Spain.
    expect(() =>
      validateDocumentSignerChain(der(fixtures.impostorSigner.der), anchors, { now: NOW }),
    ).toThrow(/no trust anchor signed this certificate/);
  });

  it("ignores anchors whose subject does not match, rather than failing on the first", () => {
    // A verifier holds a trust list, not one anchor. Trying them in order and
    // stopping at the first mismatch would make acceptance depend on how the
    // caller sorted their list.
    const { anchor } = validateDocumentSignerChain(
      documentSigner,
      [der(fixtures.strangerIaca.der), iaca],
      { now: NOW },
    );

    expect(anchor.subject.commonName).toBe("Test IACA");
  });
});
