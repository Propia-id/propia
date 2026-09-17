/**
 * An ISO-docType mDL, verified by the SDK through its certificate chain.
 *
 * The other mdoc suites all use a generated `io.sovra.<address>.…` docType,
 * which carries the issuer's address and is resolved on-chain. This one covers
 * the other route, which is the one a real mDL uses: the docType names nobody,
 * and the `x5chain` leaf is the only thing that says whose key signed it.
 *
 * ## Why the clock is pinned
 *
 * Annex B caps a document signer certificate at 457 days, so a committed
 * fixture checked against the real clock would start failing about a year after
 * it was generated — looking exactly like a regression, in a suite whose job is
 * to catch regressions. The certificates carry fixed windows and the test sets
 * the system time to `validAt`, which sits inside them. `mix
 * sovra.mdl_certificate_fixture` mints the whole set.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { buildDeviceResponse, parseIssuerSigned, type DeviceSigner } from "@sovrahq/holder-core/mdoc";
import { COSE_ALG } from "@sovrahq/holder-core/cose";
import { hexToBytes, sha256 } from "@sovrahq/holder-core/utils";
import { p256 } from "@noble/curves/p256";

import fixtures from "./fixtures/mdl-certificates.json";
import { verifyMdoc } from "../src/mdoc/verify-mdoc.js";
import { ErrorCode } from "../src/types.js";
import { pemToDer } from "../src/x509.js";

const mdl = fixtures.mdl;
const parsed = parseIssuerSigned(mdl.issuerSigned);
const holderPrivateKey = hexToBytes(mdl.holderPrivateKey);

function toDer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const handover = {
  clientId: "verifier:018f4a1c-0000-7000-8000-000000000001",
  nonce: "n-0S6_WzA2Mj",
  responseUri: "https://api.sovra.io/wallet/verifier/direct_post/abc",
};

const signer: DeviceSigner = {
  coseAlg: COSE_ALG.ES256,
  async signCose(toBeSigned) {
    const sig = p256.sign(sha256(toBeSigned), holderPrivateKey, { prehash: false });
    return { signature: sig.toBytes("compact"), unprotected: new Map() };
  },
};

// Offline, because what is under test is the certificate route — which needs no
// network at all. The chain reads have their own suite.
const base = {
  ...handover,
  offlineMode: true,
  l2RpcUrl: "http://unused",
  didRegistryAddress: "0x0000000000000000000000000000000000000001",
  issuerRegistryAddress: "0x0000000000000000000000000000000000000002",
};

const MANDATORY = [
  "birth_date",
  "document_number",
  "driving_privileges",
  "expiry_date",
  "family_name",
  "given_name",
  "issue_date",
  "issuing_authority",
  "issuing_country",
  "portrait",
  "un_distinguishing_sign",
];

async function present(disclose: string[] = [...MANDATORY, "age_over_18"]) {
  const disclosed = parsed.items.filter(
    (item) => item.namespace !== mdl.namespace || disclose.includes(item.elementIdentifier),
  );

  return buildDeviceResponse({ parsed, disclosed, handover, signer });
}

beforeAll(() => {
  vi.useFakeTimers();
  vi.setSystemTime(fixtures.validAt * 1000);
});

afterAll(() => {
  vi.useRealTimers();
});

describe("an mDL verified through its certificate chain", () => {
  it("verifies against the admitted root", async () => {
    const result = await verifyMdoc(await present(), {
      ...base,
      trustAnchors: [toDer(fixtures.iaca.der)],
    });

    expect(result.error).toBeUndefined();
    expect(result.valid).toBe(true);
    expect(result.docType).toBe("org.iso.18013.5.1.mDL");
    expect(result.credentialType).toBe("DrivingLicence");
  });

  it("names the authority that vouched, and the signer it vouched for", async () => {
    // A verifier holding a trust list needs to be able to say *which* authority
    // it accepted, not only that one of them was acceptable. Those two names
    // are the whole of what this route establishes about the issuer.
    const result = await verifyMdoc(await present(), {
      ...base,
      trustAnchors: pemToDer(fixtures.iaca.pem),
    });

    expect(result.issuingAuthority).toBe("Test IACA");
    expect(result.documentSigner?.country).toBe("ES");
    expect(result.documentSigner?.commonName).toBeDefined();
  });

  it("reports the address as asserted, never as the issuer", async () => {
    // The address is issuer-signed, so it survives transit — and that is all it
    // is worth here. Any workspace holding a document signer under an admitted
    // authority can write any address into its own meta namespace, and nothing
    // in an ISO certificate names a Sovra workspace, so there is nothing to
    // check it against. Reporting it as `issuer` would state as fact something
    // the chain never established.
    const result = await verifyMdoc(await present(), {
      ...base,
      trustAnchors: [toDer(fixtures.iaca.der)],
    });

    expect(result.issuer).toBeUndefined();
    expect(result.assertedIssuerAddress).toBe(mdl.issuerAddress);
  });

  it("returns the ISO elements, namespace-qualified", async () => {
    const result = await verifyMdoc(await present(), {
      ...base,
      trustAnchors: [toDer(fixtures.iaca.der)],
    });

    expect(result.claims?.["org.iso.18013.5.1.family_name"]).toBe("Lovelace");
    expect(result.claims?.["org.iso.18013.5.1.age_over_18"]).toBe(true);
    // The point of the `bytes` element type: a portrait reaches the verifier as
    // bytes, not as text that happens to look like base64.
    expect(result.claims?.["org.iso.18013.5.1.portrait"]).toBeInstanceOf(Uint8Array);
  });

  it("refuses to verify without trust anchors", async () => {
    // The failure that must never be silent. There is no default trust list and
    // an empty one is not one: which authorities to trust is the verifier's
    // decision, and it cannot be inferred from the thing being checked.
    const result = await verifyMdoc(await present(), base);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.ISSUER_NOT_TRUSTED);
    expect(result.error).toMatch(/trustAnchors/);
  });

  it("rejects an anchor that did not sign this chain", async () => {
    const result = await verifyMdoc(await present(), {
      ...base,
      trustAnchors: [toDer(fixtures.strangerIaca.der)],
    });

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.ISSUER_NOT_TRUSTED);
  });

  it("rejects the credential once its document signer has expired", async () => {
    // The check registration cannot make, because at registration the
    // certificate was current. Read from after the window instead of
    // substituting a chain: this is what a verifier sees a year later.
    vi.setSystemTime(new Date("2027-06-01T00:00:00Z"));

    const result = await verifyMdoc(await present(), {
      ...base,
      trustAnchors: [toDer(fixtures.iaca.der)],
    });

    vi.setSystemTime(fixtures.validAt * 1000);

    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe(ErrorCode.ISSUER_NOT_TRUSTED);
  });

  it("still enforces the mandatory element set", async () => {
    // The certificate route changes who signed and how they are found. It
    // changes nothing about what the holder is allowed to withhold.
    const result = await verifyMdoc(await present(MANDATORY.filter((e) => e !== "portrait")), {
      ...base,
      trustAnchors: [toDer(fixtures.iaca.der)],
    });

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/portrait/);
  });
});
