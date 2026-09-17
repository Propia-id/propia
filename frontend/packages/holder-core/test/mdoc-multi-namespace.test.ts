/**
 * A credential carrying more than one namespace, which is what a real mDL is.
 *
 * ISO pairs `org.iso.18013.5.1` with whatever a jurisdiction adds beside it —
 * AAMVA's `org.iso.18013.5.1.aamva`, say — and element identifiers are only
 * unique *within* a namespace. So the two can both carry `document_number`,
 * meaning different things.
 *
 * Everything in the wallet keys off `claimKey`, which `claimKeyFor` leaves
 * unqualified for the credential's own namespace and qualifies for any other.
 * A DCQL path is `[namespace, element_identifier]`, so turning one into a
 * `claimKey` is a lookup, never a matter of taking the last segment.
 */

import { describe, expect, it } from "vitest";

import { PresentationProtocol } from "../src/protocols/index";
import type { StoredMdocCredential } from "../src/state/index";

const ISO = "org.iso.18013.5.1";
const AAMVA = "org.iso.18013.5.1.aamva";

/**
 * An mDL with a domestic namespace beside the ISO one, both carrying
 * `document_number` — which is the collision the namespacing exists for.
 */
const credential: StoredMdocCredential = {
  id: "mdl-1",
  format: "mso_mdoc",
  issuerDid: "did:sovra:0xab34cd09f900112233445566778899aabbccddee",
  credentialType: "org.iso.18013.5.1.mDL",
  docType: "org.iso.18013.5.1.mDL",
  issuerName: "Test Issuer",
  issuedAt: 0,
  expiresAt: 0,
  issuerSigned: "",
  claims: {
    family_name: "Lovelace",
    document_number: "D-1234567",
    [`${AAMVA}.document_number`]: "AAMVA-9999",
  },
  elements: [
    {
      namespace: ISO,
      elementIdentifier: "family_name",
      claimKey: "family_name",
      mandatory: true,
    },
    {
      namespace: ISO,
      elementIdentifier: "document_number",
      claimKey: "document_number",
      mandatory: true,
    },
    {
      namespace: AAMVA,
      elementIdentifier: "document_number",
      claimKey: `${AAMVA}.document_number`,
      mandatory: false,
    },
  ],
};

const protocol = new PresentationProtocol(
  null as never,
  null as never,
  null as never,
  null as never,
);

function query(paths: string[][]) {
  return {
    credentials: [
      {
        id: "mdl",
        format: "mso_mdoc" as const,
        meta: { doctype_value: "org.iso.18013.5.1.mDL" },
        claims: paths.map((path) => ({ path })),
      },
    ],
  };
}

function resolve(paths: string[][]) {
  const match = protocol.findMatchingCredentials(query(paths), [credential]);
  if (!match) throw new Error("no match");
  return match.requestedClaims;
}

describe("resolving a claim path against a multi-namespace credential", () => {
  it("keys a foreign namespace's element by its qualified claim key", () => {
    // The bug this pins: taking the last path segment gives the bare
    // `document_number`, which is not a key `claims` holds — so the claim
    // disappears from the approval screen and is never disclosed.
    const [claim] = resolve([[AAMVA, "document_number"]]);

    expect(claim?.key).toBe(`${AAMVA}.document_number`);
    expect(Object.keys(credential.claims)).toContain(claim?.key);
  });

  it("keys the credential's own namespace unqualified", () => {
    const [claim] = resolve([[ISO, "document_number"]]);

    expect(claim?.key).toBe("document_number");
  });

  it("tells the two document_numbers apart", () => {
    // Same element identifier, different namespaces, different values. A
    // verifier asking for one must not be handed the other.
    const [iso, aamva] = resolve([
      [ISO, "document_number"],
      [AAMVA, "document_number"],
    ]);

    expect(iso?.key).not.toBe(aamva?.key);
    expect(credential.claims[iso!.key]).toBe("D-1234567");
    expect(credential.claims[aamva!.key]).toBe("AAMVA-9999");
  });

  it("reads mandatory from the element the path names, not from a namesake", () => {
    // The ISO `document_number` is mandatory and the AAMVA one is not. Matching
    // on the bare identifier would make the domestic element inherit the ISO
    // element's mandatory flag, and the holder would be told they cannot
    // withhold something they can.
    const [aamva] = resolve([[AAMVA, "document_number"]]);
    const [iso] = resolve([[ISO, "document_number"]]);

    expect(aamva?.mandatory).toBe(false);
    expect(iso?.mandatory).toBe(true);
  });

  it("keeps the full path for the response, whatever the key is", () => {
    // The key is the wallet's internal handle; the path is what the verifier
    // asked with, and what the mdoc response has to be keyed by.
    const [claim] = resolve([[AAMVA, "document_number"]]);

    expect(claim?.path).toEqual([AAMVA, "document_number"]);
    expect(claim?.id).toBe(`${AAMVA}/document_number`);
  });

  it("falls back to the last segment when the credential has no such element", () => {
    // A verifier may ask for something this credential does not carry.
    // `buildApprovalData` then finds no matching claim and drops it, which is
    // the right outcome — but resolving must not throw on the way there.
    const [claim] = resolve([[ISO, "nonexistent_element"]]);

    expect(claim?.key).toBe("nonexistent_element");
    expect(claim?.mandatory).toBe(false);
  });
});
