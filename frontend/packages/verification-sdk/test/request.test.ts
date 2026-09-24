/**
 * Contract test: the request a verifier builds with this SDK — the standalone
 * verifier app and the wallet's own verify flow alike — parsed by the code the
 * wallet actually runs.
 *
 * `buildPresentationRequestUri` and `PresentationProtocol` live in separate
 * packages with no shared schema, so nothing but a test like this keeps them
 * agreeing. The last two cases pin the failure modes that make a demo dead-end
 * silently — an unmatched credential type, and requested claims that exist on no
 * credential (which disables the wallet's own Approve button).
 */

import { describe, it, expect } from "vitest";
import {
  PresentationProtocol,
  type StoredSdJwtCredential,
} from "@sovrahq/holder-core";
import { mdocCredential, sdJwtCredential } from "@sovrahq/holder-core/test-fixtures";
import { buildPresentationRequestUri } from "../src/request";

/**
 * `findMatchingCredential` and `buildApprovalData` are pure methods that touch
 * none of the constructor's collaborators, and `resolveRequest` reaches for
 * one only to fetch a request object by reference — which the unsigned URIs
 * built here never carry.
 */
const wallet = new PresentationProtocol(
  null as never,
  null as never,
  null as never,
  null as never,
);

const VERIFIER_DID = "did:sovra:0x00000000000000000000000000000000000000a1";
const VCT = "NationalIdCredential";

// No `as StoredCredential` here. Against a union that is a widening assertion
// TypeScript permits, so it keeps compiling while producing a credential with
// no `format` — hiding exactly the breakage the union exists to surface.
function credential(
  overrides: Partial<StoredSdJwtCredential> = {},
): StoredSdJwtCredential {
  return sdJwtCredential({
    id: "cred-1",
    credentialType: VCT,
    claims: {
      given_name: "Maria",
      family_name: "Rossi",
      birth_date: "1990-07-15",
      document_number: "AB1234567",
      vct: VCT,
      iss: "did:sovra:0x00000000000000000000000000000000000000b2",
    },
    ...overrides,
  });
}

function buildUri(claims: string[], credentialType = VCT) {
  return buildPresentationRequestUri({
    clientId: VERIFIER_DID,
    clientName: "Roadside Inspection Unit",
    nonce: "nonce-abc123",
    queryId: "check-1",
    credentialType,
    claims,
  });
}

describe("OpenID4VP request → wallet parser", () => {
  it("is recognised as a presentation request", async () => {
    expect(wallet.isPresentationRequest(buildUri(["birth_date"]))).toBe(true);
  });

  it("round-trips client_id, nonce and the DCQL query", async () => {
    const request = await wallet.resolveRequest(buildUri(["given_name", "birth_date"]));

    expect(request.clientId).toBe(VERIFIER_DID);
    expect(request.nonce).toBe("nonce-abc123");
    expect(request.dcqlQuery.credentials).toHaveLength(1);
    expect(request.dcqlQuery.credentials[0].meta?.vct_values).toEqual([VCT]);
    expect(request.dcqlQuery.credentials[0].claims?.map((c) => c.path)).toEqual([
      ["given_name"],
      ["birth_date"],
    ]);
  });

  it("omits response_uri and response_mode, so the wallet answers by QR", async () => {
    const request = await wallet.resolveRequest(buildUri(["birth_date"]));

    // executeDirectPost throws without both; their absence is what routes the
    // wallet to its response-QR screen instead.
    expect(request.responseUri).toBeUndefined();
    expect(request.responseMode).toBeUndefined();
  });

  it("survives a nonce containing URL-significant characters", async () => {
    const uri = buildPresentationRequestUri({
      clientId: VERIFIER_DID,
      clientName: "Ministry of Transport & Border Control / Unit #3",
      nonce: "n=1&x",
      queryId: "check-1",
      credentialType: VCT,
      claims: ["birth_date"],
    });
    const request = await wallet.resolveRequest(uri);

    expect(request.nonce).toBe("n=1&x");
  });

  /**
   * This verifier cannot sign its requests: its DID is minted locally with no
   * key registered anywhere, so a wallet has nothing to check a signature
   * against. The wallet still answers the request, but it drops the name and
   * flags the verifier as unauthenticated — otherwise `client_name` would be a
   * free-text field any QR could use to impersonate a government counter.
   */
  it("is unverified, and its client_name never reaches the consent screen", async () => {
    const request = await wallet.resolveRequest(buildUri(["given_name"]));

    expect(request.verified).toBe(false);
    expect(request.verifierName).toBeUndefined();

    const match = wallet.findMatchingCredential(request.dcqlQuery, [credential()]);
    const approval = wallet.buildApprovalData(
      request,
      match!.credential,
      match!.requestedClaims,
    );

    expect(approval.verified).toBe(false);
    expect(approval.verifierName).toBeUndefined();
    // The DID is on the request for correlation, but the consent screen is
    // given no name at all rather than one this device asserted for itself.
    expect(request.clientId).toBe(VERIFIER_DID);
  });

  it("returns every held credential the query accepts, in wallet order", async () => {
    const request = await wallet.resolveRequest(buildUri(["given_name"]));
    const older = credential({ id: "cred-1", claims: { given_name: "Maria", vct: VCT } });
    const newer = credential({ id: "cred-2", claims: { given_name: "Maria", vct: VCT } });
    const other = credential({ id: "cred-3", credentialType: "MembershipCredential" });

    const match = wallet.findMatchingCredentials(request.dcqlQuery, [older, other, newer]);

    expect(match!.credentials.map((c) => c.id)).toEqual(["cred-1", "cred-2"]);
  });

  it("keeps the singular helper returning the first of those", async () => {
    const request = await wallet.resolveRequest(buildUri(["given_name"]));
    const a = credential({ id: "cred-1" });
    const b = credential({ id: "cred-2" });

    expect(wallet.findMatchingCredential(request.dcqlQuery, [a, b])!.credential.id).toBe("cred-1");
    expect(wallet.findMatchingCredentials(request.dcqlQuery, [])).toBeNull();
  });

  it("carries the alternatives and the request's claims into the approval data", async () => {
    const request = await wallet.resolveRequest(buildUri(["given_name", "birth_date"]));
    const a = credential({ id: "cred-1" });
    const b = credential({ id: "cred-2" });
    const match = wallet.findMatchingCredentials(request.dcqlQuery, [a, b])!;

    const approval = wallet.buildApprovalData(
      request,
      match.credentials[0],
      match.requestedClaims,
      match.credentials,
    );

    expect(approval.matches.map((c) => c.id)).toEqual(["cred-1", "cred-2"]);
    expect(approval.requestedClaims.map((c) => c.key)).toEqual([
      "given_name",
      "birth_date",
    ]);
  });

  it("defaults matches to the single credential when no choice was offered", async () => {
    const request = await wallet.resolveRequest(buildUri(["given_name"]));
    const only = credential({ id: "cred-1" });
    const match = wallet.findMatchingCredential(request.dcqlQuery, [only])!;
    const approval = wallet.buildApprovalData(request, only, match.requestedClaims);

    expect(approval.matches).toEqual([only]);
  });

  it("re-deriving for a different credential changes what is shared", async () => {
    const request = await wallet.resolveRequest(buildUri(["given_name", "birth_date"]));
    const full = credential({ id: "cred-1" });
    const partial = credential({
      id: "cred-2",
      claims: { given_name: "Maria", vct: VCT },
    });
    const match = wallet.findMatchingCredentials(request.dcqlQuery, [full, partial])!;

    const first = wallet.buildApprovalData(request, match.credentials[0], match.requestedClaims, match.credentials);
    const second = wallet.buildApprovalData(request, match.credentials[1], match.requestedClaims, match.credentials);

    expect(first.sharedClaims.map((c) => c.key)).toEqual(["given_name", "birth_date"]);
    expect(second.sharedClaims.map((c) => c.key)).toEqual(["given_name"]);
  });

  it("matches a held credential and yields shareable claims", async () => {
    const request = await wallet.resolveRequest(buildUri(["given_name", "birth_date"]));
    const match = wallet.findMatchingCredential(request.dcqlQuery, [credential()]);

    expect(match).not.toBeNull();
    const approval = wallet.buildApprovalData(
      request,
      match!.credential,
      match!.requestedClaims,
    );

    // Non-empty sharedClaims is the wallet's precondition for enabling Approve.
    // These are ClaimRefs rather than bare names, because an mdoc claim is a
    // [namespace, element] path — comparing on `key` keeps this assertion about
    // what is shared rather than about the shape carrying it.
    expect(approval.sharedClaims.map((c) => c.key)).toEqual(["given_name", "birth_date"]);

    const withheld = approval.withheldClaims.map((c) => c.key);
    expect(withheld).toContain("family_name");
    expect(withheld).toContain("document_number");
  });

  it("does not match a credential of a different format", async () => {
    // Without a format check an mdoc would satisfy a vc+sd-jwt query and the
    // presentation would fail much later, in signature verification, with
    // nothing pointing back here.
    const request = await wallet.resolveRequest(buildUri(["given_name"]));
    const mdoc = mdocCredential({ credentialType: VCT });

    expect(wallet.findMatchingCredential(request.dcqlQuery, [mdoc])).toBeNull();
  });

  it("finds no credential when the credential type does not match", async () => {
    const request = await wallet.resolveRequest(buildUri(["birth_date"], "DrivingLicenceCredential"));

    expect(wallet.findMatchingCredential(request.dcqlQuery, [credential()])).toBeNull();
  });

  it("matches but shares nothing when no requested claim exists on the credential", async () => {
    const request = await wallet.resolveRequest(buildUri(["licence_class", "expiry_date"]));
    const match = wallet.findMatchingCredential(request.dcqlQuery, [credential()]);

    expect(match).not.toBeNull();
    const approval = wallet.buildApprovalData(
      request,
      match!.credential,
      match!.requestedClaims,
    );

    // The wallet reaches its approval screen and then cannot proceed. This is the
    // dead end the check editor's hints exist to prevent.
    expect(approval.sharedClaims).toEqual([]);
  });
});
