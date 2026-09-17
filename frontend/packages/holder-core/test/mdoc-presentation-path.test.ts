import { describe, expect, it } from "vitest";
import fixture from "./fixtures/mdoc-issuer-signed.json";
import { CredentialManager } from "../src/credentials/index";
import { createCredentialStore } from "../src/state/index";
import { PresentationProtocol, type VPRequest } from "../src/protocols/index";
import { COSE_ALG } from "../src/cose/index";
import { SOVRA_META_NAMESPACE } from "../src/mdoc/index";
import { decode, unwrapEmbedded, type CborMap, type CborValue } from "../src/cbor/index";
import { base64urlDecode, hexToBytes, sha256 } from "../src/utils/index";
import { memoryStorage } from "./fixtures";
import { p256 } from "@noble/curves/p256";

/**
 * Exercises the path the wallet actually takes: store the credential, then
 * present it through `PresentationProtocol`.
 *
 * This exists because the round-trip tests did not go through it. Both of them
 * — the TypeScript one and the backend's wallet simulator — chose which items
 * to disclose themselves, and both happened to keep the Sovra meta namespace.
 * The real path selects through `CredentialManager.selectMdocElements`, whose
 * `elements` list deliberately excludes that namespace, so it was silently
 * dropped from every presentation the wallet built. Verification would have
 * failed for every mdoc, and no test said so.
 */

const holderPrivateKey = hexToBytes(fixture.holderPrivateKey);

const signer = {
  alg: "WebAuthn",
  coseAlg: COSE_ALG.ES256,
  async sign(hash: Uint8Array) {
    const sig = p256.sign(hash, holderPrivateKey, { prehash: false });
    return {
      kind: "es256" as const,
      r: `0x${Buffer.from(sig.toBytes("compact").subarray(0, 32)).toString("hex")}`,
      s: `0x${Buffer.from(sig.toBytes("compact").subarray(32)).toString("hex")}`,
    };
  },
};

const request: VPRequest = {
  clientId: "verifier:018f4a1c-0000-7000-8000-000000000001",
  nonce: "n-0S6_WzA2Mj",
  responseUri: "https://api.sovra.io/wallet/verifier/direct_post/abc",
  responseMode: "direct_post",
  dcqlQuery: { credentials: [] },
};

async function presentThroughWallet(approvedClaims: string[]) {
  const { storage } = memoryStorage();
  const store = createCredentialStore();
  const manager = new CredentialManager(storage, store);
  manager.setActiveWallet("0xwallet");

  const credential = await manager.storeMdocCredential(fixture.issuerSigned, {
    issuerDid: `did:sovra:${fixture.issuerAddress}`,
    issuerName: "Test Issuer",
  });

  const protocol = new PresentationProtocol(null as never, manager, signer, () => ({
    did: fixture.holderDid,
    passkeyCredentialId: "cred-id",
    passkeyPublicKey: new Uint8Array(65),
  }));

  const vp = await protocol.executePresentation(request, credential, approvedClaims);
  return { credential, response: decode(base64urlDecode(vp)) as CborMap };
}

function namespacesOf(response: CborMap): CborMap {
  const documents = response.get("documents") as CborValue[];
  const document = documents[0] as CborMap;
  return (document.get("issuerSigned") as CborMap).get("nameSpaces") as CborMap;
}

function elementIdsIn(nameSpaces: CborMap, namespace: string): string[] {
  const items = (nameSpaces.get(namespace) ?? []) as CborValue[];
  return items
    .map((tagged) => decode(unwrapEmbedded(tagged)!) as CborMap)
    .map((item) => String(item.get("elementIdentifier")))
    .sort();
}

describe("presenting through the wallet's own path", () => {
  it("always includes the Sovra meta namespace", async () => {
    // Not the holder's to withhold: the verifier requires it whole, and it
    // carries the holder DID, the issuer's address, the revocation index and
    // the mandatory set.
    const { response } = await presentThroughWallet(["member_name"]);
    const nameSpaces = namespacesOf(response);

    expect(elementIdsIn(nameSpaces, SOVRA_META_NAMESPACE).sort()).toEqual([
      "credential_type",
      "holder_did",
      "issuer_address",
      "mandatory_elements",
      "namespace",
      "status_list_index",
    ]);
  });

  it("discloses the approved element plus the mandatory one", async () => {
    const { response } = await presentThroughWallet(["member_name"]);

    expect(elementIdsIn(namespacesOf(response), fixture.docType)).toEqual([
      "member_name",
      "tier", // disclosable: false — unioned in by the manager
    ]);
  });

  it("withholds an element the verifier did not ask for", async () => {
    const { response } = await presentThroughWallet(["member_name"]);

    expect(elementIdsIn(namespacesOf(response), fixture.docType)).not.toContain("visits");
  });

  it("records the mandatory element on the stored credential", async () => {
    const { credential } = await presentThroughWallet(["member_name"]);

    const tier = credential.elements.find((e) => e.elementIdentifier === "tier");
    expect(tier?.mandatory).toBe(true);

    const memberName = credential.elements.find((e) => e.elementIdentifier === "member_name");
    expect(memberName?.mandatory).toBe(false);
  });

  it("does not expose the meta namespace as a selectable element", async () => {
    // It has no user data to decide about, so it must not appear on the
    // approval screen — which is why it has to be added back at presentation.
    const { credential } = await presentThroughWallet(["member_name"]);

    expect(credential.elements.some((e) => e.namespace === SOVRA_META_NAMESPACE)).toBe(false);
  });

  it("refuses a request with no response address", async () => {
    await expect(
      presentThroughWalletWithout(["member_name"], "responseUri"),
    ).rejects.toThrow(/response address/);
  });
});

async function presentThroughWalletWithout(approvedClaims: string[], drop: keyof VPRequest) {
  const { storage } = memoryStorage();
  const store = createCredentialStore();
  const manager = new CredentialManager(storage, store);
  manager.setActiveWallet("0xwallet");

  const credential = await manager.storeMdocCredential(fixture.issuerSigned, {
    issuerDid: `did:sovra:${fixture.issuerAddress}`,
    issuerName: "Test Issuer",
  });

  const protocol = new PresentationProtocol(null as never, manager, signer, () => ({
    did: fixture.holderDid,
    passkeyCredentialId: "cred-id",
    passkeyPublicKey: new Uint8Array(65),
  }));

  const stripped = { ...request };
  delete stripped[drop];

  return protocol.executePresentation(stripped, credential, approvedClaims);
}

export { sha256 };
