import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { bytesToHex, keccak256 } from "@sovrahq/holder-core/utils";
import { encodeResolveResult } from "@sovrahq/holder-core/test-fixtures";
import { discoverCredentialTypes } from "../src/discover";
import type { DiscoverOptions } from "../src/discover";

const RPC = "https://rpc.example";
const DID_REGISTRY = "0x00000000000000000000000000000000000000d1";
const ISSUER_REGISTRY = "0x00000000000000000000000000000000000000e1";
const BASE = "https://api.sovra.example";

const OPTIONS: DiscoverOptions = {
  l2RpcUrl: RPC,
  didRegistryAddress: DID_REGISTRY,
  issuerRegistryAddress: ISSUER_REGISTRY,
};

const utf8 = (s: string) => new TextEncoder().encode(s);
const selector = (sig: string) => bytesToHex(keccak256(utf8(sig)).slice(0, 4), false);
const typeHash = (vct: string) => bytesToHex(keccak256(utf8(vct)), false);

interface FakeIssuer {
  address: string;
  /** The OID4VCI service endpoint on-chain; omitted = no service. */
  endpoint?: string;
  deactivated?: boolean;
  /** Types the IssuerRegistry trusts this issuer for. */
  trusted: string[];
  /** What the metadata URL serves: a JSON body, or an HTTP status. */
  metadata?: unknown;
}

function sdJwtConfig(vct: string, claims: unknown[] = [], name = vct) {
  return {
    format: "vc+sd-jwt",
    credential_definition: { type: ["VerifiableCredential", vct] },
    credential_metadata: { display: [{ name, locale: "en-US" }], claims },
  };
}

function metadataFor(issuer: FakeIssuer, configs: Record<string, unknown>) {
  return {
    credential_issuer: `${BASE}/did:sovra:${issuer.address}`,
    credential_endpoint: `${BASE}/wallet/issuer/credential`,
    credential_configurations_supported: configs,
    display: [{ name: `Issuer ${issuer.address.slice(-2)}` }],
  };
}

function rpcResult(result: string) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
}

function rpcError(message: string) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: 3, message } }));
}

/** One fetch standing in for the three contracts and every issuer's server. */
function fakeNetwork(issuers: FakeIssuer[], opts: { listError?: string } = {}) {
  return vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === RPC) {
      const { params } = JSON.parse(String(init!.body));
      const { to, data } = params[0] as { to: string; data: string };
      const call = data.slice(2, 10);
      const args = data.slice(10);

      if (to === ISSUER_REGISTRY && call === selector("issuerList(uint256)")) {
        if (opts.listError) return rpcError(opts.listError);
        const issuer = issuers[parseInt(args, 16)];
        if (!issuer) return rpcError("execution reverted");
        return rpcResult(`0x${issuer.address.slice(2).padStart(64, "0")}`);
      }
      if (to === ISSUER_REGISTRY && call === selector("isTrusted(address,bytes32)")) {
        const address = `0x${args.slice(24, 64)}`;
        const issuer = issuers.find((i) => i.address === address)!;
        const trusted = issuer.trusted.some((vct) => typeHash(vct) === args.slice(64, 128));
        return rpcResult(`0x${(trusted ? "1" : "0").padStart(64, "0")}`);
      }
      if (to === DID_REGISTRY && call === selector("resolve(address)")) {
        const issuer = issuers.find((i) => i.address === `0x${args.slice(24, 64)}`)!;
        return rpcResult(
          encodeResolveResult({
            methods: [
              {
                id: keccak256(utf8("key-assert")),
                keyType: 0,
                pubKeyX: new Uint8Array(32).fill(1),
                pubKeyY: new Uint8Array(32).fill(2),
                relationships: 2,
              },
            ],
            services: issuer.endpoint
              ? [
                  {
                    id: keccak256(utf8("oid4vci")),
                    serviceType: keccak256(utf8("OpenID4VCIIssuer")),
                    endpoint: issuer.endpoint,
                  },
                ]
              : [],
            deactivated: issuer.deactivated ?? false,
          }),
        );
      }
      throw new Error(`unexpected eth_call to ${to}: ${data.slice(0, 10)}`);
    }

    const issuer = issuers.find(
      (i) => url === `${BASE}/did:sovra:${i.address}/.well-known/openid-credential-issuer`,
    );
    if (!issuer) return new Response("not found", { status: 404 });
    if (typeof issuer.metadata === "number") {
      return new Response("unavailable", { status: issuer.metadata });
    }
    return new Response(JSON.stringify(issuer.metadata));
  });
}

const ADDR_A = "0x00000000000000000000000000000000000000a1";
const ADDR_B = "0x00000000000000000000000000000000000000b2";

describe("discoverCredentialTypes", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function install(issuers: FakeIssuer[], opts?: { listError?: string }) {
    const fetchMock = fakeNetwork(issuers, opts);
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  }

  it("lists every trusted issuer's SD-JWT types, with their claims and display", async () => {
    const a: FakeIssuer = { address: ADDR_A, endpoint: BASE, trusted: ["NationalIdentityCard"] };
    a.metadata = metadataFor(a, {
      NationalIdentityCard: sdJwtConfig(
        "NationalIdentityCard",
        [
          { path: ["full_name"], mandatory: true, display: [{ name: "Full name", locale: "en-US" }] },
          { path: ["age_over_18"] },
        ],
        "National ID",
      ),
    });
    // A trailing slash on the registered endpoint must not double up.
    const b: FakeIssuer = { address: ADDR_B, endpoint: `${BASE}/`, trusted: ["UniversityDegree"] };
    b.metadata = metadataFor(b, {
      UniversityDegree: sdJwtConfig("UniversityDegree", [{ path: ["degree"] }]),
    });
    install([a, b]);

    const result = await discoverCredentialTypes(OPTIONS);

    expect(result.failures).toEqual([]);
    expect(result.credentialTypes).toEqual([
      {
        vct: "NationalIdentityCard",
        issuer: {
          did: `did:sovra:${ADDR_A}`,
          url: `${BASE}/did:sovra:${ADDR_A}`,
          display: [{ name: "Issuer a1" }],
        },
        display: [{ name: "National ID", locale: "en-US" }],
        claims: [
          { path: ["full_name"], mandatory: true, display: [{ name: "Full name", locale: "en-US" }] },
          { path: ["age_over_18"] },
        ],
      },
      {
        vct: "UniversityDegree",
        issuer: {
          did: `did:sovra:${ADDR_B}`,
          url: `${BASE}/did:sovra:${ADDR_B}`,
          display: [{ name: "Issuer b2" }],
        },
        display: [{ name: "UniversityDegree", locale: "en-US" }],
        claims: [{ path: ["degree"] }],
      },
    ]);
  });

  it("drops a type the registry does not trust the issuer for", async () => {
    const a: FakeIssuer = { address: ADDR_A, endpoint: BASE, trusted: ["NationalIdentityCard"] };
    a.metadata = metadataFor(a, {
      NationalIdentityCard: sdJwtConfig("NationalIdentityCard"),
      // Offered by the issuer, but never granted on-chain.
      MobileDrivingLicence: sdJwtConfig("MobileDrivingLicence"),
    });
    install([a]);

    const result = await discoverCredentialTypes(OPTIONS);

    expect(result.credentialTypes.map((t) => t.vct)).toEqual(["NationalIdentityCard"]);
  });

  it("ignores mdoc configurations and claims addressed by a nested path", async () => {
    const a: FakeIssuer = { address: ADDR_A, endpoint: BASE, trusted: ["NationalIdentityCard", "org.iso.18013.5.1.mDL"] };
    a.metadata = metadataFor(a, {
      NationalIdentityCard: sdJwtConfig("NationalIdentityCard", [
        { path: ["full_name"] },
        { path: ["address", "street"] },
        { path: [] },
      ]),
      mDL: {
        format: "mso_mdoc",
        doctype: "org.iso.18013.5.1.mDL",
        credential_metadata: { claims: [{ path: ["org.iso.18013.5.1", "family_name"] }] },
      },
    });
    install([a]);

    const result = await discoverCredentialTypes(OPTIONS);

    expect(result.credentialTypes).toHaveLength(1);
    expect(result.credentialTypes[0].claims).toEqual([{ path: ["full_name"] }]);
  });

  it("skips a deactivated issuer without reporting it", async () => {
    const a: FakeIssuer = { address: ADDR_A, endpoint: BASE, deactivated: true, trusted: ["NationalIdentityCard"] };
    a.metadata = metadataFor(a, { NationalIdentityCard: sdJwtConfig("NationalIdentityCard") });
    const fetchMock = install([a]);

    const result = await discoverCredentialTypes(OPTIONS);

    expect(result).toEqual({ credentialTypes: [], failures: [] });
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes(".well-known"))).toBe(false);
  });

  it("reports an unreachable issuer and still returns the others", async () => {
    const a: FakeIssuer = { address: ADDR_A, endpoint: BASE, trusted: ["NationalIdentityCard"], metadata: 503 };
    const b: FakeIssuer = { address: ADDR_B, endpoint: BASE, trusted: ["UniversityDegree"] };
    b.metadata = metadataFor(b, { UniversityDegree: sdJwtConfig("UniversityDegree") });
    install([a, b]);

    const result = await discoverCredentialTypes(OPTIONS);

    expect(result.credentialTypes.map((t) => t.vct)).toEqual(["UniversityDegree"]);
    expect(result.failures).toEqual([
      { issuer: `did:sovra:${ADDR_A}`, reason: "Issuer metadata returned HTTP 503" },
    ]);
  });

  it("reports an issuer whose DID publishes no OpenID4VCI service", async () => {
    install([{ address: ADDR_A, trusted: ["NationalIdentityCard"] }]);

    const result = await discoverCredentialTypes(OPTIONS);

    expect(result.failures).toEqual([
      { issuer: `did:sovra:${ADDR_A}`, reason: "DID publishes no OpenID4VCIIssuer service" },
    ]);
  });

  it("rejects metadata that names a different credential issuer", async () => {
    const a: FakeIssuer = { address: ADDR_A, endpoint: BASE, trusted: ["NationalIdentityCard"] };
    a.metadata = {
      ...metadataFor(a, { NationalIdentityCard: sdJwtConfig("NationalIdentityCard") }),
      credential_issuer: `${BASE}/did:sovra:${ADDR_B}`,
    };
    install([a]);

    const result = await discoverCredentialTypes(OPTIONS);

    expect(result.credentialTypes).toEqual([]);
    expect(result.failures[0].reason).toMatch(/names credential issuer/);
  });

  it("returns nothing for an empty issuer list", async () => {
    install([]);

    expect(await discoverCredentialTypes(OPTIONS)).toEqual({ credentialTypes: [], failures: [] });
  });

  it("propagates an RPC error that is not the end of the list", async () => {
    install([], { listError: "rate limit exceeded" });

    await expect(discoverCredentialTypes(OPTIONS)).rejects.toThrow("rate limit exceeded");
  });
});
