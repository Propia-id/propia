/**
 * Discover what a verifier can ask for: every SD-JWT credential type a trusted
 * issuer offers, with the claims the issuer describes for it.
 *
 * The chain lists the issuers and what each is trusted for, but only as
 * `keccak256(vct)` hashes — no names and no claims. Those live in each
 * issuer's OID4VCI metadata, which the issuer's DID document points at. So:
 *
 *   IssuerRegistry.issuerList → DIDRegistry.resolve → OpenID4VCIIssuer service
 *   → issuer metadata → keep the types IssuerRegistry.isTrusted confirms
 *
 * What this returns only shapes a request. Verifying the answer never reads it:
 * `verify()` checks the issuer against the chain on its own.
 */

import type {
  ClaimDescription,
  CredentialDisplay,
  IssuerMetadata,
} from "@sovrahq/holder-core";
import { hexToBytes, keccak256, bytesToHex } from "@sovrahq/holder-core/utils";
import {
  ethCall,
  RpcError,
  encodeAddress,
  encodeFunctionCall,
  decodeResolveResult,
} from "./rpc.js";
import { isIssuerTrusted } from "./resolve-issuer.js";

export interface DiscoverOptions {
  /** Endpoint for the DID and issuer registries. */
  l2RpcUrl: string;
  didRegistryAddress: string;
  issuerRegistryAddress: string;
  /** Upper bound on the issuer list entries read. Defaults to 256. */
  maxIssuers?: number;
}

export interface DiscoveredCredentialType {
  /** The SD-JWT `vct`: what a request's `vct_values` must carry. */
  vct: string;
  issuer: {
    did: string;
    /** The Credential Issuer Identifier the metadata was fetched from. */
    url: string;
    /** The issuer's own `display` entries, one per locale. */
    display?: CredentialDisplay[];
  };
  /** The configuration's `display` entries, one per locale. */
  display?: CredentialDisplay[];
  /**
   * The claims the issuer describes, single-segment paths only: SD-JWT claims
   * are flat, and a request names each by key.
   */
  claims: ClaimDescription[];
}

export interface DiscoveryFailure {
  /** The issuer's DID. */
  issuer: string;
  reason: string;
}

export interface DiscoveryResult {
  credentialTypes: DiscoveredCredentialType[];
  /**
   * Trusted issuers whose offer could not be read: an unreachable server, a
   * DID with no OID4VCI service, metadata that does not match the DID. One
   * issuer being down leaves the others discoverable.
   */
  failures: DiscoveryFailure[];
}

const DEFAULT_MAX_ISSUERS = 256;
const METADATA_TIMEOUT_MS = 10_000;
const OID4VCI_SERVICE_TYPE = bytesToHex(
  keccak256(new TextEncoder().encode("OpenID4VCIIssuer")),
);
/** The format `buildPresentationRequestUri` asks for; nothing else is answerable by QR. */
const SD_JWT_FORMAT = "vc+sd-jwt";

export async function discoverCredentialTypes(
  options: DiscoverOptions,
): Promise<DiscoveryResult> {
  const issuers = await listIssuers(
    options.l2RpcUrl,
    options.issuerRegistryAddress,
    options.maxIssuers ?? DEFAULT_MAX_ISSUERS,
  );

  const outcomes = await Promise.all(
    issuers.map(async (address) => {
      const did = `did:sovra:${address}`;
      try {
        return { types: await discoverIssuer(options, address, did) };
      } catch (e) {
        return { failure: { issuer: did, reason: e instanceof Error ? e.message : String(e) } };
      }
    }),
  );

  return {
    credentialTypes: outcomes.flatMap((o) => o.types ?? []),
    failures: outcomes.flatMap((o) => (o.failure ? [o.failure] : [])),
  };
}

/**
 * Walk `issuerList(i)` until it reverts. The registry exposes no length, so
 * the revert past the last entry is the end marker. Any other RPC error
 * propagates: a list cut short by a rate limit would look like a complete one.
 */
async function listIssuers(
  rpcUrl: string,
  issuerRegistryAddress: string,
  max: number,
): Promise<string[]> {
  const issuers: string[] = [];
  for (let i = 0; i < max; i++) {
    const index = hexToBytes(i.toString(16).padStart(64, "0"));
    let result: string;
    try {
      result = await ethCall(
        rpcUrl,
        issuerRegistryAddress,
        encodeFunctionCall("issuerList(uint256)", [index]),
      );
    } catch (e) {
      if (e instanceof RpcError && /revert/i.test(e.message)) break;
      throw e;
    }
    if (result.length < 66) break;
    // Lowercase, as the backend spells the workspace DID it serves metadata under.
    issuers.push(`0x${result.slice(-40).toLowerCase()}`);
  }
  return issuers;
}

async function discoverIssuer(
  options: DiscoverOptions,
  address: string,
  did: string,
): Promise<DiscoveredCredentialType[]> {
  const document = decodeResolveResult(
    await ethCall(
      options.l2RpcUrl,
      options.didRegistryAddress,
      encodeFunctionCall("resolve(address)", [encodeAddress(address)]),
    ),
  );
  if (document.deactivated) return [];

  const service = document.services.find(
    (s) => bytesToHex(s.serviceType) === OID4VCI_SERVICE_TYPE,
  );
  if (!service) throw new Error("DID publishes no OpenID4VCIIssuer service");

  // The Sovra backend registers its bare base URL as this endpoint and serves
  // each workspace's metadata one path segment below it, under the workspace
  // DID. So the Credential Issuer Identifier is rebuilt here rather than read.
  // An issuer hosted any other way is not found; registering the full
  // identifier on-chain would let this read the endpoint as-is.
  const url = `${service.endpoint.replace(/\/+$/, "")}/${did}`;
  const metadata = await fetchMetadata(url);

  // OID4VCI 1.0 §12.2.2: the metadata must name the identifier it was fetched
  // for. Here that also ties it to the DID, which is part of the URL.
  if (metadata.credential_issuer !== url) {
    throw new Error(
      `Metadata names credential issuer ${metadata.credential_issuer}, expected ${url}`,
    );
  }

  const candidates = Object.values(metadata.credential_configurations_supported ?? {})
    .filter((config) => config.format === SD_JWT_FORMAT)
    .flatMap((config) => {
      const types = (config.credential_definition?.type ?? []).filter(
        (t) => t !== "VerifiableCredential",
      );
      return types.length === 1 ? [{ vct: types[0], meta: config.credential_metadata }] : [];
    });

  const trusted = await Promise.all(
    candidates.map((c) =>
      isIssuerTrusted(options.l2RpcUrl, options.issuerRegistryAddress, address, c.vct),
    ),
  );

  return candidates
    .filter((_, i) => trusted[i])
    .map(({ vct, meta }) => ({
      vct,
      issuer: { did, url, ...(metadata.display && { display: metadata.display }) },
      ...(meta?.display && { display: meta.display }),
      claims: (meta?.claims ?? []).filter(
        (c) => c.path?.length === 1 && typeof c.path[0] === "string" && c.path[0] !== "",
      ),
    }));
}

async function fetchMetadata(url: string): Promise<IssuerMetadata> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), METADATA_TIMEOUT_MS);
  try {
    const res = await fetch(`${url}/.well-known/openid-credential-issuer`, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`Issuer metadata returned HTTP ${res.status}`);
    return (await res.json()) as IssuerMetadata;
  } finally {
    clearTimeout(timer);
  }
}
