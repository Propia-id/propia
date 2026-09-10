import {
  decodeResolveResult,
  encodeAddress,
  encodeFunctionCall,
  bytesToHex,
  keccak256,
} from "../utils/index.js";

/** A P-256 verification method resolved from a DID document. */
export interface ResolvedKey {
  x: Uint8Array;
  y: Uint8Array;
}

/** `eth_call` seam, so the resolver stays independent of the RPC transport. */
export type EthCall = (to: string, calldata: string) => Promise<string>;

export class DidResolutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DidResolutionError";
  }
}

// SovraDIDRegistry keyType enum: 0 = P256.
const KEY_TYPE_P256 = 0;

// SovraDIDRegistry relationships bitmask: bit1 = assertionMethod. This is the
// relationship workspace keys are registered under, and the one a signature
// over a document (a credential, or an authorization request) is made in.
const RELATIONSHIP_ASSERTION = 0x02;

const DID_SOVRA_PREFIX = "did:sovra:";

// resolve() head: two array offsets, created, updated, versionId, deactivated.
const RESOLVE_HEAD_WORDS = 6;

/**
 * Split a `did:sovra` DID URL into its DID and fragment: the `kid` of a signed
 * request names the verification method that signed it.
 */
export function parseDidUrl(didUrl: string): { did: string; fragment?: string } {
  const hash = didUrl.indexOf("#");
  if (hash === -1) return { did: didUrl };
  return { did: didUrl.slice(0, hash), fragment: didUrl.slice(hash + 1) };
}

/** The 20-byte identity address a `did:sovra` DID points at. */
export function didSovraAddress(did: string): string {
  if (!did.startsWith(DID_SOVRA_PREFIX)) {
    throw new DidResolutionError(`Unsupported DID method: ${did}`);
  }

  const address = did.slice(DID_SOVRA_PREFIX.length);
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new DidResolutionError(`Malformed did:sovra identifier: ${did}`);
  }
  return address;
}

/**
 * Resolve the P-256 assertion key a `did:sovra` DID publishes, reading the
 * on-chain DID Registry directly.
 *
 * Chain is the trust anchor on purpose: the DID and the key come from the
 * registry, not from whatever handed us the DID, so a forged QR cannot supply
 * its own key material along with its own identifier.
 *
 * `fragment` names the verification method to use — the fragment of the signer's
 * `kid`. The registry stores method ids as `keccak256(fragment)`, so the match
 * is exact rather than positional.
 */
export async function resolveAssertionKey(
  ethCall: EthCall,
  registryAddress: string,
  did: string,
  fragment: string,
): Promise<ResolvedKey> {
  const identity = didSovraAddress(did);

  const calldata = bytesToHex(
    encodeFunctionCall("resolve(address)", [encodeAddress(identity)]),
  );

  let result: string;
  try {
    result = await ethCall(registryAddress, calldata);
  } catch (e) {
    throw new DidResolutionError(
      `DID Registry unreachable for ${did}: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
  }

  // `resolve()` returns a six-word head before any dynamic data. Anything
  // shorter is not a document, and decoding it read past the end.
  if (!result || result.length < 2 + RESOLVE_HEAD_WORDS * 64) {
    throw new DidResolutionError(`DID not registered: ${did}`);
  }

  let document;
  try {
    document = decodeResolveResult(result);
  } catch (e) {
    throw new DidResolutionError(
      `DID Registry returned an undecodable document for ${did}: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
  }

  if (document.deactivated) {
    throw new DidResolutionError(`DID deactivated: ${did}`);
  }

  const wanted = bytesToHex(keccak256(new TextEncoder().encode(fragment)));

  const method = document.methods.find(
    (m) =>
      bytesToHex(m.id) === wanted &&
      m.keyType === KEY_TYPE_P256 &&
      (m.relationships & RELATIONSHIP_ASSERTION) !== 0,
  );

  if (!method) {
    throw new DidResolutionError(
      `DID ${did} publishes no P-256 assertion key #${fragment}`,
    );
  }

  return { x: method.pubKeyX, y: method.pubKeyY };
}
