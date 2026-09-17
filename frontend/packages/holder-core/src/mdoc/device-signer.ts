/**
 * How a holder signs an mdoc `DeviceAuth` — **seam 2** of the retrofit
 * contract.
 *
 * The mdoc code above this interface knows nothing about WebAuthn. It hands
 * over bytes to sign and gets back a signature plus whatever unprotected header
 * the algorithm needs. Swapping the holder's key from a WebAuthn passkey to a
 * raw Secure Enclave key later means writing one more implementation of this
 * interface that returns `{signature, unprotected: empty}` with `coseAlg: -7`,
 * and touching nothing else here.
 */

import type { CborMap, CborValue } from "../cbor/index.js";
import { COSE_ALG, SOVRA_WEBAUTHN_LABEL } from "../cose/index.js";
import { hexToBytes } from "../utils/index.js";
import type { HolderAssertion, HolderSigner } from "../protocols/types.js";

export interface DeviceSignature {
  /** Raw `r || s`, 64 bytes for P-256. */
  signature: Uint8Array;
  /** Extra material the verifier needs to check this algorithm. */
  unprotected: CborMap;
}

export interface DeviceSigner {
  readonly coseAlg: number;
  signCose(toBeSigned: Uint8Array): Promise<DeviceSignature>;
}

/**
 * Adapt the wallet's existing passkey signer into a `DeviceSigner`.
 *
 * A WebAuthn authenticator does not sign the payload: it signs
 * `authenticatorData || SHA-256(clientDataJSON)`, with the payload appearing
 * only as the `challenge` inside `clientDataJSON`. That is a different
 * computation from ES256, so it gets its own algorithm identifier rather than
 * claiming `-7` — a conformant reader would otherwise fail with no diagnostic.
 *
 * The envelope rides in the *unprotected* header, which the signature does not
 * cover. That is safe here because integrity comes from the challenge binding:
 * a verifier recomputes `Sig_structure`, hashes it, and checks that value
 * appears at `challenge_index` inside the signed `clientDataJSON`. Tampering
 * with the envelope breaks verification even though the bytes are unsigned.
 */
export function holderSignerToDeviceSigner(
  signer: HolderSigner,
  credentialId: string,
  sha256: (data: Uint8Array) => Uint8Array,
): DeviceSigner {
  return {
    coseAlg: signer.coseAlg,

    async signCose(toBeSigned: Uint8Array): Promise<DeviceSignature> {
      const assertion = await signer.sign(sha256(toBeSigned), credentialId);
      return {
        signature: assertionSignature(assertion),
        unprotected: assertionUnprotectedHeader(assertion),
      };
    },
  };
}

function assertionSignature(assertion: HolderAssertion): Uint8Array {
  const r = hexToBytes(assertion.r);
  const s = hexToBytes(assertion.s);
  const out = new Uint8Array(r.length + s.length);
  out.set(r, 0);
  out.set(s, r.length);
  return out;
}

function assertionUnprotectedHeader(assertion: HolderAssertion): CborMap {
  if (assertion.kind === "es256") return new Map();

  const envelope = new Map<string, CborValue>([
    ["authenticator_data", hexToBytes(assertion.authenticatorData)],
    ["client_data_json", new TextEncoder().encode(assertion.clientDataJson)],
    ["challenge_index", assertion.challengeIndex],
    ["type_index", assertion.typeIndex],
  ]);

  return new Map<string, CborValue>([[SOVRA_WEBAUTHN_LABEL, envelope]]);
}

export { COSE_ALG };
