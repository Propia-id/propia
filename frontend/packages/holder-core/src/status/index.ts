import { didSovraAddress, type EthCall } from "../did/index.js";
import { parseIssuerSigned } from "../mdoc/index.js";
import { isSdJwt, type RegistryStatus, type StoredCredential } from "../state/index.js";
import {
  base64urlDecode,
  bytesToHex,
  decodeUint64,
  encodeAddress,
  encodeFunctionCall,
  hexToBytes,
} from "../utils/index.js";

// ─── Credential status ────────────────────────────────
//
// Reads what verifiers read: the SovraRevocationRegistry bitmaps on the L2,
// one for revocation and one for suspension, both indexed by the bit the
// issuer signed into the credential.
//
// The wallet fetches an issuer's whole bitmap with `getBitmap` rather than its
// own bit with `getStatus`. The answer is the same, but asking for one bit
// tells the RPC node which credential this device holds — the index is unique
// to the holder. A whole list is the herd privacy the W3C Bitstring Status
// List was designed for; it costs one call per issuer and purpose instead of
// per credential.

/** SovraRevocationRegistry purposes. */
export const STATUS_PURPOSE = { revocation: 0, suspension: 1 } as const;

/** Where a credential's bits live in its issuer's lists. */
export interface StatusReference {
  /** The registry key: the issuer's address, lowercased. */
  issuerAddress: string;
  revocationIndex: number;
  suspensionIndex: number;
}

/**
 * The status bits a credential's issuer signed into it, or null when it
 * declares none — which is a credential that cannot be revoked, not one whose
 * status is unknown.
 *
 * Read from the signed payload, never from the metadata stored beside it: the
 * index a verifier checks is the one the issuer signed.
 */
export function statusReference(cred: StoredCredential): StatusReference | null {
  try {
    return isSdJwt(cred) ? sdJwtStatusReference(cred.sdJwt) : mdocStatusReference(cred.issuerSigned);
  } catch {
    return null;
  }
}

// An SD-JWT declares an entry per purpose. A purpose it leaves out is still
// read at the first entry's index, exactly as the verification SDK and the
// backend verifier do: an issuer cannot escape suspension by omitting the
// entry for it.
function sdJwtStatusReference(sdJwt: string): StatusReference | null {
  const payloadB64 = sdJwt.split("~")[0].split(".")[1];
  const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)));

  if (typeof payload.iss !== "string") return null;
  const issuerDid = payload.iss.slice(payload.iss.lastIndexOf("/") + 1);

  const raw = payload.credentialStatus;
  const entries = (Array.isArray(raw) ? raw : [raw]).flatMap((entry) => {
    if (!entry || typeof entry !== "object" || entry.type !== "BitstringStatusListEntry") {
      return [];
    }
    const index = Number(entry.statusListIndex);
    return Number.isSafeInteger(index) && index >= 0
      ? [{ purpose: entry.statusPurpose, index }]
      : [];
  });
  if (entries.length === 0) return null;

  const indexFor = (purpose: string) =>
    (entries.find((e) => e.purpose === purpose) ?? entries[0]).index;

  return {
    issuerAddress: didSovraAddress(issuerDid).toLowerCase(),
    revocationIndex: indexFor("revocation"),
    suspensionIndex: indexFor("suspension"),
  };
}

// An mdoc carries one index in the Sovra meta namespace, and both lists apply
// to it.
function mdocStatusReference(issuerSigned: string): StatusReference | null {
  const { statusListIndex, issuerAddress } = parseIssuerSigned(issuerSigned);
  if (statusListIndex === null || !issuerAddress) return null;
  if (!/^0x[0-9a-fA-F]{40}$/.test(issuerAddress)) return null;

  return {
    issuerAddress: issuerAddress.toLowerCase(),
    revocationIndex: statusListIndex,
    suspensionIndex: statusListIndex,
  };
}

/**
 * One issuer's list for one purpose, as the registry stores it: 256-bit words,
 * each big-endian, concatenated.
 */
export async function readStatusBitmap(
  ethCall: EthCall,
  registryAddress: string,
  issuerAddress: string,
  purpose: number,
): Promise<Uint8Array> {
  const calldata = bytesToHex(
    encodeFunctionCall("getBitmap(address,uint8)", [
      encodeAddress(issuerAddress),
      new Uint8Array([purpose]),
    ]),
  );
  const result = await ethCall(registryAddress, calldata);

  // A dynamic `uint256[]`: the offset to it, then its length, then the words.
  const offsetWord = decodeUint64(result, 0) / 32;
  if (!Number.isInteger(offsetWord)) throw new Error("getBitmap returned a misaligned array");
  const length = decodeUint64(result, offsetWord);

  const hex = result.startsWith("0x") ? result.slice(2) : result;
  const start = (offsetWord + 1) * 64;
  const words = hex.slice(start, start + length * 64);
  if (words.length !== length * 64) throw new Error("getBitmap returned a truncated array");

  return hexToBytes(words);
}

/**
 * Whether `index` is set, by the contract's own arithmetic: bit `index % 256`
 * of word `index / 256`. A bit past the end of the list is unset, as it is
 * on-chain.
 */
export function isStatusSet(bitmap: Uint8Array, index: number): boolean {
  const word = Math.floor(index / 256);
  const bit = index % 256;
  if ((word + 1) * 32 > bitmap.length) return false;

  const byte = bitmap[word * 32 + 31 - Math.floor(bit / 8)];
  return ((byte >> (bit % 8)) & 1) === 1;
}

/**
 * Check every credential that declares a status, two reads per issuer.
 *
 * Credentials that declare no status are left out of the result, and so are
 * those whose issuer's lists could not be read: a failed read is not evidence
 * that a credential is valid, so the caller keeps whatever it knew before.
 * Revocation outranks suspension, since it is permanent.
 */
export async function readRegistryStatuses(
  ethCall: EthCall,
  registryAddress: string,
  credentials: readonly StoredCredential[],
): Promise<Map<string, RegistryStatus>> {
  const byIssuer = new Map<string, { id: string; ref: StatusReference }[]>();
  for (const cred of credentials) {
    const ref = statusReference(cred);
    if (!ref) continue;
    const group = byIssuer.get(ref.issuerAddress) ?? [];
    group.push({ id: cred.id, ref });
    byIssuer.set(ref.issuerAddress, group);
  }

  const out = new Map<string, RegistryStatus>();
  await Promise.all(
    [...byIssuer].map(async ([issuerAddress, group]) => {
      let revocation: Uint8Array;
      let suspension: Uint8Array;
      try {
        [revocation, suspension] = await Promise.all([
          readStatusBitmap(ethCall, registryAddress, issuerAddress, STATUS_PURPOSE.revocation),
          readStatusBitmap(ethCall, registryAddress, issuerAddress, STATUS_PURPOSE.suspension),
        ]);
      } catch (err) {
        console.warn(`[credentials] status lists for ${issuerAddress} unreadable:`, err);
        return;
      }

      for (const { id, ref } of group) {
        out.set(
          id,
          isStatusSet(revocation, ref.revocationIndex)
            ? "revoked"
            : isStatusSet(suspension, ref.suspensionIndex)
              ? "suspended"
              : "valid",
        );
      }
    }),
  );
  return out;
}
