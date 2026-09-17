/**
 * `COSE_Key` (RFC 9052 §7) for P-256.
 *
 * mDoc carries the holder's public key here — `MSO.deviceKeyInfo.deviceKey` —
 * where SD-JWT VC carries a `cnf` DID reference instead. A raw key rather than
 * a pointer is what lets an offline reader verify with no network, and also why
 * the key baked in at issuance can never be changed afterwards.
 */

import { CborError, type CborMap, type CborValue } from "../cbor/index.js";

// RFC 9053 §7.1: kty=EC2(2), crv=P-256(1). Labels: kty=1, crv=-1, x=-2, y=-3.
const KTY = 1;
const CRV = -1;
const X = -2;
const Y = -3;
const KTY_EC2 = 2;
const CRV_P256 = 1;
const COORD_SIZE = 32;

export interface P256Point {
  x: Uint8Array;
  y: Uint8Array;
}

export function xyToCoseKey({ x, y }: P256Point): CborMap {
  if (x.length !== COORD_SIZE || y.length !== COORD_SIZE) {
    throw new CborError(`P-256 coordinates must be ${COORD_SIZE} bytes`);
  }
  return new Map<number, CborValue>([
    [KTY, KTY_EC2],
    [CRV, CRV_P256],
    [X, x],
    [Y, y],
  ]);
}

export function coseKeyToXY(value: CborValue): P256Point {
  if (!(value instanceof Map)) throw new CborError("COSE_Key must be a map");

  if (value.get(KTY) !== KTY_EC2) throw new CborError("COSE_Key is not EC2");
  if (value.get(CRV) !== CRV_P256) throw new CborError("COSE_Key is not P-256");

  const x = value.get(X);
  const y = value.get(Y);

  if (!(x instanceof Uint8Array) || x.length !== COORD_SIZE) {
    throw new CborError("COSE_Key x coordinate is malformed");
  }
  if (!(y instanceof Uint8Array) || y.length !== COORD_SIZE) {
    throw new CborError("COSE_Key y coordinate is malformed");
  }

  return { x, y };
}
