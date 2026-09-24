/**
 * The one reading of an issuer-supplied base64 `data:` URI — a card logo, an
 * attached document.
 *
 * Both end in `AssetStorage.put(key, base64)`, whose platform decoder refuses
 * anything but standard, padded base64. So this refuses the same: a payload
 * accepted here and rejected there is a value the wallet claimed to understand
 * and then could not write.
 */
export interface Base64DataUri {
  /** As written. Whether its case matters is the caller's decision. */
  mediaType: string;
  base64: string;
}

// Whitespace is legal inside a base64 body but not inside a `data:` URI, and
// the backend rejects it on the way in — so a value carrying any is left alone
// rather than repaired.
const DATA_URI = /^data:([A-Za-z]+\/[A-Za-z0-9.+-]+);base64,([A-Za-z0-9+/]+={0,2})$/;

/**
 * Split a `data:` URI into its media type and payload, or null when it is not
 * one whose payload is at most `maxBase64Length` characters.
 */
export function parseBase64DataUri(
  value: string,
  maxBase64Length: number,
): Base64DataUri | null {
  const match = DATA_URI.exec(value);
  if (!match) return null;

  const [, mediaType, base64] = match;
  // The alphabet alone admits a length that is not a multiple of four — which
  // is also what missing padding looks like — and no decoder accepts one.
  if (base64.length % 4 !== 0 || base64.length > maxBase64Length) return null;

  return { mediaType, base64 };
}
