import { sha256, base64urlEncode } from "@sovrahq/holder-core/utils";
import { ErrorCode, type ParsedDisclosure } from "./types.js";
import { VerificationError } from "./errors.js";

/**
 * Verify that each disclosure's hash appears in the issuer JWT's _sd array.
 * Returns the reconstructed claims (disclosed + non-disclosable).
 */
export function verifyDisclosures(
  disclosures: ParsedDisclosure[],
  sdArray: string[],
  sdAlg: string,
  payload: Record<string, unknown>,
): Record<string, unknown> {
  if (sdAlg !== "sha-256") {
    throw new VerificationError(
      `Unsupported _sd_alg: ${sdAlg}`,
      ErrorCode.PARSE_ERROR,
    );
  }

  for (const disclosure of disclosures) {
    const hash = base64urlEncode(
      sha256(new TextEncoder().encode(disclosure.encoded)),
    );
    if (!sdArray.includes(hash)) {
      throw new VerificationError(
        `Disclosure hash not found in _sd array for key: ${disclosure.key}`,
        ErrorCode.DISCLOSURE_MISMATCH,
      );
    }
  }

  // Reconstruct claims: start with non-internal payload fields, add disclosed claims
  const claims: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (key !== "_sd" && key !== "_sd_alg" && key !== "cnf") {
      claims[key] = value;
    }
  }
  for (const d of disclosures) {
    claims[d.key] = d.value;
  }

  return claims;
}
