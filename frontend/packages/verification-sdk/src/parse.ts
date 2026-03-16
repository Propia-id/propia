import { base64urlDecode } from "@sovra/wallet-core/utils";
import { ErrorCode, type ParsedPresentation, type ParsedDisclosure } from "./types";
import { VerificationError } from "./errors";

/**
 * Parse an SD-JWT presentation string into its components.
 *
 * Format: issuerJwt~disc1~disc2~...~kbJwt
 *
 * Mirrors wallet-core CredentialManager.parseSDJwt but also handles KB-JWT.
 */
export function parsePresentation(sdJwt: string): ParsedPresentation {
  const parts = sdJwt.split("~");

  if (parts.length < 2) {
    throw new VerificationError("SD-JWT must contain at least issuer JWT and KB-JWT", ErrorCode.PARSE_ERROR);
  }

  const issuerJwtRaw = parts[0];

  // Last non-empty part is the KB-JWT
  const lastNonEmpty = parts.filter(Boolean).pop();
  const kbJwtRaw = lastNonEmpty === issuerJwtRaw ? undefined : lastNonEmpty;

  if (!kbJwtRaw) {
    throw new VerificationError("KB-JWT missing from presentation", ErrorCode.KB_JWT_MISSING);
  }

  // Everything between issuer JWT and KB-JWT is disclosures
  // parts = [issuerJwt, disc1, disc2, ..., kbJwt, ""] (trailing ~ produces empty last element)
  const disclosureStrings = parts.slice(1, -1).filter((s) => s !== kbJwtRaw && s !== "");

  // Decode issuer JWT
  const issuerJwtParts = issuerJwtRaw.split(".");
  if (issuerJwtParts.length !== 3) {
    throw new VerificationError("Issuer JWT must have 3 parts", ErrorCode.PARSE_ERROR);
  }
  const issuerHeader = decodeJsonPart(issuerJwtParts[0], "issuer JWT header");
  const issuerPayload = decodeJsonPart(issuerJwtParts[1], "issuer JWT payload");

  // Validate issuer JWT header
  if (issuerHeader.alg !== "ES256") {
    throw new VerificationError(`Expected alg ES256, got ${issuerHeader.alg}`, ErrorCode.PARSE_ERROR);
  }
  if (issuerHeader.typ !== "vc+sd-jwt") {
    throw new VerificationError(`Expected typ vc+sd-jwt, got ${issuerHeader.typ}`, ErrorCode.PARSE_ERROR);
  }

  // Validate required payload fields
  for (const field of ["iss", "vct", "iat"]) {
    if (!(field in issuerPayload)) {
      throw new VerificationError(`Missing required field: ${field}`, ErrorCode.PARSE_ERROR);
    }
  }

  // Decode KB-JWT
  const kbJwtParts = kbJwtRaw.split(".");
  if (kbJwtParts.length !== 3) {
    throw new VerificationError("KB-JWT must have 3 parts", ErrorCode.PARSE_ERROR);
  }
  const kbHeader = decodeJsonPart(kbJwtParts[0], "KB-JWT header");
  const kbPayload = decodeJsonPart(kbJwtParts[1], "KB-JWT payload");

  if (kbHeader.typ !== "kb+jwt") {
    throw new VerificationError(`Expected KB-JWT typ kb+jwt, got ${kbHeader.typ}`, ErrorCode.PARSE_ERROR);
  }

  // Decode disclosures
  const disclosures: ParsedDisclosure[] = disclosureStrings.map((encoded) => {
    try {
      const decoded = JSON.parse(
        new TextDecoder().decode(base64urlDecode(encoded)),
      ) as unknown[];
      if (!Array.isArray(decoded) || decoded.length !== 3) {
        throw new Error("Expected [salt, key, value]");
      }
      return {
        encoded,
        salt: decoded[0] as string,
        key: decoded[1] as string,
        value: decoded[2],
      };
    } catch {
      throw new VerificationError(`Invalid disclosure: ${encoded.slice(0, 20)}...`, ErrorCode.PARSE_ERROR);
    }
  });

  return {
    issuerJwtRaw,
    issuerHeader,
    issuerPayload,
    disclosures,
    kbJwtRaw,
    kbHeader,
    kbPayload,
  };
}

function decodeJsonPart(b64: string, label: string): Record<string, unknown> {
  try {
    return JSON.parse(new TextDecoder().decode(base64urlDecode(b64))) as Record<string, unknown>;
  } catch {
    throw new VerificationError(`Failed to decode ${label}`, ErrorCode.PARSE_ERROR);
  }
}

// Re-export for backward compatibility
export { VerificationError } from "./errors";
