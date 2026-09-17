/**
 * The one list of claim keys that are protocol plumbing rather than data.
 *
 * Previously duplicated four ways — in the wallet's display helpers, the
 * approval builder, the standalone credential screen, and the verifier app —
 * which meant four chances to disagree about whether `aud` is user data.
 *
 * These are SD-JWT / JWT envelope claims. An mdoc namespace contains only real
 * data elements, so this filter must not be applied to one: an operator is free
 * to define an element called `status`, and hiding it would be a bug rather
 * than tidiness.
 */
const ENVELOPE_CLAIMS = new Set([
  "iss",
  "sub",
  "aud",
  "iat",
  "exp",
  "nbf",
  "jti",
  "vct",
  "cnf",
  "vc",
  "type",
  "status",
  "credentialStatus",
  "iss_country",
  "iss_authority",
  "_sd",
  "_sd_alg",
]);

export function isEnvelopeClaim(key: string): boolean {
  // Anything underscore-prefixed is SD-JWT internals by convention.
  return key.startsWith("_") || ENVELOPE_CLAIMS.has(key);
}
