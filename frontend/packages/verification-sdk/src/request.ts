/**
 * OpenID4VP request construction, for a verifier whose holder answers by QR.
 *
 * Used by the standalone verifier app, and tested directly against the
 * wallet's parser — this URI is the entire contract between the two devices,
 * and a mismatch is only visible at a demo.
 */

export interface PresentationRequestInput {
  /** Verifier DID. Becomes `client_id` and the audience of the holder's proof. */
  clientId: string;
  /**
   * Human-readable verifier name, sent as `client_metadata.client_name`.
   *
   * The Sovra wallet no longer renders it: a name off an unsigned request is
   * the one field an impersonator sets. Nor does it fall back to `client_id`,
   * which is free text on the same unsigned request — the consent screen calls
   * this verifier unknown and says so. The name stays on the wire because it
   * is the spec's field for this, and a wallet that can authenticate the
   * request will have something to attach it to.
   */
  clientName: string;
  /** One-time challenge the wallet echoes in its KB-JWT. */
  nonce: string;
  /** DCQL credential-query id. Opaque to the wallet; used for correlation. */
  queryId: string;
  /** SD-JWT `vct` the wallet must match a stored credential against. */
  credentialType: string;
  /** Claim names to request. */
  claims: string[];
}

/**
 * The request asks for `vc+sd-jwt` and nothing else, and that is a property of
 * the flow rather than an omission.
 *
 * An mdoc presentation is signed over a session transcript that hashes the
 * `response_uri` the response will be posted to. This request deliberately sends no
 * `response_uri` — the wallet answers by rendering its own QR, which is what
 * lets the whole exchange work with neither device having network access to the
 * other. There is nothing to hash, and substituting a placeholder would be a
 * private convention only our own verifier could follow.
 *
 * mdoc verification therefore runs through the hosted OID4VP flow, where a
 * backend session supplies a real `response_uri`. Adding a format parameter
 * here would ship a path that cannot work.
 */
const REQUESTED_FORMAT = "vc+sd-jwt";

/**
 * Build an `openid4vp://` request URI carrying the request object inline.
 *
 * Two properties the wallet side depends on:
 *  - the `openid4vp://` scheme — `PresentationProtocol.isPresentationRequest`
 *    dispatches on that prefix alone;
 *  - the request object as percent-encoded JSON in the `request` parameter —
 *    the wallet takes this wrapped form or a flat query, and the wrapped form
 *    keeps JSON punctuation out of the query string. JSON is also what marks
 *    it *unsigned*: the signed form is a compact JWS in the same parameter.
 *
 * There is no `response_uri` or `response_mode`, which is what makes the wallet
 * answer by rendering its own QR rather than posting anywhere. The request is
 * unsigned, so the wallet presents this verifier as unverified.
 */
export function buildPresentationRequestUri(input: PresentationRequestInput): string {
  const requestObject = JSON.stringify({
    client_id: input.clientId,
    nonce: input.nonce,
    dcql_query: {
      credentials: [
        {
          id: input.queryId,
          format: REQUESTED_FORMAT,
          meta: { vct_values: [input.credentialType] },
          claims: input.claims.map((claim) => ({ path: [claim], id: claim })),
        },
      ],
    },
    client_metadata: { client_name: input.clientName },
  });

  return `openid4vp://?client_id=${encodeURIComponent(
    input.clientId,
  )}&request=${encodeURIComponent(requestObject)}`;
}
