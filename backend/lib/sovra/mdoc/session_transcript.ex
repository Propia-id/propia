defmodule Sovra.Mdoc.SessionTranscript do
  @moduledoc """
  The `SessionTranscript` that binds an mdoc presentation to one verifier and
  one request.

  ## This is a wire contract, not an implementation detail

  The wallet and the verifier build this independently from the same inputs and
  never exchange it. A single byte of disagreement makes the device signature
  verify against nothing, and the failure surfaces as a crypto error rather than
  as a disagreement about a string — the least debuggable shape a bug can take.
  `test/sovra/mdoc/session_transcript_test.exs` pins a hex vector, and
  `holder-core`'s `session-transcript.ts` pins the same one.

  ## Profile

  OpenID4VP 1.0, the `direct_post` variant:

      SessionTranscript      = [null, null, OpenID4VPHandover]
      OpenID4VPHandover      = ["OpenID4VPHandover", SHA-256(cbor(HandoverInfo))]
      OpenID4VPHandoverInfo  = [client_id, nonce, jwk_thumbprint, response_uri]

  where `client_id`, `nonce` and `response_uri` are text strings and
  `jwk_thumbprint` is a **byte string or null** — never text.

  ISO/IEC TS 18013-7 Annex B defines a different shape whose hashes each cover an
  `mdocGeneratedNonce`. That nonce binds the wallet's ephemeral *encryption*
  key and travels in the JWE `apu` header, which an unencrypted `direct_post`
  response does not have — carrying it would mean inventing a private
  extension. The verifier's own `nonce` remains the freshness anchor, exactly as
  it is for the SD-JWT key-binding JWT today.

  `jwk_thumbprint` is null for us, because it identifies a response-encryption
  key we do not use. If we ever adopt `direct_post.jwt` it becomes the RFC 7638
  SHA-256 thumbprint of the verifier's encryption key, and the spec is explicit
  that it travels *"encoded as a Byte String"* — so `handover_info/4` takes the
  raw 32 bytes and wraps them, rather than a base64url string that would encode
  as CBOR text and hash to something no conformant wallet produces.
  """

  alias Sovra.Cbor
  alias Sovra.Verification.RequestObject
  alias Sovra.Verification.Session

  @handover_type "OpenID4VPHandover"

  @doc "Bump only alongside a reviewed change to the structures below."
  def profile, do: "openid4vp-1.0"

  @doc """
  The `SessionTranscript` value for a verification session.

  Takes only the session, deliberately. The `client_id` identifies the
  *verifier* — the workspace that created the session — and an earlier version
  of this took a workspace argument, which made it possible to hand it the
  issuer's instead. That produced a transcript the wallet could never match, and
  the failure surfaced as a signature error pointing nowhere near the cause.
  The session already knows its verifier, so there is nothing to get wrong.

  `client_id` is read off the row rather than rebuilt: it is the exact string
  signed into the request object and sent to the wallet, and the transcript has
  to hash what was sent, not what we would send today.
  """
  @spec build(Session.t()) :: list()
  def build(%Session{} = session) do
    from_parts(
      session.client_id,
      session.nonce,
      RequestObject.response_uri(session)
    )
  end

  @doc """
  The `SessionTranscript` from raw parts.

  Separate from `build/2` so the interop vector can be pinned without
  constructing a session, and so a verifier can rebuild the transcript from
  whatever it actually sent.
  """
  @spec from_parts(String.t(), String.t(), String.t(), binary() | nil) :: list()
  def from_parts(client_id, nonce, response_uri, jwk_thumbprint \\ nil) do
    info_hash =
      :crypto.hash(
        :sha256,
        Cbor.encode(handover_info(client_id, nonce, response_uri, jwk_thumbprint))
      )

    [nil, nil, [@handover_type, Cbor.bstr(info_hash)]]
  end

  @doc """
  The `OpenID4VPHandoverInfo` array that gets hashed into the handover.

  `jwk_thumbprint` is the raw thumbprint digest, not a base64url string of it.
  """
  @spec handover_info(String.t(), String.t(), String.t(), binary() | nil) :: list()
  def handover_info(client_id, nonce, response_uri, jwk_thumbprint \\ nil) do
    [client_id, nonce, thumbprint(jwk_thumbprint), response_uri]
  end

  # A bare binary would encode as CBOR text; the spec requires a byte string.
  defp thumbprint(nil), do: nil
  defp thumbprint(digest) when is_binary(digest), do: Cbor.bstr(digest)
end
