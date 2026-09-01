defmodule Sovra.Verification.RequestObject do
  @moduledoc """
  Signed OID4VP authorization requests (JAR, RFC 9101).

  An unsigned authorization request authenticates nothing: the verifier name,
  the `client_id` and the `response_uri` all reach the wallet straight off the
  QR, so anyone who prints a sticker can display a trusted name and route the
  citizen's `vp_token` to their own server. OID4VP 1.0 answers that with a
  request object signed under a Client Identifier the wallet can resolve a key
  for, and this module builds it.

  The `client_id` uses the `decentralized_identifier` Client Identifier Prefix
  (OID4VP 1.0 §5.10): `decentralized_identifier:did:sovra:0x…`, the workspace's
  own DID. The wallet resolves that DID against the on-chain DID Registry and
  verifies the JWS with the `#key-assert` verification method — the same P-256
  key the workspace signs its credentials with. Nothing in the request is
  trusted until that signature verifies, `response_uri` included.

  This authenticates the verifier. It does not accredit it: a signature proves
  only that whoever controls the DID made the request, so an attacker who
  provisions their own workspace still gets a valid signature over whatever
  `client_name` they like. Answering *that* needs a verifier trust registry
  alongside the issuer one — the second layer, not this one.
  """

  alias Sovra.Crypto.JwtSigner
  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Workspaces.Workspace

  @client_id_prefix "decentralized_identifier"

  # OID4VP 1.0 §5.10.1: the assertion key registered on-chain for the
  # workspace, named by the fragment `did:sovra` gives it.
  @verification_method "key-assert"

  # OID4VP 1.0 §5.9: with no dynamic Wallet metadata to discover, the audience
  # of a signed request is the fixed static-discovery value.
  @static_wallet_aud "https://self-issued.me/v2"

  @typ "oauth-authz-req+jwt"

  @doc """
  The OID4VP Client Identifier for a workspace acting as a verifier.

  Carried both as a top-level query parameter and inside the signed request
  object (OID4VP 1.0 requires the two to match), and it is the audience the
  holder's KB-JWT must name.
  """
  @spec client_id(Workspace.t() | String.t()) :: String.t()
  def client_id(%Workspace{did: did}), do: client_id(did)
  def client_id(did) when is_binary(did), do: "#{@client_id_prefix}:#{did}"

  @doc """
  Build and sign the authorization request object for `session`, issued by
  `workspace`. Returns the compact JWS to serve from the `request_uri`
  endpoint and to inline as the `request` parameter.
  """
  @spec sign(Workspace.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def sign(%Workspace{} = workspace, %{} = session) do
    header = %{
      "alg" => "ES256",
      "typ" => @typ,
      "kid" => "#{workspace.did}##{@verification_method}"
    }

    JwtSigner.sign(header, payload(workspace, session), workspace.signing_key_id)
  end

  defp payload(%Workspace{} = workspace, session) do
    client_id = client_id(workspace)

    %{
      "iss" => client_id,
      "aud" => @static_wallet_aud,
      "iat" => System.system_time(:second),
      "exp" => DateTime.to_unix(session.expires_at),
      "client_id" => client_id,
      "response_type" => "vp_token",
      "response_mode" => "direct_post",
      "response_uri" => response_uri(session),
      "nonce" => session.nonce,
      "state" => session.state,
      "dcql_query" => session.dcql_query,
      "client_metadata" => %{"client_name" => workspace.name}
    }
  end

  @doc """
  Where the wallet posts the `vp_token`. Signed into the request object, so a
  forged QR cannot point it somewhere else while keeping the verifier's name.
  """
  @spec response_uri(map()) :: String.t()
  def response_uri(session) do
    "#{ClaimUtils.base_url()}/wallet/verifier/direct_post/#{session.id}"
  end
end
