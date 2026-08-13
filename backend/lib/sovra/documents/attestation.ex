defmodule Sovra.Documents.Attestation do
  @moduledoc """
  Builds and signs a document attestation: an ES256 JWS over the schema's claims,
  serialised as an SD-JWT VC with no disclosures and no key binding, so the
  artefact is `<jwt>~`.
  """

  alias Sovra.Crypto.JwtSigner
  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Issuer.SDJWT

  # Same media type the credential rail emits and the verification SDK checks.
  @header %{"alg" => "ES256", "typ" => "vc+sd-jwt"}

  @doc """
  Signs an attestation over `claims`. `jti` is the document's id, so its identity
  is covered by the signature. Returns the JWS, the payload, and the sha-256 of
  the signing input, which is the digest anchored on-chain.
  """
  def build(workspace, schema, claims, jti) do
    payload = payload(workspace, schema, claims, jti)
    signing_input = JwtSigner.encode_signing_input(@header, payload)

    case JwtSigner.sign_signing_input(signing_input, workspace.signing_key_id) do
      {:ok, signature} ->
        {:ok,
         %{
           # Bare trailing separator: an empty disclosure list.
           credential: signing_input <> "." <> signature <> "~",
           payload: payload,
           digest: :crypto.hash(:sha256, signing_input)
         }}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  The declared claims of a signed document, read back out of the credential.

  Keyed off the schema, like issuance, so a rendering can only show what was
  signed. Raises on a credential this server did not produce.
  """
  def claims(credential, schema) do
    [jwt | _disclosures] = String.split(credential, "~")
    [_header, payload, _signature] = String.split(jwt, ".")

    payload
    |> Base.url_decode64!(padding: false)
    |> Jason.decode!()
    |> then(&ClaimUtils.take_declared_claims(schema, &1))
  end

  @doc """
  The claims that get signed, flat.

  `jti` is the document's id, so a JWS cannot be served under another document's
  id, and its 122 bits of entropy stop the payload being reconstructed by
  guessing `iat` against the on-chain digest.
  """
  def payload(workspace, schema, claims, jti) do
    iat = System.system_time(:second)
    exp = iat + SDJWT.parse_validity_period(schema.validity_period)
    declared = ClaimUtils.take_declared_claims(schema, claims)

    registered = %{
      "iss" => "#{ClaimUtils.base_url()}/#{workspace.did}",
      "vct" => schema.credential_type,
      "jti" => jti,
      "iat" => iat,
      "exp" => exp
    }

    # Registered claims win: a schema declaring a claim named `iss` must not be
    # able to overwrite who issued the document.
    Map.merge(declared, registered)
  end
end
