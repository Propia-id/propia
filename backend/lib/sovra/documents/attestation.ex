defmodule Sovra.Documents.Attestation do
  @moduledoc """
  Builds and signs a document attestation: an ES256 JWS over the schema's claims,
  serialised as an SD-JWT VC with no disclosures and no key binding, so the
  artefact is `<jwt>~`.
  """

  alias Sovra.Crypto.JwtSigner
  alias Sovra.Issuer.ClaimUtils

  # Same media type the credential rail emits and the verification SDK checks.
  @header %{"alg" => "ES256", "typ" => "vc+sd-jwt"}

  # The claims payload/4 sets itself, so a schema is not allowed to declare one.
  # `exp` is listed even though the registered map omits it when the schema has
  # no validity period: that absence is exactly what would let a declared `exp`
  # through and put an expiry the issuer never configured into a signed payload.
  @registered_claims ~w(iss vct jti iat exp)

  @doc """
  Signs an attestation over `claims`. `jti` is the document's id, so its identity
  is covered by the signature. Returns the JWS, the payload, and the sha-256 of
  the signing input, which is the digest anchored on-chain.
  """
  def build(workspace, schema, claims, jti, opts \\ []) do
    payload = payload(workspace, schema, claims, jti, opts)
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
    |> then(&declared_claims(schema, &1))
  end

  @doc """
  The claims that get signed, flat.

  `jti` is the document's id, so a JWS cannot be served under another document's
  id, and its 122 bits of entropy stop the payload being reconstructed by
  guessing `iat` against the on-chain digest.
  """
  def payload(workspace, schema, claims, jti, opts \\ []) do
    iat = System.system_time(:second)
    declared = declared_claims(schema, claims)

    registered =
      %{
        "iss" => "#{ClaimUtils.base_url()}/#{workspace.did}",
        "vct" => schema.credential_type,
        "jti" => jti,
        "iat" => iat
      }
      |> maybe_put_exp(ClaimUtils.resolve_expiry(schema, opts))

    # Registered claims win: a schema declaring a claim named `iss` must not be
    # able to overwrite who issued the document.
    Map.merge(declared, registered)
  end

  defp declared_claims(schema, claims) do
    schema
    |> ClaimUtils.take_declared_claims(claims)
    |> Map.drop(@registered_claims)
  end

  # Defers to the resolver every issuance path shares, so a document's custom
  # `:valid_until` overrides the schema's period exactly as a credential's does.
  defp maybe_put_exp(registered, nil), do: registered

  defp maybe_put_exp(registered, %DateTime{} = expires_at),
    do: Map.put(registered, "exp", DateTime.to_unix(expires_at))
end
