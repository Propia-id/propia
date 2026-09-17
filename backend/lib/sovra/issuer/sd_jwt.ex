defmodule Sovra.Issuer.SDJWT do
  @moduledoc """
  Builds SD-JWT credentials compatible with the wallet's CredentialManager.parseSDJwt().

  Format: <issuerJWT>~<disclosure1>~<disclosure2>~...~
  Each disclosure: base64url(JSON([salt, key, value]))
  Issuer JWT payload contains _sd array of base64url(SHA-256(disclosure)) digests.
  """

  alias Sovra.Issuer.ClaimUtils

  @doc """
  Build a complete SD-JWT string for a credential.

  The `schema` must have a `claims` field that is a list of maps with keys:
  "key", "type", "required", "disclosable".
  """
  def build(issuer, schema, claims, holder_did, opts \\ []) do
    # `:now` lets the caller pin the issuance instant. `Sovra.Issuer` records
    # `expires_at` on the IssuedCredential row from the same instant, and the
    # two must agree exactly — the row is what the dashboard shows, the `exp`
    # claim is what a verifier enforces.
    now =
      case Keyword.get(opts, :now) do
        %DateTime{} = dt -> DateTime.to_unix(dt)
        _ -> System.system_time(:second)
      end

    # Separate claims into disclosable vs non-disclosable based on schema
    claim_defs = ClaimUtils.parse_claim_defs(schema.claims)
    {disclosable_claims, non_disclosable_claims} = split_claims(claim_defs, claims)

    # Build disclosures for disclosable claims
    disclosures =
      Enum.map(disclosable_claims, fn {key, value} ->
        salt = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
        disclosure_array = Jason.encode!([salt, key, value])
        encoded = Base.url_encode64(disclosure_array, padding: false)
        digest = :crypto.hash(:sha256, encoded) |> Base.url_encode64(padding: false)
        %{encoded: encoded, digest: digest}
      end)

    # Build JWT payload
    payload =
      %{
        "iss" => "#{ClaimUtils.base_url()}/#{issuer.did}",
        "sub" => holder_did,
        "iat" => now,
        "vct" => schema.credential_type,
        "cnf" => %{"kid" => "#{holder_did}#2of2"},
        "_sd" => Enum.map(disclosures, & &1.digest),
        "_sd_alg" => "sha-256"
      }
      |> maybe_add_expiry(schema, now)
      |> Map.merge(Map.new(non_disclosable_claims))
      |> maybe_add_credential_status(issuer, opts)

    # Sign the JWT
    header = %{"alg" => "ES256", "typ" => "vc+sd-jwt"}

    case sign_jwt(header, payload, issuer.signing_key_id) do
      {:ok, jwt} ->
        disclosure_strings = Enum.map(disclosures, & &1.encoded)
        sd_jwt = jwt <> "~" <> Enum.join(disclosure_strings, "~") <> "~"
        {:ok, sd_jwt}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Build the preliminary VC payload returned at offer-creation time, before the
  holder has scanned the QR. Same shape as the SD-JWT payload but without
  holder-bound fields (`sub`, `cnf`), without selective-disclosure digests
  (claims are emitted plaintext), and without a signature. Sovra Gov stores
  this and renders it for the citizen immediately; the signed SD-JWT arrives
  later via the `credential.issued` webhook.
  """
  def build_preview(issuer, schema, claims, opts \\ []) do
    iat = System.system_time(:second)

    schema_keys =
      schema.claims
      |> ClaimUtils.parse_claim_defs()
      |> Enum.map(& &1["key"])

    %{
      "iss" => "#{ClaimUtils.base_url()}/#{issuer.did}",
      "iat" => iat,
      "vct" => schema.credential_type
    }
    |> maybe_add_expiry(schema, iat)
    |> Map.merge(Map.take(claims, schema_keys))
    |> maybe_add_credential_status(issuer, opts)
  end

  # Omitted, never `"exp" => nil`: RFC 7519 requires a NumericDate when present.
  defp maybe_add_expiry(payload, schema, iat) do
    case parse_validity_period(schema.validity_period) do
      nil -> payload
      seconds -> Map.put(payload, "exp", iat + seconds)
    end
  end

  defp maybe_add_credential_status(payload, issuer, opts) do
    case Keyword.get(opts, :status_list_index) do
      nil ->
        payload

      index ->
        Map.put(payload, "credentialStatus", ClaimUtils.credential_status_entries(issuer, index))
    end
  end

  defp sign_jwt(header, payload, signing_key_id) do
    Sovra.Crypto.JwtSigner.sign(header, payload, signing_key_id)
  end

  defp split_claims(claim_defs, claims) do
    Enum.reduce(claim_defs, {[], []}, fn def, {disc, non_disc} ->
      key = def["key"]
      value = Map.get(claims, key)

      if value != nil do
        if def["disclosable"] || def["sd"] do
          {[{key, value} | disc], non_disc}
        else
          {disc, [{key, value} | non_disc]}
        end
      else
        {disc, non_disc}
      end
    end)
    |> then(fn {disc, non_disc} -> {Enum.reverse(disc), Enum.reverse(non_disc)} end)
  end

  @doc """
  Parses a schema validity period (`"1y"`, `"6m"`, `"30d"`) into seconds.

  `nil` in, `nil` out: no validity period, so no `exp`. An unparseable string
  still falls back to one year.

  Lives in `Sovra.Issuer.ClaimUtils` now that mdoc needs it too; delegated here
  because the document issuance path reaches it through this module.
  """
  defdelegate parse_validity_period(period), to: ClaimUtils
end
