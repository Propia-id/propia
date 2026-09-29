defmodule Sovra.Issuer.SDJWT do
  @moduledoc """
  Builds SD-JWT credentials compatible with the wallet's CredentialManager.parseSDJwt().

  Format: <issuerJWT>~<disclosure1>~<disclosure2>~...~
  Each disclosure: base64url(JSON([salt, key, value]))
  Issuer JWT payload contains _sd array of base64url(SHA-256(disclosure)) digests.
  """

  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Issuer.ClaimValue

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
      |> maybe_add_expiry(schema, opts)
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
    iat =
      case Keyword.get(opts, :now) do
        %DateTime{} = dt -> DateTime.to_unix(dt)
        _ -> System.system_time(:second)
      end

    schema_keys =
      schema.claims
      |> ClaimUtils.parse_claim_defs()
      |> Enum.map(& &1["key"])

    %{
      "iss" => "#{ClaimUtils.base_url()}/#{issuer.did}",
      "iat" => iat,
      "vct" => schema.credential_type
    }
    |> maybe_add_expiry(schema, opts)
    |> Map.merge(claims |> Map.take(schema_keys) |> describe_attachments(schema))
    |> maybe_add_credential_status(issuer, opts)
  end

  # The preview is unsigned and has no disclosure semantics — its job is to let
  # Sovra Gov render the citizen's credential immediately. Echoing half a
  # megabyte of PDF back to the request that just uploaded it buys nothing, so
  # an attachment travels as a description of itself.
  defp describe_attachments(claims, schema) do
    schema.claims
    |> ClaimValue.attachment_claims()
    |> Enum.reduce(claims, fn claim_def, acc ->
      key = claim_def["key"]

      case ClaimValue.describe(Map.get(acc, key)) do
        {:ok, described} -> Map.put(acc, key, attachment_descriptor(described))
        :error -> acc
      end
    end)
  end

  @doc """
  Splits one disclosure out of a compact SD-JWT, returning the remainder and a
  description of what was removed.

  Lossless: the disclosure's digest stays in the signed `_sd` array, so what
  comes back is an ordinary credential with one claim withheld — exactly the
  state a holder creates every time they decline to disclose something. The
  issuer JWT is untouched, so the signature still verifies.

  `{sd_jwt, nil}` when the credential carries no such disclosure, so a caller
  can hand any credential to this without asking first.
  """
  @spec without_claim(String.t(), String.t()) :: {String.t(), map() | nil}
  def without_claim(sd_jwt, key) when is_binary(sd_jwt) and is_binary(key) do
    [jwt | segments] = String.split(sd_jwt, "~")

    # Each segment is decoded once, and the removed one is described from that
    # same decode: for an attachment it is the largest disclosure there is.
    {kept, described} =
      Enum.reduce(segments, {[], nil}, fn segment, {kept, described} ->
        case decode_disclosure(segment) do
          [_salt, ^key, value] -> {kept, described || describe_value(value, key)}
          _ -> {[segment | kept], described}
        end
      end)

    {Enum.join([jwt | Enum.reverse(kept)], "~"), described}
  end

  # The trailing empty segment after the final `~` is not a disclosure, and
  # neither is a KB-JWT — both fail to decode as a `[salt, key, value]` array,
  # so neither is ever mistaken for one.
  defp decode_disclosure(segment) do
    with {:ok, json} <- Base.url_decode64(segment, padding: false),
         {:ok, decoded} <- Jason.decode(json) do
      decoded
    else
      _ -> nil
    end
  end

  defp describe_value(value, key) do
    case ClaimValue.describe(value) do
      {:ok, described} -> Map.put(attachment_descriptor(described), "claim", key)
      :error -> nil
    end
  end

  defp attachment_descriptor(%{media_type: media_type, bytes: bytes}) do
    %{"type" => ClaimValue.attachment_type(), "media_type" => media_type, "bytes" => bytes}
  end

  # Defers to the one resolver every issuance path shares, so an issuer's
  # custom `:valid_until` beats the schema's period here exactly as it does in
  # the `issued_credentials` row and the offer preview.
  #
  # Omitted, never `"exp" => nil`: RFC 7519 requires a NumericDate when present.
  defp maybe_add_expiry(payload, schema, opts) do
    case ClaimUtils.resolve_expiry(schema, opts) do
      %DateTime{} = expires_at -> Map.put(payload, "exp", DateTime.to_unix(expires_at))
      nil -> payload
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
