defmodule Sovra.Issuer.SDJWT do
  @moduledoc """
  Builds SD-JWT credentials compatible with the wallet's CredentialManager.parseSDJwt().

  Format: <issuerJWT>~<disclosure1>~<disclosure2>~...~
  Each disclosure: base64url(JSON([salt, key, value]))
  Issuer JWT payload contains _sd array of base64url(SHA-256(disclosure)) digests.
  """

  alias Sovra.Crypto.Key

  @doc """
  Build a complete SD-JWT string for a credential.

  The `schema` must have a `claims` field that is a list of maps with keys:
  "key", "type", "required", "disclosable".
  """
  def build(issuer, schema, claims, holder_did) do
    now = System.system_time(:second)
    validity_seconds = parse_validity_period(schema.validity_period)
    exp = now + validity_seconds

    # Separate claims into disclosable vs non-disclosable based on schema
    claim_defs = parse_claim_defs(schema.claims)
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
        "iss" => issuer.did,
        "sub" => holder_did,
        "iat" => now,
        "exp" => exp,
        "vct" => schema.credential_type,
        "cnf" => %{"kid" => "#{holder_did}#2of2"},
        "_sd" => Enum.map(disclosures, & &1.digest),
        "_sd_alg" => "sha-256"
      }
      |> Map.merge(Map.new(non_disclosable_claims))

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

  defp sign_jwt(header, payload, signing_key_id) do
    header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
    payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
    signing_input = "#{header_b64}.#{payload_b64}"

    hash = :crypto.hash(:sha256, signing_input)

    case Key.sign(signing_key_id, hash) do
      {:ok, %{r: r, s: s}} ->
        raw_sig = pad_to_32(r) <> pad_to_32(s)
        sig_b64 = Base.url_encode64(raw_sig, padding: false)
        {:ok, "#{signing_input}.#{sig_b64}"}

      {:error, _} = error ->
        error
    end
  end

  defp pad_to_32(bin) when byte_size(bin) == 32, do: bin

  defp pad_to_32(bin) when byte_size(bin) < 32 do
    padding = 32 - byte_size(bin)
    <<0::size(padding * 8)>> <> bin
  end

  defp pad_to_32(bin) when byte_size(bin) > 32 do
    # Trim leading zeros if longer than 32 bytes
    skip = byte_size(bin) - 32
    <<_::binary-size(skip), trimmed::binary-size(32)>> = bin
    trimmed
  end

  defp parse_claim_defs(claims) when is_list(claims), do: claims

  defp parse_claim_defs(claims) when is_map(claims) do
    # Handle both {"claims" => [...]} and direct list formats
    case Map.get(claims, "claims") do
      list when is_list(list) -> list
      _ -> []
    end
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

  defp parse_validity_period(period) do
    case Regex.run(~r/^(\d+)(y|m|d)$/, period) do
      [_, n, "y"] -> String.to_integer(n) * 365 * 86400
      [_, n, "m"] -> String.to_integer(n) * 30 * 86400
      [_, n, "d"] -> String.to_integer(n) * 86400
      _ -> 365 * 86400
    end
  end
end
