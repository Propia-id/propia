defmodule Sovra.Credentials.SDJWT do
  @moduledoc """
  SD-JWT VC parsing and verification for OID4VP `vp_token` payloads.

  A vp_token presented by a wallet has the form

      <issuer_jwt>~<disclosure_1>~...~<disclosure_n>~<kb_jwt>

  This module parses that string, verifies the issuer's ES256 signature on the
  SD-JWT, verifies the holder's ES256 signature on the Key Binding JWT, and
  resolves disclosures against the SD-JWT's `_sd` digest array.
  """

  alias Sovra.Crypto.P256

  @doc """
  Splits a vp_token string into its SD-JWT, disclosures, and KB-JWT parts.

  The OID4VP `vp_token` always carries a KB-JWT for SD-JWT VC presentations,
  but the trailing `~` separator may or may not be present. Both forms are
  accepted.
  """
  def parse(vp_token) when is_binary(vp_token) do
    case String.split(vp_token, "~") do
      [sd_jwt | rest] when rest != [] ->
        # Drop the empty trailing segment from the spec's "tilde-after-kb" form.
        rest = if List.last(rest) == "", do: Enum.drop(rest, -1), else: rest

        case Enum.split(rest, length(rest) - 1) do
          {disclosures, [kb_jwt]} when is_binary(kb_jwt) and kb_jwt != "" ->
            {:ok, %{sd_jwt: sd_jwt, disclosures: disclosures, kb_jwt: kb_jwt}}

          _ ->
            {:error, :malformed_vp_token}
        end

      _ ->
        {:error, :malformed_vp_token}
    end
  end

  def parse(_), do: {:error, :malformed_vp_token}

  @doc """
  Decodes a JWT string into header/payload/signing_input/signature components.
  """
  def decode_jwt(jwt) when is_binary(jwt) do
    with [header_b64, payload_b64, sig_b64] <- String.split(jwt, "."),
         {:ok, header_json} <- Base.url_decode64(header_b64, padding: false),
         {:ok, payload_json} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, header} <- Jason.decode(header_json),
         {:ok, payload} <- Jason.decode(payload_json),
         {:ok, sig_bytes} <- Base.url_decode64(sig_b64, padding: false) do
      {:ok,
       %{
         header: header,
         payload: payload,
         signing_input: header_b64 <> "." <> payload_b64,
         sig_bytes: sig_bytes
       }}
    else
      _ -> {:error, :malformed_jwt}
    end
  end

  @doc """
  Verifies an ES256 signature on a JWT using raw P-256 public key coordinates.
  """
  def verify_issuer_signature(jwt, %{x: x, y: y})
      when is_binary(jwt) and is_binary(x) and is_binary(y) do
    with {:ok, %{header: header, signing_input: input, sig_bytes: sig}} <- decode_jwt(jwt),
         true <- header["alg"] == "ES256",
         <<r::binary-32, s::binary-32>> <- sig do
      hash = :crypto.hash(:sha256, input)

      if P256.verify(hash, %{r: r, s: s}, {x, y}) do
        :ok
      else
        {:error, :invalid_signature}
      end
    else
      _ -> {:error, :invalid_signature}
    end
  end

  @doc """
  Verifies a KB-JWT's ES256 signature against a list of candidate keys.
  Returns `{:ok, %{header, payload}}` if the signature verifies under any
  key in the list, `{:error, :invalid_kb_signature}` otherwise.

  The KB-JWT's own `header.jwk` is **not** trusted — callers supply the
  authoritative key set (typically resolved from the holder's DID).
  """
  def verify_kb_signature(kb_jwt, valid_keys)
      when is_binary(kb_jwt) and is_list(valid_keys) and valid_keys != [] do
    with {:ok, %{header: header, payload: payload, signing_input: input, sig_bytes: sig}} <-
           decode_jwt(kb_jwt),
         true <- header["alg"] == "ES256",
         <<r::binary-32, s::binary-32>> <- sig do
      hash = :crypto.hash(:sha256, input)

      if Enum.any?(valid_keys, fn %{x: x, y: y} -> P256.verify(hash, %{r: r, s: s}, {x, y}) end) do
        {:ok, %{header: header, payload: payload}}
      else
        {:error, :invalid_kb_signature}
      end
    else
      _ -> {:error, :invalid_kb_signature}
    end
  end

  def verify_kb_signature(_, _), do: {:error, :invalid_kb_signature}

  @doc """
  Computes the value the KB-JWT's `sd_hash` claim must equal:
  base64url(SHA-256(`<sd_jwt>~<disclosure>~...~`)).
  """
  def compute_sd_hash(sd_jwt, disclosures) when is_binary(sd_jwt) and is_list(disclosures) do
    presented = sd_jwt <> "~" <> Enum.join(disclosures, "~") <> "~"
    :crypto.hash(:sha256, presented) |> Base.url_encode64(padding: false)
  end

  @doc """
  Resolves disclosures against the SD-JWT payload's `_sd` digest array.

  Returns `{:ok, effective_payload}` (a map merging disclosed `key => value`
  into the SD-JWT payload, with `_sd` and `_sd_alg` stripped) or
  `{:error, :invalid_disclosure}` if any disclosure's digest is not in `_sd`.
  """
  def resolve_disclosures(payload, disclosures) when is_map(payload) and is_list(disclosures) do
    sd_digests = MapSet.new(payload["_sd"] || [])

    result =
      Enum.reduce_while(disclosures, {:ok, %{}}, fn encoded, {:ok, acc} ->
        with {:ok, json} <- Base.url_decode64(encoded, padding: false),
             {:ok, [_salt, key, value]} <- Jason.decode(json),
             digest = :crypto.hash(:sha256, encoded) |> Base.url_encode64(padding: false),
             true <- MapSet.member?(sd_digests, digest) do
          {:cont, {:ok, Map.put(acc, key, value)}}
        else
          _ -> {:halt, {:error, :invalid_disclosure}}
        end
      end)

    case result do
      {:ok, disclosed} ->
        effective =
          payload
          |> Map.drop(["_sd", "_sd_alg"])
          |> Map.merge(disclosed)

        {:ok, effective}

      err ->
        err
    end
  end
end
