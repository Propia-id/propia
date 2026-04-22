defmodule Sovra.Credentials.BitstringStatusList do
  @moduledoc """
  Encodes on-chain bitmaps as W3C Bitstring Status List v1.0 format.

  Pipeline: uint256[] → raw bytes (big-endian) → GZIP → base64url → multibase 'u' prefix.
  """

  @doc """
  Encode a list of uint256 values (as integers) into a W3C encodedList string.
  """
  def encode(bitmap_words) do
    raw_bytes =
      bitmap_words
      |> Enum.map(fn word -> <<word::unsigned-big-256>> end)
      |> IO.iodata_to_binary()

    compressed = :zlib.gzip(raw_bytes)
    encoded = Base.url_encode64(compressed, padding: false)
    "u" <> encoded
  end

  @doc """
  Build a BitstringStatusListCredential JSON map.
  """
  def build_credential(issuer_did, purpose, encoded_list) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    %{
      "@context" => ["https://www.w3.org/ns/credentials/v2"],
      "type" => ["VerifiableCredential", "BitstringStatusListCredential"],
      "issuer" => issuer_did,
      "validFrom" => now,
      "credentialSubject" => %{
        "type" => "BitstringStatusList",
        "statusPurpose" => purpose,
        "encodedList" => encoded_list
      }
    }
  end
end
