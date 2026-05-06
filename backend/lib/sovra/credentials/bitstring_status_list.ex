defmodule Sovra.Credentials.BitstringStatusList do
  @moduledoc """
  Encodes on-chain bitmaps as W3C Bitstring Status List v1.0 format and signs
  them as VC-JWT credentials.

  Pipeline: uint256[] → raw bytes (big-endian) → GZIP → base64url → multibase 'u' prefix.
  """

  alias Sovra.Crypto.JwtSigner
  alias Sovra.Workspaces.Workspace

  # ETag stability: `iat` is rounded down to a 5-minute bucket so identical
  # on-chain state yields byte-identical JWTs across requests within the
  # cache TTL. Must equal the `Cache-Control: max-age` value.
  @iat_bucket_seconds 300

  @doc "Bucket length in seconds. Public so the controller can render Cache-Control headers from a single source of truth."
  def iat_bucket_seconds, do: @iat_bucket_seconds

  @doc """
  Bucketed Unix-second timestamp used for `iat` / `validFrom`. Single read of
  the system clock so callers that need the same value across multiple
  payload fields (e.g. `iat` and `validFrom`) avoid drift across a bucket
  boundary.
  """
  def bucket_iat, do: div(System.system_time(:second), @iat_bucket_seconds) * @iat_bucket_seconds

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
  Build a BitstringStatusListCredential JSON map (unsigned). Pass `iat` so the
  credential's `validFrom` is consistent with the outer JWT's `iat` claim
  even when called near a bucket boundary.
  """
  def build_credential(issuer_did, purpose, encoded_list, iat) when is_integer(iat) do
    %{
      "@context" => ["https://www.w3.org/ns/credentials/v2"],
      "type" => ["VerifiableCredential", "BitstringStatusListCredential"],
      "issuer" => issuer_did,
      "validFrom" => iat |> DateTime.from_unix!() |> DateTime.to_iso8601(),
      "credentialSubject" => %{
        "type" => "BitstringStatusList",
        "statusPurpose" => purpose,
        "encodedList" => encoded_list
      }
    }
  end

  @doc """
  Build the unsigned signing input (`header.payload`) for the
  BitstringStatusListCredential VC-JWT. Useful when the caller wants to
  compute an ETag from the content before paying for a signature.
  """
  @spec build_signing_input(Workspace.t(), String.t(), String.t()) :: String.t()
  def build_signing_input(%Workspace{} = workspace, purpose, encoded_list) do
    {header, payload} = jwt_components(workspace, purpose, encoded_list)
    JwtSigner.encode_signing_input(header, payload)
  end

  @doc """
  Append an ES256 signature to a signing input previously produced by
  `build_signing_input/3`. Returns the compact JWS.
  """
  @spec sign(Workspace.t(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def sign(%Workspace{signing_key_id: key_id}, signing_input) do
    case JwtSigner.sign_signing_input(signing_input, key_id) do
      {:ok, sig_b64} -> {:ok, "#{signing_input}.#{sig_b64}"}
      {:error, _} = error -> error
    end
  end

  @doc """
  Build a VC-JWT 1.1 wrapping the BitstringStatusListCredential, signed with
  the workspace's P-256 issuer key (ES256). Returns the compact JWS.
  """
  @spec build_signed_credential(Workspace.t(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, term()}
  def build_signed_credential(%Workspace{} = workspace, purpose, encoded_list) do
    sign(workspace, build_signing_input(workspace, purpose, encoded_list))
  end

  defp jwt_components(workspace, purpose, encoded_list) do
    iat = bucket_iat()
    credential = build_credential(workspace.did, purpose, encoded_list, iat)

    payload = %{
      "iss" => workspace.did,
      "sub" => "#{workspace.did}/status/#{purpose}",
      "iat" => iat,
      "vc" => credential
    }

    header = %{"alg" => "ES256", "typ" => "JWT"}
    {header, payload}
  end
end
