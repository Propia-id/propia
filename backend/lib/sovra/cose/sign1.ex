defmodule Sovra.Cose.Sign1 do
  @moduledoc """
  `COSE_Sign1` (RFC 9052 §4.2) — build, parse, and verify.

  Both mDoc signatures are `COSE_Sign1`: the issuer's `MSO` and the holder's
  `DeviceAuth`. Signing goes through `Sovra.Crypto.Key.sign/2`, the same
  32-byte-digest-in, `%{r, s}`-out seam `Sovra.Crypto.JwtSigner` uses — so an
  mDoc issued in production is signed by KMS exactly like an SD-JWT, with no
  key material on the API node.

  ## Verbatim bytes

  `parse/1` keeps `protected_bytes` and the payload byte string exactly as
  received and `to_be_signed/3` uses those, never a re-encode. Treat that as an
  invariant, not an optimisation.

  The protected header is a **map**, and 18013-5 does not require map keys to be
  sorted (see `Sovra.Cbor`), so an issuer may emit them in any order. Recomputing
  the header from its decoded form would run it through a sorting encoder,
  producing a different `Sig_structure` and failing every signature. This is the
  case where verbatim bytes genuinely matter; a tag-24 wrapper, whose payload is
  opaque, is not.

  ## Detached payloads

  `DeviceAuth` is signed over `DeviceAuthenticationBytes` while transmitting a
  `nil` payload, so both `sign/5` and `to_be_signed/3` take the signed bytes
  separately from what goes on the wire.
  """

  alias Sovra.Cbor
  alias Sovra.Crypto.Key
  alias Sovra.Crypto.P256

  @typedoc "A parsed COSE_Sign1, with the byte-exact fields verification needs."
  @type parsed :: %{
          protected_bytes: binary(),
          protected: map(),
          unprotected: map(),
          payload: binary() | nil,
          signature: binary()
        }

  # RFC 9053 §2.1
  @alg_es256 -7
  @alg_label 1
  @coord_size 32

  @doc "The COSE algorithm identifier for ES256."
  def alg_es256, do: @alg_es256

  @doc """
  Build and sign a `COSE_Sign1`.

  `payload` is what goes on the wire — `nil` for a detached signature, in which
  case `:signed_payload` must say what the signature actually covers.

  Options:
    * `:external_aad` — defaults to `<<>>`; mDoc never uses it
    * `:signed_payload` — the covered bytes when they differ from `payload`
  """
  @spec sign(String.t(), map(), map(), binary() | nil, keyword()) ::
          {:ok, list()} | {:error, term()}
  def sign(key_id, protected, unprotected, payload, opts \\ []) do
    external_aad = Keyword.get(opts, :external_aad, <<>>)
    covered = Keyword.get(opts, :signed_payload) || payload

    protected_bytes = Cbor.encode(protected)
    tbs = sig_structure(protected_bytes, external_aad, covered)

    case Key.sign(key_id, :crypto.hash(:sha256, tbs)) do
      {:ok, %{r: r, s: s}} ->
        signature = P256.pad_or_trim(r, @coord_size) <> P256.pad_or_trim(s, @coord_size)

        {:ok,
         [
           Cbor.bstr(protected_bytes),
           unprotected,
           if(payload, do: Cbor.bstr(payload)),
           Cbor.bstr(signature)
         ]}

      {:error, _} = error ->
        error
    end
  end

  @doc "Parse a decoded `COSE_Sign1` array, keeping the header and payload bytes verbatim."
  @spec parse(term()) :: {:ok, parsed()} | {:error, :malformed_cose_sign1}
  def parse([protected, unprotected, payload, signature]) do
    with {:ok, protected_bytes} <- unwrap_bstr(protected),
         {:ok, sig} <- unwrap_bstr(signature),
         {:ok, payload_bytes} <- unwrap_payload(payload),
         {:ok, protected_map} <- decode_protected(protected_bytes),
         true <- is_map(unprotected) do
      {:ok,
       %{
         protected_bytes: protected_bytes,
         protected: protected_map,
         unprotected: unprotected,
         payload: payload_bytes,
         signature: sig
       }}
    else
      _ -> {:error, :malformed_cose_sign1}
    end
  end

  def parse(_), do: {:error, :malformed_cose_sign1}

  @doc """
  The `Sig_structure` bytes a signature covers.

  `signed_payload` overrides the transmitted payload, for detached signatures.
  """
  @spec to_be_signed(parsed(), binary(), binary() | nil) :: binary()
  def to_be_signed(
        %{protected_bytes: protected_bytes, payload: payload},
        external_aad,
        signed_payload \\ nil
      ) do
    sig_structure(protected_bytes, external_aad, signed_payload || payload)
  end

  @doc """
  The algorithm from the **protected** header only.

  An `alg` in the unprotected header is not covered by the signature and so
  carries no authority; reading one would let an attacker pick the verification
  path. Callers must reject a `COSE_Sign1` whose protected `alg` is absent.
  """
  @spec alg(parsed()) :: integer() | nil
  def alg(%{protected: protected}), do: Map.get(protected, @alg_label)

  @doc "Verify an ES256 `COSE_Sign1` against a P-256 public key."
  @spec verify_es256(parsed(), binary(), binary() | nil, {binary(), binary()}) ::
          :ok | {:error, atom()}
  def verify_es256(parsed, external_aad, signed_payload, {pub_x, pub_y}) do
    with @alg_es256 <- alg(parsed),
         <<r::binary-size(@coord_size), s::binary-size(@coord_size)>> <- parsed.signature,
         digest = :crypto.hash(:sha256, to_be_signed(parsed, external_aad, signed_payload)),
         true <- P256.verify(digest, %{r: r, s: s}, {pub_x, pub_y}) do
      :ok
    else
      alg when is_integer(alg) -> {:error, :unexpected_cose_alg}
      nil -> {:error, :missing_cose_alg}
      _ -> {:error, :invalid_signature}
    end
  end

  # RFC 9052 §4.4. `external_aad` and the payload are always byte strings; a
  # detached payload still appears here, which is the whole point.
  defp sig_structure(protected_bytes, external_aad, payload) do
    Cbor.encode([
      "Signature1",
      Cbor.bstr(protected_bytes),
      Cbor.bstr(external_aad),
      Cbor.bstr(payload || <<>>)
    ])
  end

  defp unwrap_bstr(%CBOR.Tag{tag: :bytes, value: bin}) when is_binary(bin), do: {:ok, bin}
  defp unwrap_bstr(bin) when is_binary(bin), do: {:ok, bin}
  defp unwrap_bstr(_), do: :error

  defp unwrap_payload(nil), do: {:ok, nil}
  defp unwrap_payload(other), do: unwrap_bstr(other)

  # An empty protected header is legal and encodes as a zero-length bstr rather
  # than as an encoded empty map.
  defp decode_protected(<<>>), do: {:ok, %{}}

  defp decode_protected(bytes) do
    case Cbor.decode(bytes) do
      {:ok, map} when is_map(map) -> {:ok, map}
      _ -> :error
    end
  end
end
