defmodule Sovra.Crypto.WebAuthn do
  @moduledoc """
  WebAuthn authentication-assertion verification for holder binding.

  Mirrors the on-chain `WebAuthn.verify` (OpenZeppelin) that `AlignedAccount`
  uses, and Aligned's own backend verifier — so a passkey assertion that an
  `AlignedAccount` would accept on-chain also verifies here off-chain.

  Checks performed, in order:

    * `authenticator_data` is ≥ 37 bytes (rpIdHash || flags || counter).
    * `client_data_json[type_index..]` begins with `"type":"webauthn.get"`.
    * `client_data_json[challenge_index..]` begins with
      `"challenge":"<base64url(challenge)>"` (no padding). `challenge` is the
      32-byte digest the verifier computed — never a caller-supplied value.
    * `authenticator_data[32]` flag byte: UP (0x01) set, UV (0x04) set, and
      `(BE == 1 || BS == 0)`.
    * `P256.verify(sha256(authenticator_data || sha256(client_data_json)), r, s, {qx, qy})`.

  Deliberately NOT checked (also omitted on-chain by OZ): origin, rpIdHash,
  signature counter, extensions, attestation. The signed challenge binds the
  request; origin/RP are enforced by the authenticator + platform.
  """

  import Bitwise, only: [&&&: 2]

  alias Sovra.Crypto.P256

  @expected_type ~s("type":"webauthn.get")
  @expected_type_size byte_size(@expected_type)

  @up_bit 0x01
  @uv_bit 0x04
  @be_bit 0x08
  @bs_bit 0x10

  @typedoc """
  Parsed WebAuthn assertion. `r`/`s` are 32-byte binaries, `authenticator_data`
  and `client_data_json` raw binaries, the indices byte offsets into
  `client_data_json`.
  """
  @type assertion :: %{
          r: <<_::256>>,
          s: <<_::256>>,
          challenge_index: non_neg_integer(),
          type_index: non_neg_integer(),
          authenticator_data: binary(),
          client_data_json: binary()
        }

  @doc """
  Returns `true` iff `assertion` is a valid WebAuthn signature over `digest`
  by the P-256 key `{qx, qy}` (raw 32-byte coordinates).
  """
  @spec valid?(binary(), assertion(), {binary(), binary()}) :: boolean()
  def valid?(
        <<digest::binary-size(32)>>,
        %{} = sig,
        {<<qx::binary-size(32)>>, <<qy::binary-size(32)>>}
      ) do
    with {:r, <<r::binary-size(32)>>} <- {:r, Map.get(sig, :r)},
         {:s, <<s::binary-size(32)>>} <- {:s, Map.get(sig, :s)},
         %{
           authenticator_data: auth_data,
           client_data_json: cdj,
           challenge_index: ci,
           type_index: ti
         } <- sig,
         true <- is_binary(auth_data) and is_binary(cdj),
         true <- is_integer(ci) and ci >= 0 and is_integer(ti) and ti >= 0,
         :ok <- check_auth_data_length(auth_data),
         :ok <- check_type(cdj, ti),
         :ok <- check_challenge(cdj, ci, digest),
         flags = :binary.at(auth_data, 32),
         :ok <- check_user_present(flags),
         :ok <- check_user_verified(flags),
         :ok <- check_backup_state(flags) do
      message_hash = :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, cdj))
      P256.verify(message_hash, %{r: r, s: s}, {qx, qy})
    else
      _ -> false
    end
  end

  def valid?(_, _, _), do: false

  @doc """
  Parse the JSON wire form of a WebAuthn assertion (the shape the Aligned SDK
  produces and that holder proofs carry as their JWT third segment) into the
  `t:assertion/0` map. `r`/`s`/`authenticator_data` are `0x`-hex; the indices
  are integers; `client_data_json` is a UTF-8 string. Returns `:error` on any
  malformed field.
  """
  @spec parse_assertion(binary()) :: {:ok, assertion()} | :error
  def parse_assertion(json_bytes) when is_binary(json_bytes) do
    with {:ok, json} <- Jason.decode(json_bytes),
         %{
           "r" => r_hex,
           "s" => s_hex,
           "challenge_index" => ci,
           "type_index" => ti,
           "authenticator_data" => ad_hex,
           "client_data_json" => cdj
         } <- json,
         {:ok, <<r::binary-32>>} <- decode_hex(r_hex),
         {:ok, <<s::binary-32>>} <- decode_hex(s_hex),
         {:ok, ad} <- decode_hex(ad_hex),
         true <- is_integer(ci) and ci >= 0 and is_integer(ti) and ti >= 0 and is_binary(cdj) do
      {:ok,
       %{
         r: r,
         s: s,
         challenge_index: ci,
         type_index: ti,
         authenticator_data: ad,
         client_data_json: cdj
       }}
    else
      _ -> :error
    end
  end

  def parse_assertion(_), do: :error

  defp decode_hex("0x" <> hex), do: Base.decode16(hex, case: :mixed)
  defp decode_hex(hex) when is_binary(hex), do: Base.decode16(hex, case: :mixed)
  defp decode_hex(_), do: :error

  defp check_auth_data_length(auth_data) when byte_size(auth_data) >= 37, do: :ok
  defp check_auth_data_length(_), do: {:error, :authenticator_data_too_short}

  defp check_type(cdj, type_index) do
    if byte_size(cdj) >= type_index + @expected_type_size and
         binary_part(cdj, type_index, @expected_type_size) == @expected_type do
      :ok
    else
      {:error, :invalid_type}
    end
  end

  defp check_challenge(cdj, challenge_index, digest) do
    expected = ~s("challenge":") <> Base.url_encode64(digest, padding: false) <> ~s(")
    expected_size = byte_size(expected)

    if byte_size(cdj) >= challenge_index + expected_size and
         binary_part(cdj, challenge_index, expected_size) == expected do
      :ok
    else
      {:error, :invalid_challenge}
    end
  end

  defp check_user_present(flags) when (flags &&& @up_bit) == @up_bit, do: :ok
  defp check_user_present(_), do: {:error, :user_present_bit_unset}

  defp check_user_verified(flags) when (flags &&& @uv_bit) == @uv_bit, do: :ok
  defp check_user_verified(_), do: {:error, :user_verified_bit_unset}

  # Valid iff BE == 1 OR BS == 0 (the invalid state is "backed up but not
  # eligible for backup").
  defp check_backup_state(flags) do
    cond do
      (flags &&& @be_bit) == @be_bit -> :ok
      (flags &&& @bs_bit) == 0 -> :ok
      true -> {:error, :backup_state_inconsistent}
    end
  end
end
