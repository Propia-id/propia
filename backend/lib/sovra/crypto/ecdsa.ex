defmodule Sovra.Crypto.Ecdsa do
  @moduledoc """
  Curve-generic ECDSA signature helpers for curves with 32-byte coordinates.
  `Sovra.Crypto.P256` (secp256r1) and `Sovra.Crypto.Secp256k1` delegate here,
  passing their own group order, so DER-integer trimming and low-s
  normalization have exactly one implementation.
  """

  @coord_size 32

  @doc """
  Parse a DER `SEQUENCE { INTEGER r, INTEGER s }` ECDSA signature into 32-byte
  `{r, s}`, with `s` low-s normalized against the curve's group `order`.
  """
  @spec parse_der_signature(binary(), pos_integer()) ::
          {:ok, {binary(), binary()}} | {:error, :bad_der_signature}
  def parse_der_signature(
        <<0x30, _len, 0x02, r_len, r::binary-size(r_len), 0x02, s_len, s::binary-size(s_len)>>,
        order
      ) do
    {:ok, {pad_or_trim(r, @coord_size), low_s(pad_or_trim(s, @coord_size), order)}}
  end

  def parse_der_signature(_der, _order), do: {:error, :bad_der_signature}

  @doc "Pad to `size` (left with zeros) or trim leading bytes (DER 0x00 prefix)."
  def pad_or_trim(bin, size) when byte_size(bin) == size, do: bin

  def pad_or_trim(bin, size) when byte_size(bin) > size do
    <<_::binary-size(byte_size(bin) - size), trimmed::binary-size(size)>> = bin
    trimmed
  end

  def pad_or_trim(bin, size) when byte_size(bin) < size do
    padding = size - byte_size(bin)
    <<0::size(padding * 8), bin::binary>>
  end

  # If s > order/2, replace with order - s (low-s form; EIP-2 on secp256k1).
  defp low_s(s_bin, order) do
    s = :binary.decode_unsigned(s_bin)

    if s > div(order, 2) do
      (order - s) |> :binary.encode_unsigned() |> pad_or_trim(@coord_size)
    else
      s_bin
    end
  end
end
