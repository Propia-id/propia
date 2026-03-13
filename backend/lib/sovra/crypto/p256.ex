defmodule Sovra.Crypto.P256 do
  @moduledoc """
  P-256 (secp256r1) key operations using Erlang :crypto.
  """

  @curve :secp256r1
  @coord_size 32
  # P-256 curve order
  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  @doc """
  Generates a new P-256 key pair.
  Returns `{:ok, %{private_key: binary, public_key_x: binary, public_key_y: binary}}`.
  """
  def generate_key_pair do
    {pub, priv} = :crypto.generate_key(:ecdh, @curve)
    <<4, x::binary-size(@coord_size), y::binary-size(@coord_size)>> = pub
    {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}}
  end

  @doc """
  Signs a 32-byte hash with a P-256 private key.
  Returns `{:ok, %{r: binary, s: binary}}`.
  """
  def sign(<<hash::binary-size(32)>>, private_key) when is_binary(private_key) do
    der = :crypto.sign(:ecdsa, :sha256, {:digest, hash}, [private_key, @curve])
    %{r: r, s: s} = der_to_rs(der)
    {:ok, %{r: r, s: normalize_s(s)}}
  end

  def sign(_hash, _private_key), do: {:error, :invalid_hash_size}

  @doc """
  Verifies a P-256 signature against a 32-byte hash and public key coordinates.
  """
  def verify(<<hash::binary-size(32)>>, %{r: r, s: s}, {pub_x, pub_y})
      when byte_size(pub_x) == @coord_size and byte_size(pub_y) == @coord_size do
    der = rs_to_der(r, s)
    pub = <<4, pub_x::binary, pub_y::binary>>
    :crypto.verify(:ecdsa, :sha256, {:digest, hash}, der, [pub, @curve])
  end

  def verify(_hash, _signature, _public_key), do: false

  # DER decode: SEQUENCE { INTEGER r, INTEGER s }
  defp der_to_rs(
         <<0x30, _len, 0x02, r_len, r_raw::binary-size(r_len), 0x02, s_len,
           s_raw::binary-size(s_len)>>
       ) do
    %{r: pad_or_trim(r_raw, @coord_size), s: pad_or_trim(s_raw, @coord_size)}
  end

  defp rs_to_der(r, s) do
    r_int = encode_der_integer(r)
    s_int = encode_der_integer(s)
    content = <<0x02, byte_size(r_int), r_int::binary, 0x02, byte_size(s_int), s_int::binary>>
    <<0x30, byte_size(content), content::binary>>
  end

  # Strip leading zeros, then add 0x00 prefix if high bit set (DER signed integer)
  defp encode_der_integer(bin) do
    bin = bin |> :binary.bin_to_list() |> Enum.drop_while(&(&1 == 0)) |> :binary.list_to_bin()

    if bin == <<>> do
      <<0>>
    else
      <<first, _::binary>> = bin
      if Bitwise.band(first, 0x80) != 0, do: <<0, bin::binary>>, else: bin
    end
  end

  # Ensure low-S: if s > n/2, replace with n - s
  defp normalize_s(s_bin) do
    s = :binary.decode_unsigned(s_bin)
    half_n = div(@n, 2)

    if s > half_n do
      (@n - s) |> :binary.encode_unsigned() |> pad_or_trim(@coord_size)
    else
      s_bin
    end
  end

  @doc """
  Pad to size (left with zeros) or trim leading zero bytes.
  """
  def pad_or_trim(bin, size) when byte_size(bin) == size, do: bin

  def pad_or_trim(bin, size) when byte_size(bin) > size do
    # Strip leading zero bytes (DER integer may have 0x00 prefix)
    <<_::binary-size(byte_size(bin) - size), trimmed::binary-size(size)>> = bin
    trimmed
  end

  def pad_or_trim(bin, size) when byte_size(bin) < size do
    padding = size - byte_size(bin)
    <<0::size(padding * 8), bin::binary>>
  end
end
