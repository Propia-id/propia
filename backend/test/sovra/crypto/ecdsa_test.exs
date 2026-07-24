defmodule Sovra.Crypto.EcdsaTest do
  use ExUnit.Case, async: true

  alias Sovra.Crypto.Ecdsa

  @p256_n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  @k1_n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  test "keeps a low-s signature unchanged and pads short integers" do
    assert {:ok, {r, s}} = Ecdsa.parse_der_signature(der(3, 7), @p256_n)
    assert r == <<0::248, 3>>
    assert s == <<0::248, 7>>
  end

  test "normalizes a high-s signature to order - s for each curve's order" do
    for order <- [@p256_n, @k1_n] do
      assert {:ok, {_r, s}} = Ecdsa.parse_der_signature(der(3, order - 5), order)
      assert :binary.decode_unsigned(s) == 5
    end
  end

  test "trims the DER 0x00 sign-byte prefix from 33-byte integers" do
    # order - 1 has the high bit set, so its DER integer carries a 0x00 prefix.
    high = @k1_n - 1
    assert {:ok, {r, _s}} = Ecdsa.parse_der_signature(der(high, 7), @k1_n)
    assert byte_size(r) == 32
    assert :binary.decode_unsigned(r) == high
  end

  test "rejects malformed DER" do
    assert {:error, :bad_der_signature} = Ecdsa.parse_der_signature(<<1, 2, 3>>, @p256_n)
  end

  test "pad_or_trim pads, trims and passes exact sizes through" do
    assert Ecdsa.pad_or_trim(<<1>>, 4) == <<0, 0, 0, 1>>
    assert Ecdsa.pad_or_trim(<<0, 0, 1, 2, 3, 4>>, 4) == <<1, 2, 3, 4>>
    assert Ecdsa.pad_or_trim(<<1, 2, 3, 4>>, 4) == <<1, 2, 3, 4>>
  end

  # DER SEQUENCE { INTEGER r, INTEGER s } from integer values.
  defp der(r_int, s_int) do
    r = int(r_int)
    s = int(s_int)
    content = <<0x02, byte_size(r), r::binary, 0x02, byte_size(s), s::binary>>
    <<0x30, byte_size(content), content::binary>>
  end

  defp int(i) do
    bin = :binary.encode_unsigned(i)
    if match?(<<b, _::binary>> when b >= 0x80, bin), do: <<0, bin::binary>>, else: bin
  end
end
