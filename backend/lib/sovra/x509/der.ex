defmodule Sovra.X509.Der do
  @moduledoc """
  The DER primitives X.509 structures need here, and no more.

  OTP's `:public_key` already encodes most of X.509, and this module exists for
  the one place it cannot. PKCS#10's ASN.1 information-object set has no entry
  for `id-ecPublicKey`, so `:public_key.der_encode(:CertificationRequest, ...)`
  fails on any EC key — while `der_decode/2` reads the same structure back
  without complaint. Assembling the two SEQUENCEs by hand is far smaller than
  the alternatives, and it keeps the signature step external, which is the whole
  point when the private key lives in KMS.

  Everything here is definite-length and shortest-form, the only encoding DER
  permits. That matters for the same reason it matters in `Sovra.Cbor`: these
  bytes get hashed and signed, so a second encoder that made different length
  choices would produce a structure that verifies against nothing.
  """

  import Bitwise

  @doc "A constructed SEQUENCE wrapping already-encoded members."
  @spec sequence(iodata()) :: binary()
  def sequence(members), do: tlv(0x30, IO.iodata_to_binary(members))

  @doc """
  A constructed context-specific tag, for slots like PKCS#10's `[0]` attributes.

  Implicit tagging: the caller supplies the members, and the context tag
  replaces the underlying type's own rather than wrapping it.
  """
  @spec context(0..30, iodata()) :: binary()
  def context(tag, members) when tag in 0..30,
    do: tlv(0xA0 ||| tag, IO.iodata_to_binary(members))

  @doc "A non-negative INTEGER, minimally encoded."
  @spec integer(non_neg_integer()) :: binary()
  def integer(n) when is_integer(n) and n >= 0,
    do: n |> :binary.encode_unsigned() |> unsigned_integer()

  @doc """
  A BIT STRING with no unused trailing bits.

  Every bit string X.509 puts a signature or a key in is whole-octet, so the
  unused-bits octet is always zero. Anything else would need a different
  function rather than an option, because a caller that got it wrong would
  produce a structure that parses and means something else.
  """
  @spec bit_string(binary()) :: binary()
  def bit_string(bytes) when is_binary(bytes), do: tlv(0x03, <<0>> <> bytes)

  @doc """
  An OBJECT IDENTIFIER from its arc tuple.

  The first two arcs pack into a single octet; the rest are base-128 with the
  continuation bit set on every octet but the last.
  """
  @spec oid(tuple()) :: binary()
  def oid(arcs) when is_tuple(arcs) and tuple_size(arcs) >= 2 do
    [first, second | rest] = Tuple.to_list(arcs)
    tlv(0x06, IO.iodata_to_binary([<<first * 40 + second>> | Enum.map(rest, &base128/1)]))
  end

  @doc """
  An `ECDSA-Sig-Value` from the raw `r` and `s` a signer returns.

  KMS-style signers hand back fixed-width coordinates; DER wants minimally
  encoded two's-complement integers. Getting this wrong yields a signature that
  is rejected as malformed rather than as invalid, which is a much harder error
  to read.
  """
  @spec ecdsa_signature(binary(), binary()) :: binary()
  def ecdsa_signature(r, s) when is_binary(r) and is_binary(s),
    do: sequence([unsigned_integer(r), unsigned_integer(s)])

  @doc "A SET, which X.509 uses for the attributes of a distinguished name."
  @spec set(iodata()) :: binary()
  def set(members), do: tlv(0x31, IO.iodata_to_binary(members))

  @doc """
  A PrintableString.

  X.509 restricts this to a small ASCII subset, and a country code is the only
  place this module needs it — every other name component is a UTF8String.
  """
  @spec printable_string(String.t()) :: binary()
  def printable_string(value) when is_binary(value), do: tlv(0x13, value)

  @doc "A UTF8String, the modern default for a directory-name component."
  @spec utf8_string(String.t()) :: binary()
  def utf8_string(value) when is_binary(value), do: tlv(0x0C, value)

  @doc "A raw tag/length/value triple, for structures this module has no name for."
  @spec tlv(byte(), binary()) :: binary()
  def tlv(tag, body) when is_integer(tag) and is_binary(body),
    do: <<tag>> <> length_octets(byte_size(body)) <> body

  # ── Internals ───────────────────────────────────────────

  # DER INTEGER is two's complement, so a positive value whose leading octet has
  # the high bit set needs a zero octet in front or it reads as negative.
  defp unsigned_integer(bytes) do
    trimmed = trim_leading_zeros(bytes)

    case trimmed do
      <<first, _::binary>> when first >= 0x80 -> tlv(0x02, <<0>> <> trimmed)
      _ -> tlv(0x02, trimmed)
    end
  end

  # Stops at one octet: the integer zero encodes as a single zero byte, not as
  # an empty one.
  defp trim_leading_zeros(<<0, rest::binary>>) when byte_size(rest) > 0,
    do: trim_leading_zeros(rest)

  defp trim_leading_zeros(bytes), do: bytes

  defp length_octets(n) when n < 128, do: <<n>>

  defp length_octets(n) do
    bytes = :binary.encode_unsigned(n)
    <<0x80 ||| byte_size(bytes)>> <> bytes
  end

  defp base128(n) when n < 128, do: <<n>>

  defp base128(n) do
    digits = Integer.digits(n, 128)
    {leading, [last]} = Enum.split(digits, -1)
    IO.iodata_to_binary(Enum.map(leading, &<<&1 ||| 0x80>>) ++ [<<last>>])
  end
end
