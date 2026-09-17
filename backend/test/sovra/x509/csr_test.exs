defmodule Sovra.X509.CsrTest do
  @moduledoc """
  The encoder is checked against OTP's decoder rather than against itself.

  `:public_key` cannot *encode* a PKCS#10 request for an EC key, which is why
  `Sovra.X509.Csr` exists — but it decodes one perfectly well. That asymmetry
  gives a cross-implementation check for free: if our bytes are wrong, a parser
  we did not write says so.
  """
  use ExUnit.Case, async: true

  alias Sovra.Crypto.Key
  alias Sovra.X509.Csr

  setup do
    {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} = Key.generate_key("csr-test")
    %{key_id: key_id, point: {x, y}}
  end

  defp subject(overrides \\ []),
    do: Keyword.merge([country: "ES", common_name: "Sovra Document Signer"], overrides)

  defp decode(pem) do
    [{:CertificationRequest, der, :not_encrypted}] = :public_key.pem_decode(pem)
    {:public_key.der_decode(:CertificationRequest, der), der}
  end

  # The signed region is the first member of the outer SEQUENCE, taken verbatim.
  # Re-encoding the decoded record is exactly what OTP cannot do, so the bytes
  # are located by DER's own rules instead.
  defp request_info_bytes(der) do
    {_tag, body} = read_tlv(der)
    {info, _rest} = split_tlv(body)
    info
  end

  defp read_tlv(<<tag, rest::binary>>) do
    {length, body} = read_length(rest)
    <<value::binary-size(length), _::binary>> = body
    {tag, value}
  end

  defp split_tlv(<<_tag, rest::binary>> = tlv) do
    {length, body} = read_length(rest)
    header = byte_size(tlv) - byte_size(body)
    <<element::binary-size(header + length), remainder::binary>> = tlv
    {element, remainder}
  end

  # OTP releases disagree about whether a decoded attribute value arrives as a
  # term or as raw DER, which is exactly why the encoder does not rely on them.
  # Normalise both shapes to the string they carry.
  defp attribute_value(<<tag, length, rest::binary>>) when tag in [0x13, 0x0C],
    do: binary_part(rest, 0, length)

  defp attribute_value({_string_type, value}), do: value
  defp attribute_value(value) when is_list(value), do: List.to_string(value)

  defp read_length(<<n, rest::binary>>) when n < 128, do: {n, rest}

  defp read_length(<<n, rest::binary>>) do
    count = n - 128
    <<length_bytes::binary-size(count), body::binary>> = rest
    {:binary.decode_unsigned(length_bytes), body}
  end

  describe "build/3" do
    test "produces a request OTP's own decoder reads back", %{key_id: key_id, point: point} do
      assert {:ok, pem} = Csr.build(key_id, point, subject(state: "Cataluña"))
      assert pem =~ "BEGIN CERTIFICATE REQUEST"

      {{:CertificationRequest, info, algorithm, _signature}, _der} = decode(pem)
      {:CertificationRequestInfo, :v1, {:rdnSequence, rdns}, _spki, _attrs} = info

      # ecdsa-with-SHA256
      assert {:CertificationRequest_signatureAlgorithm, {1, 2, 840, 10045, 4, 3, 2}, _} =
               algorithm

      values =
        for [{:AttributeTypeAndValue, oid, value}] <- rdns, do: {oid, attribute_value(value)}

      assert values == [
               {{2, 5, 4, 6}, "ES"},
               {{2, 5, 4, 8}, "Cataluña"},
               {{2, 5, 4, 3}, "Sovra Document Signer"}
             ]
    end

    test "carries the key it was built for", %{key_id: key_id, point: {x, y} = point} do
      assert {:ok, pem} = Csr.build(key_id, point, subject())
      [{:CertificationRequest, der, :not_encrypted}] = :public_key.pem_decode(pem)

      # The DER for id-ecPublicKey and prime256v1, written out rather than
      # produced by the encoder under test — a check against our own output is
      # not a check at all.
      assert :binary.match(der, <<0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01>>) !=
               :nomatch

      assert :binary.match(der, <<0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07>>) !=
               :nomatch

      # Uncompressed point, the only form 18013-5 uses.
      assert :binary.match(der, <<0x04>> <> x <> y) != :nomatch
    end

    test "self-signs with the requested key, proving possession", %{
      key_id: key_id,
      point: {x, y} = point
    } do
      assert {:ok, pem} = Csr.build(key_id, point, subject())
      {{:CertificationRequest, _info, _algorithm, signature}, der} = decode(pem)

      # A certification request is only meaningful if the signature is over the
      # request it travels with, made by the key it names — that is the entire
      # proof-of-possession. Verified with OTP's crypto, not ours.
      assert :crypto.verify(
               :ecdsa,
               :sha256,
               request_info_bytes(der),
               signature,
               [<<0x04>> <> x <> y, :secp256r1]
             )
    end

    test "omits optional fields rather than emitting empty ones", %{
      key_id: key_id,
      point: point
    } do
      assert {:ok, pem} = Csr.build(key_id, point, subject(state: nil, organization: ""))
      {{:CertificationRequest, info, _algorithm, _signature}, _der} = decode(pem)
      {:CertificationRequestInfo, :v1, {:rdnSequence, rdns}, _spki, _attrs} = info

      oids = for [{:AttributeTypeAndValue, oid, _value}] <- rdns, do: oid
      assert oids == [{2, 5, 4, 6}, {2, 5, 4, 3}]
    end
  end

  describe "subject validation" do
    test "requires a country, because Annex B does", %{key_id: key_id, point: point} do
      assert {:error, {:missing_subject_field, :country}} =
               Csr.build(key_id, point, common_name: "No Country")
    end

    test "requires the country to be ISO 3166-1 alpha-2", %{key_id: key_id, point: point} do
      # A CA rejects anything else, and discovering that after the operator has
      # taken the request away is a slow way to learn it.
      for bad <- ["esp", "es", "Spain", "E"] do
        assert {:error, {:invalid_subject, :country}} =
                 Csr.build(key_id, point, subject(country: bad))
      end
    end

    test "requires a common name", %{key_id: key_id, point: point} do
      assert {:error, {:missing_subject_field, :common_name}} =
               Csr.build(key_id, point, country: "ES", common_name: "   ")
    end
  end
end
