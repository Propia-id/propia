defmodule Sovra.Cose.Sign1Test do
  use ExUnit.Case, async: true

  alias Sovra.Cbor
  alias Sovra.Cose.Key, as: CoseKey
  alias Sovra.Cose.Sign1
  alias Sovra.Crypto.SoftwareKeyStore

  @es256 -7

  setup do
    # SoftwareKeyStore holds real P-256 keys in ETS, so these are genuine
    # signatures verified against genuine public keys.
    {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} =
      SoftwareKeyStore.generate_key("cose-test-#{System.unique_integer([:positive])}")

    %{key_id: key_id, pub: {x, y}}
  end

  defp round_trip(sign1) do
    {:ok, decoded} = Cbor.decode(Cbor.encode(sign1))
    Sign1.parse(decoded)
  end

  describe "sign/5 and verify_es256/4" do
    test "an attached-payload signature verifies", %{key_id: key_id, pub: pub} do
      payload = Cbor.encode(%{"docType" => "io.sovra.test.1"})

      {:ok, sign1} = Sign1.sign(key_id, %{1 => @es256}, %{}, payload)
      {:ok, parsed} = round_trip(sign1)

      assert parsed.payload == payload
      assert Sign1.alg(parsed) == @es256
      assert :ok = Sign1.verify_es256(parsed, <<>>, nil, pub)
    end

    test "a detached-payload signature verifies against the covered bytes",
         %{key_id: key_id, pub: pub} do
      covered = Cbor.encode(["DeviceAuthentication", nil, "io.sovra.test.1"])

      {:ok, sign1} = Sign1.sign(key_id, %{1 => @es256}, %{}, nil, signed_payload: covered)
      {:ok, parsed} = round_trip(sign1)

      # Nothing on the wire, but the signature still covers `covered`.
      assert parsed.payload == nil
      assert :ok = Sign1.verify_es256(parsed, <<>>, covered, pub)
    end

    test "a detached signature fails against different covered bytes",
         %{key_id: key_id, pub: pub} do
      covered = Cbor.encode(["DeviceAuthentication", nil, "io.sovra.test.1"])
      other = Cbor.encode(["DeviceAuthentication", nil, "io.sovra.other.1"])

      {:ok, sign1} = Sign1.sign(key_id, %{1 => @es256}, %{}, nil, signed_payload: covered)
      {:ok, parsed} = round_trip(sign1)

      assert {:error, :invalid_signature} = Sign1.verify_es256(parsed, <<>>, other, pub)
    end

    test "verification fails against a different key", %{key_id: key_id} do
      {:ok, %{public_key_x: x, public_key_y: y}} = SoftwareKeyStore.generate_key("other-key")

      {:ok, sign1} = Sign1.sign(key_id, %{1 => @es256}, %{}, Cbor.encode("hello"))
      {:ok, parsed} = round_trip(sign1)

      assert {:error, :invalid_signature} = Sign1.verify_es256(parsed, <<>>, nil, {x, y})
    end
  end

  describe "tamper detection" do
    setup %{key_id: key_id} do
      payload = Cbor.encode(%{"valueDigests" => %{"ns" => %{0 => Cbor.bstr(<<1::256>>)}}})
      {:ok, sign1} = Sign1.sign(key_id, %{1 => @es256}, %{}, payload)
      %{sign1: sign1, payload: payload}
    end

    test "a modified payload fails", %{sign1: sign1, pub: pub} do
      [protected, unprotected, _payload, signature] = sign1
      tampered = [protected, unprotected, Cbor.bstr(Cbor.encode(%{"nope" => 1})), signature]

      {:ok, parsed} = round_trip(tampered)
      assert {:error, :invalid_signature} = Sign1.verify_es256(parsed, <<>>, nil, pub)
    end

    test "a modified protected header fails", %{sign1: sign1, pub: pub} do
      [_protected, unprotected, payload, signature] = sign1

      tampered = [
        Cbor.bstr(Cbor.encode(%{1 => @es256, 4 => "kid"})),
        unprotected,
        payload,
        signature
      ]

      {:ok, parsed} = round_trip(tampered)
      assert {:error, :invalid_signature} = Sign1.verify_es256(parsed, <<>>, nil, pub)
    end

    test "a modified signature fails", %{sign1: sign1, pub: pub} do
      [protected, unprotected, payload, %CBOR.Tag{value: sig}] = sign1
      <<first, rest::binary>> = sig
      flipped = <<Bitwise.bxor(first, 0xFF), rest::binary>>

      {:ok, parsed} = round_trip([protected, unprotected, payload, Cbor.bstr(flipped)])
      assert {:error, :invalid_signature} = Sign1.verify_es256(parsed, <<>>, nil, pub)
    end

    test "changing the unprotected header does NOT break the signature",
         %{sign1: sign1, pub: pub} do
      # RFC 9052: the unprotected header is outside Sig_structure. This is not a
      # flaw — it is why DeviceAuth can carry the WebAuthn envelope there, with
      # integrity coming from the challenge binding instead. Pinning it here so
      # nobody later "fixes" it by moving that data into the protected header.
      [protected, _unprotected, payload, signature] = sign1
      moved = [protected, %{"sovra_extra" => "anything"}, payload, signature]

      {:ok, parsed} = round_trip(moved)
      assert :ok = Sign1.verify_es256(parsed, <<>>, nil, pub)
    end
  end

  describe "alg/1" do
    test "reads the protected header only", %{key_id: key_id} do
      {:ok, sign1} = Sign1.sign(key_id, %{1 => @es256}, %{}, Cbor.encode(1))
      {:ok, parsed} = round_trip(sign1)
      assert Sign1.alg(parsed) == @es256
    end

    test "an alg in the unprotected header is ignored, not trusted", %{key_id: key_id, pub: pub} do
      # An attacker who could steer verification by setting alg in the
      # unsigned header would choose the weakest path. Empty protected header
      # must mean "no algorithm", never "look elsewhere".
      {:ok, [_p, _u, payload, signature]} =
        Sign1.sign(key_id, %{1 => @es256}, %{}, Cbor.encode(1))

      forged = [Cbor.bstr(<<>>), %{1 => @es256}, payload, signature]

      {:ok, parsed} = round_trip(forged)
      assert Sign1.alg(parsed) == nil
      assert {:error, :missing_cose_alg} = Sign1.verify_es256(parsed, <<>>, nil, pub)
    end

    test "an unexpected alg is rejected before any crypto runs", %{key_id: key_id, pub: pub} do
      {:ok, sign1} = Sign1.sign(key_id, %{1 => -35}, %{}, Cbor.encode(1))
      {:ok, parsed} = round_trip(sign1)

      assert {:error, :unexpected_cose_alg} = Sign1.verify_es256(parsed, <<>>, nil, pub)
    end
  end

  describe "parse/1" do
    test "keeps the protected header bytes verbatim", %{key_id: key_id} do
      # The decoder is lossy, so re-encoding the protected map could yield
      # different bytes and break Sig_structure. Prove we never do.
      protected = %{1 => @es256}
      {:ok, sign1} = Sign1.sign(key_id, protected, %{}, Cbor.encode(1))
      {:ok, parsed} = round_trip(sign1)

      assert parsed.protected_bytes == Cbor.encode(protected)
      assert parsed.protected == protected
    end

    test "rejects malformed structures" do
      assert {:error, :malformed_cose_sign1} = Sign1.parse("not an array")
      assert {:error, :malformed_cose_sign1} = Sign1.parse([1, 2, 3])
      assert {:error, :malformed_cose_sign1} = Sign1.parse([1, 2, 3, 4, 5])

      assert {:error, :malformed_cose_sign1} =
               Sign1.parse([Cbor.bstr(<<>>), "not a map", nil, Cbor.bstr(<<>>)])
    end
  end

  describe "Sovra.Cose.Key" do
    test "round-trips a P-256 point", %{pub: {x, y}} do
      key = CoseKey.p256(x, y)
      {:ok, decoded} = Cbor.decode(Cbor.encode(key))

      assert {:ok, {^x, ^y}} = CoseKey.parse_p256(decoded)
    end

    test "parses coordinates supplied as raw binaries", %{pub: {x, y}} do
      assert {:ok, {^x, ^y}} = CoseKey.parse_p256(%{1 => 2, -1 => 1, -2 => x, -3 => y})
    end

    test "rejects the wrong key type, curve, or coordinate size", %{pub: {x, y}} do
      assert {:error, :unsupported_cose_key} =
               CoseKey.parse_p256(%{1 => 1, -1 => 1, -2 => x, -3 => y})

      assert {:error, :unsupported_cose_key} =
               CoseKey.parse_p256(%{1 => 2, -1 => 2, -2 => x, -3 => y})

      assert {:error, :unsupported_cose_key} =
               CoseKey.parse_p256(%{1 => 2, -1 => 1, -2 => <<0>>, -3 => y})

      assert {:error, :unsupported_cose_key} = CoseKey.parse_p256(%{})
      assert {:error, :unsupported_cose_key} = CoseKey.parse_p256("nope")
    end

    test "encodes with canonical label ordering", %{pub: {x, y}} do
      # 1, -1, -2, -3 encode as 01, 20, 21, 22 — all one byte, so bytewise.
      <<0xA4, 0x01, 0x02, 0x20, 0x01, rest::binary>> = Cbor.encode(CoseKey.p256(x, y))
      assert <<0x21, 0x58, 0x20, ^x::binary-32, 0x22, 0x58, 0x20, ^y::binary-32>> = rest
    end
  end
end
