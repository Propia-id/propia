defmodule Sovra.Credentials.BitstringStatusListTest do
  use Sovra.DataCase, async: false

  import Bitwise

  alias Sovra.Credentials.BitstringStatusList
  alias Sovra.Credentials.SDJWT, as: SDJWTReader

  defp create_workspace, do: fixture_workspace().workspace

  describe "encode/1" do
    test "round-trips uint256 words through gzip+base64url with multibase 'u' prefix" do
      words = [0, 1 <<< 200, 0xFFFF_FFFF_FFFF_FFFF]

      "u" <> b64 = BitstringStatusList.encode(words)
      {:ok, gz} = Base.url_decode64(b64, padding: false)
      raw = :zlib.gunzip(gz)

      assert byte_size(raw) == 32 * length(words)
      assert <<0::unsigned-big-256, w1::unsigned-big-256, w2::unsigned-big-256>> = raw
      assert w1 == 1 <<< 200
      assert w2 == 0xFFFF_FFFF_FFFF_FFFF
    end
  end

  describe "build_signed_credential/3" do
    test "returns a 3-segment JWT signed by the workspace P-256 key" do
      ws = create_workspace()
      encoded = BitstringStatusList.encode([0])

      {:ok, jwt} = BitstringStatusList.build_signed_credential(ws, "revocation", encoded)

      assert [_, _, _] = String.split(jwt, ".")

      assert :ok =
               SDJWTReader.verify_issuer_signature(jwt, %{
                 x: ws.signing_public_key_x,
                 y: ws.signing_public_key_y
               })
    end

    test "header is ES256/JWT and payload is VC-JWT 1.1 shape" do
      ws = create_workspace()
      encoded = BitstringStatusList.encode([0])

      {:ok, jwt} = BitstringStatusList.build_signed_credential(ws, "suspension", encoded)
      {:ok, %{header: header, payload: payload}} = SDJWTReader.decode_jwt(jwt)

      assert header["alg"] == "ES256"
      assert header["typ"] == "JWT"

      assert payload["iss"] == ws.did
      assert payload["sub"] == "#{ws.did}/status/suspension"
      assert is_integer(payload["iat"])
      # iat is quantized to a 5-minute bucket
      assert rem(payload["iat"], 300) == 0

      vc = payload["vc"]
      assert "BitstringStatusListCredential" in vc["type"]
      assert vc["issuer"] == ws.did
      assert vc["credentialSubject"]["statusPurpose"] == "suspension"
      assert vc["credentialSubject"]["encodedList"] == encoded
    end

    test "two consecutive builds within the same 5-min window produce identical signing input" do
      ws = create_workspace()
      encoded = BitstringStatusList.encode([1, 2, 3])

      {:ok, j1} = BitstringStatusList.build_signed_credential(ws, "revocation", encoded)
      {:ok, j2} = BitstringStatusList.build_signed_credential(ws, "revocation", encoded)

      [h1, p1, _] = String.split(j1, ".")
      [h2, p2, _] = String.split(j2, ".")
      # ES256 signatures are non-deterministic; ETag stability comes from a
      # stable signing input (header + payload), guaranteed by quantising
      # iat to a 5-minute bucket. The signature bytes will differ.
      assert {h1, p1} == {h2, p2}
    end

    test "different bitmaps produce different JWTs" do
      ws = create_workspace()

      {:ok, j1} =
        BitstringStatusList.build_signed_credential(
          ws,
          "revocation",
          BitstringStatusList.encode([0])
        )

      {:ok, j2} =
        BitstringStatusList.build_signed_credential(
          ws,
          "revocation",
          BitstringStatusList.encode([1])
        )

      refute j1 == j2
    end
  end
end
