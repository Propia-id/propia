defmodule Sovra.Auth.SessionTest do
  use ExUnit.Case, async: true

  alias Sovra.Auth.Session

  @test_address "0x" <> String.duplicate("ab", 20)

  describe "create/1 and verify/1" do
    test "round-trip succeeds and returns iat" do
      {:ok, token} = Session.create(@test_address)
      {:ok, %{sovra_address: address, iat: iat}} = Session.verify(token)

      assert address == @test_address
      assert is_integer(iat)
      assert iat <= System.system_time(:second)
    end

    test "rejects tampered token" do
      {:ok, token} = Session.create(@test_address)
      tampered = token <> "x"

      assert {:error, :invalid} = Session.verify(tampered)
    end

    test "rejects token with wrong secret" do
      {:ok, token} = Session.create(@test_address)

      # Manually create a token with a different secret
      jwk = JOSE.JWK.from_oct("wrong-secret-that-is-at-least-32-bytes-long!!")
      jws = %{"alg" => "HS256"}

      claims = %{
        "sub" => "0x" <> String.duplicate("ee", 20),
        "scope" => "guardian",
        "iss" => "sovra-guardian",
        "aud" => "sovra-guardian",
        "jti" => "test",
        "iat" => System.system_time(:second),
        "exp" => System.system_time(:second) + 900
      }

      {_, bad_token} = JOSE.JWT.sign(jwk, jws, claims) |> JOSE.JWS.compact()

      assert {:error, :invalid} = Session.verify(bad_token)

      # Original still works
      assert {:ok, _} = Session.verify(token)
    end

    test "rejects token without iss/aud claims" do
      jwk = Sovra.Auth.KeyDerivation.derive_key(:guardian_session) |> JOSE.JWK.from_oct()
      jws = %{"alg" => "HS256"}

      claims = %{
        "sub" => @test_address,
        "scope" => "guardian",
        "iat" => System.system_time(:second),
        "exp" => System.system_time(:second) + 900
      }

      {_, token} = JOSE.JWT.sign(jwk, jws, claims) |> JOSE.JWS.compact()

      assert {:error, :invalid} = Session.verify(token)
    end
  end
end
