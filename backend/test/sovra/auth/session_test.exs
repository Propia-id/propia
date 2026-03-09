defmodule Sovra.Auth.SessionTest do
  use ExUnit.Case, async: true

  alias Sovra.Auth.Session

  describe "create/1 and verify/1" do
    test "round-trip succeeds" do
      {:ok, token} = Session.create("0xabc123")
      {:ok, %{sovra_address: address}} = Session.verify(token)

      assert address == "0xabc123"
    end

    test "rejects tampered token" do
      {:ok, token} = Session.create("0xabc123")
      tampered = token <> "x"

      assert {:error, :invalid} = Session.verify(tampered)
    end

    test "rejects token with wrong secret" do
      {:ok, token} = Session.create("0xabc123")

      # Manually create a token with a different secret
      jwk = JOSE.JWK.from_oct("wrong-secret-that-is-at-least-32-bytes-long!!")
      jws = %{"alg" => "HS256"}

      claims = %{
        "sub" => "0xhacker",
        "scope" => "cosign",
        "exp" => System.system_time(:second) + 900
      }

      {_, bad_token} = JOSE.JWT.sign(jwk, jws, claims) |> JOSE.JWS.compact()

      assert {:error, :invalid} = Session.verify(bad_token)

      # Original still works
      assert {:ok, _} = Session.verify(token)
    end
  end
end
