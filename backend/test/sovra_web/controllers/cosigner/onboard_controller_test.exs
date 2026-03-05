defmodule SovraWeb.Cosigner.OnboardControllerTest do
  use SovraWeb.ConnCase, async: true

  alias Sovra.Auth.MockAuthProvider

  describe "POST /api/v1/cosigner/onboard" do
    test "creates holder and returns server public key", %{conn: conn} do
      conn =
        post(conn, "/api/v1/cosigner/onboard", %{
          "sovraAddress" => "0xonboard_test",
          "oauthToken" => MockAuthProvider.valid_token()
        })

      assert %{"serverPublicKey" => %{"x" => x, "y" => y}} = json_response(conn, 201)
      assert is_binary(x)
      assert is_binary(y)
    end

    test "returns 409 for duplicate address", %{conn: conn} do
      params = %{
        "sovraAddress" => "0xdup_test",
        "oauthToken" => MockAuthProvider.valid_token()
      }

      post(conn, "/api/v1/cosigner/onboard", params)
      conn = post(conn, "/api/v1/cosigner/onboard", params)

      assert %{"error" => "already_onboarded"} = json_response(conn, 409)
    end

    test "returns 401 for invalid token", %{conn: conn} do
      conn =
        post(conn, "/api/v1/cosigner/onboard", %{
          "sovraAddress" => "0xinvalid_token",
          "oauthToken" => "bad-token"
        })

      assert %{"error" => "invalid_oauth_token"} = json_response(conn, 401)
    end

    test "returns 400 for missing fields", %{conn: conn} do
      conn = post(conn, "/api/v1/cosigner/onboard", %{})

      assert %{"error" => "missing_required_fields"} = json_response(conn, 400)
    end
  end
end
