defmodule SovraWeb.Guardian.OnboardControllerTest do
  use SovraWeb.ConnCase, async: true

  alias Sovra.Auth.MockAuthProvider

  import Sovra.GuardianHelpers

  describe "POST /api/v1/holder/onboard" do
    test "creates holder and returns recovery public key", %{conn: conn} do
      conn =
        post(conn, "/api/v1/holder/onboard", %{
          "sovraAddress" => test_address("onboard_test"),
          "oauthToken" => MockAuthProvider.valid_token()
        })

      assert %{"recoveryPublicKey" => %{"x" => x, "y" => y}} = json_response(conn, 201)
      assert is_binary(x)
      assert is_binary(y)
    end

    test "returns 409 for duplicate address", %{conn: conn} do
      post(conn, "/api/v1/holder/onboard", %{
        "sovraAddress" => test_address("dup_test"),
        "oauthToken" => MockAuthProvider.valid_token()
      })

      conn =
        post(conn, "/api/v1/holder/onboard", %{
          "sovraAddress" => test_address("dup_test"),
          "oauthToken" => MockAuthProvider.valid_token_2()
        })

      assert %{"error" => "already_onboarded"} = json_response(conn, 409)
    end

    test "returns 200 login for same google account on different device", %{conn: conn} do
      addr_a = test_address("ctrl_device_a")
      addr_b = test_address("ctrl_device_b")

      post(conn, "/api/v1/holder/onboard", %{
        "sovraAddress" => addr_a,
        "oauthToken" => MockAuthProvider.valid_token()
      })

      conn =
        post(conn, "/api/v1/holder/onboard", %{
          "sovraAddress" => addr_b,
          "oauthToken" => MockAuthProvider.valid_token()
        })

      response = json_response(conn, 200)
      assert response["sovraAddress"] == addr_a
      assert is_binary(response["sessionToken"])
      refute Map.has_key?(response, "recoveryPublicKey")
    end

    test "returns 401 for invalid token", %{conn: conn} do
      conn =
        post(conn, "/api/v1/holder/onboard", %{
          "sovraAddress" => test_address("invalid_token"),
          "oauthToken" => "bad-token"
        })

      assert %{"error" => "invalid_oauth_token"} = json_response(conn, 401)
    end

    test "returns 400 for missing fields", %{conn: conn} do
      conn = post(conn, "/api/v1/holder/onboard", %{})

      assert %{"error" => "missing_required_fields"} = json_response(conn, 400)
    end
  end
end
