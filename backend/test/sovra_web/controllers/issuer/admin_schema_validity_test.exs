defmodule SovraWeb.Issuer.AdminSchemaValidityTest do
  @moduledoc """
  Covers the `validity_period` contract on `POST/PUT /dashboard/issuer/schemas`.

  How long a credential stays valid is never guessed: the caller states a
  period or sends an explicit `null` for no expiry. Anything else — an omitted
  key, a non-string, an unparseable or zero-length period — is a 422.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Auth.UserSession
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces

  defp user do
    {:ok, account} =
      User.admin_changeset(%{
        email: "owner-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    account
  end

  defp org do
    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    org
  end

  defp setup_workspace do
    owner = user()
    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org().id, %{name: "Acme"}, owner.id)
    %{workspace: provision_workspace(ws), owner: owner}
  end

  defp authed(conn, user, workspace_id) do
    {:ok, token} = UserSession.create(user.id, workspace_id, user.is_admin)
    put_req_header(conn, "authorization", "Bearer #{token}")
  end

  defp base_params do
    %{
      "schema_id" => "s-#{System.unique_integer([:positive])}",
      "credential_type" => "TestCredential#{System.unique_integer([:positive])}",
      "name" => "Test",
      "claims" => [
        %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
      ]
    }
  end

  describe "POST /dashboard/issuer/schemas — validity_period" do
    test "omitting the field is a 422 rather than a silent default", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()

      body =
        conn
        |> authed(owner, ws.id)
        |> post("/dashboard/issuer/schemas", base_params())
        |> json_response(422)

      assert body["error"] == "validation_error"
      assert [message] = body["details"]["validity_period"]
      assert message =~ "is required"
    end

    # `to_string/1` raises on a map, so this reached the client as a 500 before
    # the type guard.
    test "a non-string period is a 422, not a 500", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()

      for value <- [%{"a" => 1}, [1, 2], 12, true] do
        body =
          conn
          |> authed(owner, ws.id)
          |> post(
            "/dashboard/issuer/schemas",
            Map.put(base_params(), "validity_period", value)
          )
          |> json_response(422)

        assert body["error"] == "validation_error",
               "expected 422 for #{inspect(value)}"
      end
    end

    test "a zero-length period is rejected", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()

      for value <- ["0d", "0y", "0m"] do
        body =
          conn
          |> authed(owner, ws.id)
          |> post(
            "/dashboard/issuer/schemas",
            Map.put(base_params(), "validity_period", value)
          )
          |> json_response(422)

        assert body["details"]["validity_period"] == ["has invalid format"],
               "expected rejection for #{value}"
      end
    end

    test "an explicit null opts the schema out of expiry", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()

      body =
        conn
        |> authed(owner, ws.id)
        |> post(
          "/dashboard/issuer/schemas",
          Map.put(base_params(), "validity_period", nil)
        )
        |> json_response(201)

      assert body["validity_period"] == nil
    end

    test "an explicit period is passed through", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()

      body =
        conn
        |> authed(owner, ws.id)
        |> post(
          "/dashboard/issuer/schemas",
          Map.put(base_params(), "validity_period", "6m")
        )
        |> json_response(201)

      assert body["validity_period"] == "6m"
    end

    # Ecto treats "" — and any whitespace-only string — as an empty value and
    # casts it to the field default, so before the dedicated cast this reached
    # the database as nil: a never-expiring schema produced by clearing the
    # dashboard's Validity input without ticking "No expiry".
    test "a blank period is rejected rather than read as no expiry", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()

      for value <- ["", " ", "   ", "\t"] do
        body =
          conn
          |> authed(owner, ws.id)
          |> post(
            "/dashboard/issuer/schemas",
            Map.put(base_params(), "validity_period", value)
          )
          |> json_response(422)

        assert body["details"]["validity_period"] == ["has invalid format"],
               "expected rejection for #{inspect(value)}"
      end
    end

    test "an unparseable period is a 422, not a silent 1y", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()

      body =
        conn
        |> authed(owner, ws.id)
        |> post(
          "/dashboard/issuer/schemas",
          Map.put(base_params(), "validity_period", "1yr")
        )
        |> json_response(422)

      assert body["error"] == "validation_error"
      assert body["details"]["validity_period"] == ["has invalid format"]
    end
  end

  describe "PUT /dashboard/issuer/schemas/:schema_id — validity_period" do
    test "a revision can drop the expiry a prior version set", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()
      params = base_params()

      v1 =
        conn
        |> authed(owner, ws.id)
        |> post("/dashboard/issuer/schemas", Map.put(params, "validity_period", "1y"))
        |> json_response(201)

      assert v1["validity_period"] == "1y"

      v2 =
        conn
        |> authed(owner, ws.id)
        |> put("/dashboard/issuer/schemas/#{params["schema_id"]}", %{
          "base_version" => 1,
          "name" => "Test v2",
          "claims" => params["claims"],
          "validity_period" => nil
        })
        |> json_response(201)

      assert v2["version"] == 2
      assert v2["validity_period"] == nil
    end

    test "a blank period on a revision is a 422, not a dropped expiry", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()
      params = base_params()

      conn
      |> authed(owner, ws.id)
      |> post("/dashboard/issuer/schemas", Map.put(params, "validity_period", "1y"))
      |> json_response(201)

      body =
        conn
        |> authed(owner, ws.id)
        |> put("/dashboard/issuer/schemas/#{params["schema_id"]}", %{
          "base_version" => 1,
          "name" => "Test v2",
          "claims" => params["claims"],
          "validity_period" => ""
        })
        |> json_response(422)

      assert body["details"]["validity_period"] == ["has invalid format"]

      # The prior version is untouched: no revision was inserted.
      %{"schemas" => [latest]} =
        conn
        |> authed(owner, ws.id)
        |> get("/dashboard/issuer/schemas")
        |> json_response(200)

      assert latest["version"] == 1
      assert latest["validity_period"] == "1y"
    end

    test "omitting the field on a revision is a 422", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()
      params = base_params()

      conn
      |> authed(owner, ws.id)
      |> post("/dashboard/issuer/schemas", Map.put(params, "validity_period", "1y"))
      |> json_response(201)

      body =
        conn
        |> authed(owner, ws.id)
        |> put("/dashboard/issuer/schemas/#{params["schema_id"]}", %{
          "base_version" => 1,
          "name" => "Test v2",
          "claims" => params["claims"]
        })
        |> json_response(422)

      assert [message] = body["details"]["validity_period"]
      assert message =~ "is required"
    end

    test "a revision can add an expiry a prior version omitted", %{conn: conn} do
      %{workspace: ws, owner: owner} = setup_workspace()
      params = base_params()

      conn
      |> authed(owner, ws.id)
      |> post("/dashboard/issuer/schemas", Map.put(params, "validity_period", nil))
      |> json_response(201)

      v2 =
        conn
        |> authed(owner, ws.id)
        |> put("/dashboard/issuer/schemas/#{params["schema_id"]}", %{
          "base_version" => 1,
          "name" => "Test v2",
          "claims" => params["claims"],
          "validity_period" => "2y"
        })
        |> json_response(201)

      assert v2["validity_period"] == "2y"
    end
  end
end
