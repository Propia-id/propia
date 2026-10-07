defmodule SovraWeb.Issuer.OfferControllerTest do
  use SovraWeb.ConnCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Auth.UserSession
  alias Sovra.Issuer
  alias Sovra.Workspaces.ApiKeys

  defp create_user, do: fixture_user()

  defp create_workspace do
    %{workspace: ws, owner: user} = fixture_workspace(name: "Acme")
    %{workspace: provision_workspace(ws), user: user}
  end

  defp create_schema(workspace_id) do
    {:ok, schema} =
      Issuer.create_schema(workspace_id, %{
        schema_id: "test-#{System.unique_integer([:positive])}",
        credential_type: "TestCredential",
        name: "Test",
        claims: [
          %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
        ],
        validity_period: "1y"
      })

    schema
  end

  describe "POST /dashboard/issuer/offers (JWT path)" do
    test "201 with the unified response shape", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)

      {:ok, token} = UserSession.create(user.id, ws.id, user.is_admin)

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> post("/dashboard/issuer/offers", %{
          "schema_id" => schema.schema_id,
          "claims" => %{"name" => "Alice"}
        })
        |> json_response(201)

      assert resp["credential_id"]
      assert resp["offer_uri"]
      assert resp["pre_authorized_code"]
      assert resp["expires_at"]
    end
  end

  describe "valid_until on the offer request" do
    # Absent and null are kept distinct, exactly as they are for a schema's
    # `validity_period`: omit the key to derive expiry from the schema, or state
    # an absolute instant. Anything else is a 422 rather than a silently
    # substituted default.

    defp authed_post(conn, ws, user, params) do
      {:ok, token} = UserSession.create(user.id, ws.id, user.is_admin)

      conn
      |> put_req_header("authorization", "Bearer #{token}")
      |> post("/dashboard/issuer/offers", params)
    end

    defp offer_params(schema, extra \\ %{}) do
      Map.merge(
        %{"schema_id" => schema.schema_id, "claims" => %{"name" => "Alice"}},
        extra
      )
    end

    test "201 and the preview carries the requested instant", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)
      valid_until = DateTime.add(DateTime.utc_now(), 400, :day) |> DateTime.truncate(:second)

      resp =
        conn
        |> authed_post(
          ws,
          user,
          offer_params(schema, %{
            "valid_until" => DateTime.to_iso8601(valid_until)
          })
        )
        |> json_response(201)

      assert resp["credential"]["exp"] == DateTime.to_unix(valid_until)
    end

    test "an offset is honoured, not read as UTC", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)
      valid_until = DateTime.add(DateTime.utc_now(), 400, :day) |> DateTime.truncate(:second)

      # The same instant, written as the wall-clock time three hours west of UTC.
      shifted =
        valid_until
        |> DateTime.add(-3 * 3600, :second)
        |> DateTime.to_iso8601()
        |> String.replace("Z", "-03:00")

      resp =
        conn
        |> authed_post(ws, user, offer_params(schema, %{"valid_until" => shifted}))
        |> json_response(201)

      assert resp["credential"]["exp"] == DateTime.to_unix(valid_until)
    end

    test "422 for a date in the past", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)
      past = DateTime.add(DateTime.utc_now(), -1, :day) |> DateTime.to_iso8601()

      resp =
        conn
        |> authed_post(ws, user, offer_params(schema, %{"valid_until" => past}))
        |> json_response(422)

      assert resp["error"] == "invalid_valid_until"
      assert resp["details"] =~ "future"
    end

    test "422 for an unparseable string", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)

      resp =
        conn
        |> authed_post(ws, user, offer_params(schema, %{"valid_until" => "next tuesday"}))
        |> json_response(422)

      assert resp["error"] == "invalid_valid_until"
    end

    test "422 for an explicit null rather than falling back to the schema", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)

      resp =
        conn
        |> authed_post(ws, user, offer_params(schema, %{"valid_until" => nil}))
        |> json_response(422)

      assert resp["error"] == "invalid_valid_until"
    end

    test "422 for a non-string, which to_string/1 would otherwise raise on", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)

      resp =
        conn
        |> authed_post(ws, user, offer_params(schema, %{"valid_until" => %{}}))
        |> json_response(422)

      assert resp["error"] == "invalid_valid_until"
    end

    test "omitting the key keeps the schema-derived expiry", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)

      resp =
        conn
        |> authed_post(ws, user, offer_params(schema))
        |> json_response(201)

      exp = resp["credential"]["exp"]
      assert exp == resp["credential"]["iat"] + 365 * 86_400
    end

    test "the API key path enforces the same contract", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      schema = create_schema(ws.id)
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")
      past = DateTime.add(DateTime.utc_now(), -1, :day) |> DateTime.to_iso8601()

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/issuer/credential-offer", offer_params(schema, %{"valid_until" => past}))
        |> json_response(422)

      assert resp["error"] == "invalid_valid_until"
    end
  end

  describe "POST /api/v1/issuer/credential-offer (API key path)" do
    test "201 with the unified response shape", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      schema = create_schema(ws.id)
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/issuer/credential-offer", %{
          "schema_id" => schema.schema_id,
          "claims" => %{"name" => "Alice"}
        })
        |> json_response(201)

      assert resp["credential_id"]
      assert resp["offer_uri"]
    end

    test "401 without API key", %{conn: conn} do
      conn =
        conn
        |> put_req_header("accept", "application/json")
        |> post("/api/v1/issuer/credential-offer", %{"schema_id" => "x"})

      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "401 with unknown API key", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer sovra_sk_not-real")
        |> post("/api/v1/issuer/credential-offer", %{"schema_id" => "x"})

      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "401 with revoked API key", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key, record: rec}} = ApiKeys.create_api_key(ws.id, "Tmp")
      {:ok, _} = ApiKeys.revoke_api_key(rec)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/issuer/credential-offer", %{"schema_id" => "x"})

      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "API key from workspace A can't create offer using schema from workspace B", %{
      conn: conn
    } do
      %{workspace: ws_a} = create_workspace()
      %{workspace: ws_b} = create_workspace()
      schema_b = create_schema(ws_b.id)
      {:ok, %{api_key: key_a}} = ApiKeys.create_api_key(ws_a.id, "A")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key_a}")
        |> post("/api/v1/issuer/credential-offer", %{
          "schema_id" => schema_b.schema_id,
          "claims" => %{"name" => "Alice"}
        })
        |> json_response(404)

      assert resp["error"] == "schema_not_found"
    end
  end

  describe "POST /dashboard/issuer/offers/:id/regenerate" do
    defp authed(conn, ws, user) do
      {:ok, token} = UserSession.create(user.id, ws.id, user.is_admin)
      put_req_header(conn, "authorization", "Bearer #{token}")
    end

    defp create_offer(ws, schema) do
      {:ok, result} =
        Issuer.create_credential_offer(ws.id, schema.schema_id, %{"name" => "Alice"})

      result
    end

    test "200 with a fresh code for the same credential", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)
      created = create_offer(ws, schema)

      resp =
        conn
        |> authed(ws, user)
        |> post("/dashboard/issuer/offers/#{created.offer.id}/regenerate")
        |> json_response(200)

      assert resp["credential_id"] == created.offer.id
      assert resp["pre_authorized_code"] != created.pre_authorized_code
      assert resp["offer_uri"] != created.offer_uri
      assert String.contains?(resp["offer_uri"], resp["pre_authorized_code"])
    end

    test "the regenerated code redeems the same credential, the old one stops working", %{
      conn: conn
    } do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)
      created = create_offer(ws, schema)

      resp =
        conn
        |> authed(ws, user)
        |> post("/dashboard/issuer/offers/#{created.offer.id}/regenerate")
        |> json_response(200)

      assert {:error, :invalid_code} = Issuer.exchange_token(created.pre_authorized_code)
      assert {:ok, _} = Issuer.exchange_token(resp["pre_authorized_code"])

      offer = Sovra.Repo.get!(Sovra.Issuer.CredentialOffer, created.offer.id)
      assert offer.status_list_index == created.offer.status_list_index
    end

    test "404 for an offer belonging to another workspace", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      %{workspace: other_ws} = create_workspace()
      other_schema = create_schema(other_ws.id)
      created = create_offer(other_ws, other_schema)

      resp =
        conn
        |> authed(ws, user)
        |> post("/dashboard/issuer/offers/#{created.offer.id}/regenerate")
        |> json_response(404)

      assert resp["error"] == "offer_not_found"
    end

    test "404 for an unknown or malformed id", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()

      for id <- [Ecto.UUID.generate(), "not-a-uuid"] do
        resp =
          conn
          |> authed(ws, user)
          |> post("/dashboard/issuer/offers/#{id}/regenerate")
          |> json_response(404)

        assert resp["error"] == "offer_not_found"
      end
    end

    test "409 once the holder has exchanged the code", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)
      created = create_offer(ws, schema)
      {:ok, _} = Issuer.exchange_token(created.pre_authorized_code)

      resp =
        conn
        |> authed(ws, user)
        |> post("/dashboard/issuer/offers/#{created.offer.id}/regenerate")
        |> json_response(409)

      assert resp["error"] == "offer_not_pending"
    end

    test "409 for an expired offer", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)
      created = create_offer(ws, schema)

      past = DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)

      Sovra.Repo.get!(Sovra.Issuer.CredentialOffer, created.offer.id)
      |> Ecto.Changeset.change(expires_at: past)
      |> Sovra.Repo.update!()

      resp =
        conn
        |> authed(ws, user)
        |> post("/dashboard/issuer/offers/#{created.offer.id}/regenerate")
        |> json_response(409)

      assert resp["error"] == "offer_expired"
    end

    test "401 without a session", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      schema = create_schema(ws.id)
      created = create_offer(ws, schema)

      assert conn
             |> post("/dashboard/issuer/offers/#{created.offer.id}/regenerate")
             |> json_response(401)
    end
  end
end
