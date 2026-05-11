defmodule SovraWeb.Issuer.ApiCredentialTest do
  @moduledoc """
  Covers the API-key-authenticated credential surface used by external
  integrators (Sovra Gov):

      GET /api/v1/issuer/credentials
      GET /api/v1/issuer/credentials/:id
      PUT /api/v1/issuer/credentials/:id/status/:status

  Same controller actions back the dashboard mount under
  `/dashboard/issuer/credentials`; that path is exercised in
  `admin_credential_status_test.exs`.
  """
  use SovraWeb.ConnCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Issuer
  alias Sovra.Issuer.IssuedCredential
  alias Sovra.Accounts.User
  alias Sovra.Organizations.Organization
  alias Sovra.Webhooks.DeliveryJob
  alias Sovra.Workspaces
  alias Sovra.Workspaces.ApiKeys

  defp setup_workspace_with_credential do
    {:ok, owner} =
      User.admin_changeset(%{
        email: "owner-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, owner.id)
    ws = provision_workspace(ws)
    {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

    {:ok, schema} =
      Issuer.create_schema(ws.id, %{
        schema_id: "s-#{System.unique_integer([:positive])}",
        credential_type: "TestCredential",
        name: "Test",
        claims: [
          %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
        ],
        validity_period: "1y"
      })

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {:ok, cred} =
      IssuedCredential.create_changeset(%{
        issuer_id: ws.id,
        schema_id: schema.id,
        holder_did: "did:sovra:0xholder",
        issued_at: now,
        expires_at: DateTime.add(now, 86_400, :second)
      })
      |> Sovra.Repo.insert()

    %{workspace: ws, api_key: key, credential: cred, schema: schema}
  end

  defp setup_workspace_with_pending_offer do
    {:ok, owner} =
      User.admin_changeset(%{
        email: "owner-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, owner.id)
    ws = provision_workspace(ws)
    {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

    {:ok, schema} =
      Issuer.create_schema(ws.id, %{
        schema_id: "s-#{System.unique_integer([:positive])}",
        credential_type: "TestCredential",
        name: "Test",
        claims: [
          %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
        ],
        validity_period: "1y"
      })

    {:ok, %{offer: offer}} =
      Issuer.create_credential_offer(ws.id, schema.schema_id, %{"name" => "Alice"})

    %{workspace: ws, api_key: key, offer: offer, schema: schema}
  end

  defp authed(conn, key), do: put_req_header(conn, "authorization", "Bearer #{key}")

  describe "GET /api/v1/issuer/credentials" do
    test "lists credentials for the calling workspace", %{conn: conn} do
      %{api_key: key, credential: cred} = setup_workspace_with_credential()

      resp =
        conn
        |> authed(key)
        |> get("/api/v1/issuer/credentials")
        |> json_response(200)

      assert [%{"id" => id}] = resp["credentials"]
      assert id == cred.id
    end

    test "401 without API key", %{conn: conn} do
      conn = get(conn, "/api/v1/issuer/credentials")
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "does not leak credentials from another workspace", %{conn: conn} do
      %{api_key: key_a} = setup_workspace_with_credential()
      %{credential: cred_b} = setup_workspace_with_credential()

      resp =
        conn
        |> authed(key_a)
        |> get("/api/v1/issuer/credentials")
        |> json_response(200)

      ids = Enum.map(resp["credentials"], & &1["id"])
      refute cred_b.id in ids
    end
  end

  describe "GET /api/v1/issuer/credentials/:id" do
    test "returns credential metadata", %{conn: conn} do
      %{api_key: key, credential: cred, schema: schema} = setup_workspace_with_credential()

      resp =
        conn
        |> authed(key)
        |> get("/api/v1/issuer/credentials/#{cred.id}")
        |> json_response(200)

      assert resp["id"] == cred.id
      assert resp["holder_did"] == "did:sovra:0xholder"
      assert resp["status"] == "issued"
      assert resp["schema"]["credential_type"] == schema.credential_type
    end

    test "404 for credential in another workspace", %{conn: conn} do
      %{api_key: key_a} = setup_workspace_with_credential()
      %{credential: cred_b} = setup_workspace_with_credential()

      conn =
        conn
        |> authed(key_a)
        |> get("/api/v1/issuer/credentials/#{cred_b.id}")

      assert json_response(conn, 404) == %{"error" => "credential_not_found"}
    end

    test "returns pending state when the holder hasn't claimed yet", %{conn: conn} do
      %{api_key: key, offer: offer, schema: schema} = setup_workspace_with_pending_offer()

      resp =
        conn
        |> authed(key)
        |> get("/api/v1/issuer/credentials/#{offer.id}")
        |> json_response(200)

      assert resp["id"] == offer.id
      assert resp["status"] == "pending"
      assert is_nil(resp["holder_did"])
      assert is_nil(resp["issued_at"])
      assert resp["schema"]["credential_type"] == schema.credential_type
    end

    test "returns expired state when the offer window passed", %{conn: conn} do
      %{api_key: key, offer: offer} = setup_workspace_with_pending_offer()

      # Force the offer to be expired without round-tripping through the
      # 24h waiting period.
      past = DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second)

      offer
      |> Ecto.Changeset.change(expires_at: past)
      |> Sovra.Repo.update!()

      resp =
        conn
        |> authed(key)
        |> get("/api/v1/issuer/credentials/#{offer.id}")
        |> json_response(200)

      assert resp["status"] == "expired"
    end
  end

  describe "PUT /api/v1/issuer/credentials/:id/status/:status" do
    test "revokes via API key and emits webhook", %{conn: conn} do
      %{api_key: key, credential: cred} = setup_workspace_with_credential()

      resp =
        conn
        |> authed(key)
        |> put("/api/v1/issuer/credentials/#{cred.id}/status/revoked")
        |> json_response(200)

      assert resp["status"] == "revoked"
      assert_enqueued(worker: DeliveryJob, args: %{"event" => "credential.revoked"})
    end

    test "suspend then unsuspend round-trip", %{conn: conn} do
      %{api_key: key, credential: cred} = setup_workspace_with_credential()

      assert %{"status" => "suspended"} =
               conn
               |> authed(key)
               |> put("/api/v1/issuer/credentials/#{cred.id}/status/suspended")
               |> json_response(200)

      assert %{"status" => "issued"} =
               conn
               |> authed(key)
               |> put("/api/v1/issuer/credentials/#{cred.id}/status/issued")
               |> json_response(200)
    end

    test "unknown status returns 400", %{conn: conn} do
      %{api_key: key, credential: cred} = setup_workspace_with_credential()

      conn =
        conn
        |> authed(key)
        |> put("/api/v1/issuer/credentials/#{cred.id}/status/garbage")

      assert json_response(conn, 400) == %{"error" => "unknown_status"}
    end

    test "invalid transition returns 422", %{conn: conn} do
      %{api_key: key, credential: cred} = setup_workspace_with_credential()

      conn
      |> authed(key)
      |> put("/api/v1/issuer/credentials/#{cred.id}/status/revoked")
      |> json_response(200)

      conn =
        conn
        |> authed(key)
        |> put("/api/v1/issuer/credentials/#{cred.id}/status/suspended")

      assert json_response(conn, 422) == %{"error" => "invalid_status_transition"}
    end

    test "404 for credential in another workspace", %{conn: conn} do
      %{api_key: key_a} = setup_workspace_with_credential()
      %{credential: cred_b} = setup_workspace_with_credential()

      conn =
        conn
        |> authed(key_a)
        |> put("/api/v1/issuer/credentials/#{cred_b.id}/status/revoked")

      assert json_response(conn, 404) == %{"error" => "credential_not_found"}
    end

    test "401 without API key", %{conn: conn} do
      %{credential: cred} = setup_workspace_with_credential()
      conn = put(conn, "/api/v1/issuer/credentials/#{cred.id}/status/revoked")
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "422 when the credential hasn't been claimed yet", %{conn: conn} do
      %{api_key: key, offer: offer} = setup_workspace_with_pending_offer()

      conn =
        conn
        |> authed(key)
        |> put("/api/v1/issuer/credentials/#{offer.id}/status/revoked")

      assert json_response(conn, 422) == %{"error" => "credential_not_yet_issued"}
    end
  end
end
