defmodule SovraWeb.Organizations.OrganizationControllerTest do
  use SovraWeb.ConnCase, async: true

  alias Sovra.Auth.IssuerSession
  alias Sovra.Issuer.IssuerAccount
  alias Sovra.Organizations
  alias Sovra.Repo

  defp create_user(suffix) do
    {:ok, account} =
      IssuerAccount.admin_changeset(%{
        email: "#{suffix}-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Repo.insert()

    account
  end

  defp authed_conn(conn, account) do
    {:ok, token} = IssuerSession.create(account.id, nil, account.role || "issuer")

    conn
    |> put_req_header("authorization", "Bearer #{token}")
    |> put_req_header("accept", "application/json")
  end

  describe "POST /api/v1/organizations" do
    test "creates an org and makes the caller owner", %{conn: conn} do
      user = create_user("owner")

      resp =
        conn
        |> authed_conn(user)
        |> post("/api/v1/organizations", %{
          name: "Acme",
          logo_url: "https://acme.test/logo.png",
          website: "https://acme.test"
        })
        |> json_response(201)

      assert resp["name"] == "Acme"
      assert resp["role"] == "owner"
      assert resp["status"] == "active"

      assert {:ok, "owner"} = Organizations.member_role(resp["id"], user.id)
    end

    test "returns 401 without a session", %{conn: conn} do
      conn =
        conn
        |> put_req_header("accept", "application/json")
        |> post("/api/v1/organizations", %{name: "Acme"})

      assert json_response(conn, 401)
    end

    test "returns 422 on validation error", %{conn: conn} do
      user = create_user("owner")

      resp =
        conn
        |> authed_conn(user)
        |> post("/api/v1/organizations", %{})
        |> json_response(422)

      assert resp["error"] == "validation_error"
      assert resp["details"]
    end
  end

  describe "PATCH /api/v1/organizations/:id (as admin)" do
    setup do
      owner = create_user("owner")

      {:ok, %{organization: org}} =
        Organizations.create_organization(owner.id, %{name: "Acme"})

      %{owner: owner, org: org}
    end

    test "owner updates branding", %{conn: conn, owner: owner, org: org} do
      resp =
        conn
        |> authed_conn(owner)
        |> patch("/api/v1/organizations/#{org.id}", %{name: "Acme Inc."})
        |> json_response(200)

      assert resp["name"] == "Acme Inc."
    end

    test "non-member returns 404 (no existence leak)", %{conn: conn, org: org} do
      stranger = create_user("stranger")

      conn =
        conn
        |> authed_conn(stranger)
        |> patch("/api/v1/organizations/#{org.id}", %{name: "Hostile"})

      assert json_response(conn, 404) == %{"error" => "organization_not_found"}
    end

    test "plain member returns 403", %{conn: conn, org: org} do
      member = create_user("member")
      {:ok, _} = Organizations.add_member(org.id, member.id, "member")

      conn =
        conn
        |> authed_conn(member)
        |> patch("/api/v1/organizations/#{org.id}", %{name: "Nope"})

      assert json_response(conn, 403) == %{"error" => "org_admin_required"}
    end

    test "platform admin with no membership returns 404 (no bypass, no existence leak)", %{
      conn: conn,
      org: org
    } do
      # Platform admin, but NOT a member of this org.
      admin = create_user("platform-admin")

      # Ensure they have platform role "admin".
      admin =
        admin
        |> Ecto.Changeset.change(role: "admin")
        |> Repo.update!()

      conn =
        conn
        |> authed_conn(admin)
        |> patch("/api/v1/organizations/#{org.id}", %{name: "Nope"})

      assert json_response(conn, 404) == %{"error" => "organization_not_found"}
    end
  end

  describe "POST /api/v1/organizations/:id/deactivate" do
    setup do
      owner = create_user("owner")

      {:ok, %{organization: org}} =
        Organizations.create_organization(owner.id, %{name: "Acme"})

      %{owner: owner, org: org}
    end

    test "owner deactivates", %{conn: conn, owner: owner, org: org} do
      resp =
        conn
        |> authed_conn(owner)
        |> post("/api/v1/organizations/#{org.id}/deactivate")
        |> json_response(200)

      assert resp["status"] == "deactivated"
    end

    test "admin (not owner) returns 403", %{conn: conn, org: org} do
      admin = create_user("org-admin")
      {:ok, _} = Organizations.add_member(org.id, admin.id, "admin")

      conn =
        conn
        |> authed_conn(admin)
        |> post("/api/v1/organizations/#{org.id}/deactivate")

      assert json_response(conn, 403) == %{"error" => "org_owner_required"}
    end

    test "update refused after deactivate", %{conn: conn, owner: owner, org: org} do
      conn
      |> authed_conn(owner)
      |> post("/api/v1/organizations/#{org.id}/deactivate")

      conn2 =
        build_conn()
        |> authed_conn(owner)
        |> patch("/api/v1/organizations/#{org.id}", %{name: "Too late"})

      assert json_response(conn2, 422)["error"] == "validation_error"
    end
  end

  describe "GET /api/v1/organizations/:id/members" do
    test "lists all members with role and status for org admin", %{conn: conn} do
      owner = create_user("owner")
      member = create_user("member")

      {:ok, %{organization: org}} =
        Organizations.create_organization(owner.id, %{name: "Acme"})

      {:ok, _} = Organizations.add_member(org.id, member.id, "member")

      resp =
        conn
        |> authed_conn(owner)
        |> get("/api/v1/organizations/#{org.id}/members")
        |> json_response(200)

      roles = Map.new(resp["members"], &{&1["id"], &1["role"]})
      assert roles[owner.id] == "owner"
      assert roles[member.id] == "member"
      assert Enum.all?(resp["members"], &(&1["status"] == "active"))
    end

    test "plain member cannot list", %{conn: conn} do
      owner = create_user("owner")
      member = create_user("member")

      {:ok, %{organization: org}} =
        Organizations.create_organization(owner.id, %{name: "Acme"})

      {:ok, _} = Organizations.add_member(org.id, member.id, "member")

      conn =
        conn
        |> authed_conn(member)
        |> get("/api/v1/organizations/#{org.id}/members")

      assert json_response(conn, 403) == %{"error" => "org_admin_required"}
    end
  end

  describe "GET /api/v1/organizations" do
    test "lists only orgs the caller belongs to", %{conn: conn} do
      owner_a = create_user("a")
      owner_b = create_user("b")

      {:ok, %{organization: org_a}} =
        Organizations.create_organization(owner_a.id, %{name: "Org A"})

      {:ok, _} = Organizations.create_organization(owner_b.id, %{name: "Org B"})

      resp =
        conn
        |> authed_conn(owner_a)
        |> get("/api/v1/organizations")
        |> json_response(200)

      ids = Enum.map(resp["organizations"], & &1["id"])
      assert ids == [org_a.id]
    end
  end
end
