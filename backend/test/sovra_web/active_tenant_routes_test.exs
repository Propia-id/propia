defmodule SovraWeb.ActiveTenantRoutesTest do
  @moduledoc """
  Which routes refuse an inactive tenant, asserted over the router itself so a
  route added later is covered without anyone writing a test for it.

  Every API-key route is gated by the `:api_key` pipeline. On the dashboard,
  every `/dashboard/issuer` route that acts for the session's workspace goes
  through `:active_tenant`; the exceptions are in `@ungated`, each with its
  reason, and the platform-admin routes act for no workspace.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Auth.UserSession
  alias Sovra.Organizations
  alias Sovra.Workspaces.ApiKeys
  alias Sovra.Workspaces.Workspace

  @ungated [
    # Carries the workspace's status: how the dashboard explains the 403s.
    {:get, "/dashboard/issuer/profile"},
    # ISO's element list, the same for every workspace.
    {:get, "/dashboard/issuer/mdl/template"}
  ]

  # `__routes__/0` leaves out the pipelines; `route_info/4` has them.
  defp routes do
    for %{verb: verb, path: path} <- SovraWeb.Router.__routes__(), verb != :* do
      method = verb |> to_string() |> String.upcase()
      %{pipe_through: pipe_through} = Phoenix.Router.route_info(SovraWeb.Router, method, path, "")
      %{verb: verb, path: path, pipe_through: pipe_through}
    end
  end

  defp routes_through(pipeline), do: Enum.filter(routes(), &(pipeline in &1.pipe_through))

  # The plug halts before the action, so what fills a path param is never read.
  defp concrete(path), do: String.replace(path, ~r/:[a-z_]+/, Ecto.UUID.generate())

  defp request(conn, route), do: dispatch(conn, @endpoint, route.verb, concrete(route.path), %{})

  defp label(route), do: "#{route.verb |> to_string() |> String.upcase()} #{route.path}"

  test "every /dashboard/issuer route acting for a workspace goes through :active_tenant" do
    for route <- routes(),
        String.starts_with?(route.path, "/dashboard/issuer"),
        :user_session in route.pipe_through,
        :require_admin not in route.pipe_through,
        {route.verb, route.path} not in @ungated do
      assert :active_tenant in route.pipe_through, "#{label(route)} is not gated"
    end
  end

  test "every route left ungated still exists" do
    present = MapSet.new(routes(), &{&1.verb, &1.path})

    for route <- @ungated, do: assert(route in present, "#{inspect(route)} is not a route")
  end

  test "an API key of a deactivated organization is refused on every API-key route", %{
    conn: conn
  } do
    %{workspace: ws, org: org} = fixture_workspace()
    {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")
    {:ok, _} = Organizations.deactivate_organization(org)

    assert [_ | _] = routes = routes_through(:api_key)

    for route <- routes do
      conn = conn |> put_req_header("authorization", "Bearer #{key}") |> request(route)

      assert json_response(conn, 403) == %{"error" => "organization_inactive"}, label(route)
    end
  end

  test "a session in a suspended workspace is refused on every gated dashboard route", %{
    conn: conn
  } do
    %{workspace: ws, owner: owner} = fixture_workspace()
    {:ok, token} = UserSession.create(owner.id, ws.id, owner.is_admin)
    {:ok, _} = ws |> Workspace.status_changeset("suspended") |> Sovra.Repo.update()

    assert [_ | _] = routes = routes_through(:active_tenant)

    for route <- routes do
      conn = conn |> put_req_header("authorization", "Bearer #{token}") |> request(route)

      assert json_response(conn, 403) == %{"error" => "workspace_inactive"}, label(route)
    end
  end

  test "a session in a deactivated organization can still see why, and leave", %{conn: conn} do
    %{workspace: ws, owner: owner, org: org} = fixture_workspace()
    {:ok, token} = UserSession.create(owner.id, ws.id, owner.is_admin)
    {:ok, _} = Organizations.deactivate_organization(org)
    conn = put_req_header(conn, "authorization", "Bearer #{token}")

    assert %{"id" => id} = conn |> get("/dashboard/issuer/profile") |> json_response(200)
    assert id == ws.id

    assert conn |> get("/dashboard/workspaces") |> json_response(200)
  end
end
