defmodule SovraWeb.Plugs.RequireOrgAdminPlug do
  @moduledoc """
  Restricts access to organization endpoints to `owner` or `admin` members.
  Must be used after `IssuerSessionPlug`. Does NOT bypass for platform
  super-admins — Sovra admins must be explicit org members to act on one.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Sovra.Organizations

  def init(opts), do: opts

  def call(conn, _opts) do
    with %{account_id: account_id} <- conn.assigns[:current_issuer_account],
         org_id when is_binary(org_id) <- conn.path_params["org_id"] || conn.params["org_id"] do
      case Organizations.member_role(org_id, account_id) do
        {:ok, role} when role in ~w(owner admin) ->
          assign(conn, :current_org_role, role)

        {:ok, _member_role} ->
          conn |> put_status(403) |> json(%{error: "org_admin_required"}) |> halt()

        {:error, :not_a_member} ->
          conn |> put_status(404) |> json(%{error: "organization_not_found"}) |> halt()
      end
    else
      _ ->
        conn |> put_status(403) |> json(%{error: "org_admin_required"}) |> halt()
    end
  end
end
