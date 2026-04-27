defmodule SovraWeb.Plugs.ApiKeyPlug do
  @moduledoc """
  Authenticates server-to-server requests via a workspace API key.

  Expects `Authorization: Bearer sovra_sk_...` (case-sensitive scheme). Looks
  up the key's SHA-256 hash in `workspace_api_keys`; rejects unknown, malformed,
  or revoked keys with 401. On success assigns `:current_workspace_id` (the
  owning workspace's UUID), `:current_api_key_id`, and
  `:current_auth_method`. Also fire-and-forgets a `last_used_at` update so
  operators can triage leaks.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Sovra.Workspaces.ApiKeys

  def init(opts), do: opts

  def call(conn, _opts) do
    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         {:ok, key} <- ApiKeys.find_active_by_plaintext(token) do
      ApiKeys.touch_last_used(key.id)

      conn
      |> assign(:current_workspace_id, key.workspace_id)
      |> assign(:current_api_key_id, key.id)
      |> assign(:current_auth_method, :api_key)
    else
      _ ->
        conn |> put_status(401) |> json(%{error: "invalid_api_key"}) |> halt()
    end
  end
end
