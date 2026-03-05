defmodule SovraWeb.Plugs.SessionPlug do
  @moduledoc """
  Plug that authenticates co-signing requests via session JWT.
  Expects `Authorization: Bearer <token>` header.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  def init(opts), do: opts

  def call(conn, _opts) do
    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         {:ok, %{sovra_address: address}} <- Sovra.Auth.Session.verify(token) do
      assign(conn, :current_holder, %{sovra_address: address})
    else
      [] ->
        conn |> put_status(401) |> json(%{error: "missing_authorization"}) |> halt()

      {:error, :expired} ->
        conn |> put_status(401) |> json(%{error: "session_expired"}) |> halt()

      {:error, _} ->
        conn |> put_status(401) |> json(%{error: "invalid_session"}) |> halt()
    end
  end
end
