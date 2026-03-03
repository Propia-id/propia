defmodule SovraWeb.Issuer.CredentialController do
  use SovraWeb, :controller

  def offer(conn, _params) do
    json(conn, %{error: "not_implemented"})
  end

  def authorize(conn, _params) do
    json(conn, %{error: "not_implemented"})
  end

  def token(conn, _params) do
    json(conn, %{error: "not_implemented"})
  end

  def issue(conn, _params) do
    json(conn, %{error: "not_implemented"})
  end
end
