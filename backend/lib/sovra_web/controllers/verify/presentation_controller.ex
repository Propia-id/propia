defmodule SovraWeb.Verify.PresentationController do
  use SovraWeb, :controller

  def verify(conn, _params) do
    json(conn, %{error: "not_implemented"})
  end

  def resolve_did(conn, %{"did" => _did}) do
    json(conn, %{error: "not_implemented"})
  end
end
