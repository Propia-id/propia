defmodule SovraWeb.Cosigner.SignController do
  use SovraWeb, :controller

  def sign(conn, _params) do
    json(conn, %{error: "not_implemented"})
  end
end
