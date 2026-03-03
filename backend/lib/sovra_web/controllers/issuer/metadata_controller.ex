defmodule SovraWeb.Issuer.MetadataController do
  use SovraWeb, :controller

  def show(conn, _params) do
    json(conn, %{
      credential_issuer: "https://issuer.sovra.id",
      credential_endpoint: "/api/v1/issuer/credential",
      credentials_supported: []
    })
  end
end
