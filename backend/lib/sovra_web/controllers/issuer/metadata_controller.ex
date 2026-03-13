defmodule SovraWeb.Issuer.MetadataController do
  use SovraWeb, :controller

  alias Sovra.Issuer
  alias Sovra.Issuer.OID4VCI

  def show(conn, _params) do
    case Issuer.get_first_issuer() do
      {:ok, issuer} ->
        schemas = Issuer.list_schemas(issuer.id)
        metadata = OID4VCI.build_metadata(issuer, schemas)
        json(conn, metadata)

      {:error, :no_issuers} ->
        conn
        |> put_status(503)
        |> json(%{error: "no_issuers_configured"})
    end
  end

  def show_by_id(conn, %{"issuer_id" => issuer_id}) do
    case Issuer.get_issuer(issuer_id) do
      {:ok, issuer} ->
        schemas = Issuer.list_schemas(issuer.id)
        metadata = OID4VCI.build_metadata(issuer, schemas)
        json(conn, metadata)

      {:error, :issuer_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})
    end
  end
end
