defmodule SovraWeb.Issuer.AdminController do
  use SovraWeb, :controller

  alias Sovra.Issuer

  def create_issuer(conn, %{"name" => name}) do
    case Issuer.create_issuer(name) do
      {:ok, issuer} ->
        conn
        |> put_status(201)
        |> json(%{
          id: issuer.id,
          name: issuer.name,
          did: issuer.did,
          eoa_address: issuer.eoa_address,
          signing_public_key: %{
            x: Base.url_encode64(issuer.signing_public_key_x, padding: false),
            y: Base.url_encode64(issuer.signing_public_key_y, padding: false)
          }
        })

      {:error, reason} ->
        conn |> put_status(500) |> json(%{error: inspect(reason)})
    end
  end

  def create_schema(conn, params) do
    issuer_id = params["issuer_id"]

    attrs = %{
      schema_id: params["schema_id"],
      credential_type: params["credential_type"],
      name: params["name"],
      claims: params["claims"],
      validity_period: params["validity_period"] || "1y"
    }

    case Issuer.create_schema(issuer_id, attrs) do
      {:ok, schema} ->
        conn
        |> put_status(201)
        |> json(%{
          id: schema.id,
          schema_id: schema.schema_id,
          credential_type: schema.credential_type,
          name: schema.name,
          claims: schema.claims,
          validity_period: schema.validity_period
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        conn |> put_status(422) |> json(%{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        conn |> put_status(500) |> json(%{error: inspect(reason)})
    end
  end

  def list_schemas(conn, %{"issuer_id" => issuer_id}) do
    schemas = Issuer.list_schemas(issuer_id)

    json(conn, %{
      schemas:
        Enum.map(schemas, fn s ->
          %{
            id: s.id,
            schema_id: s.schema_id,
            credential_type: s.credential_type,
            name: s.name,
            claims: s.claims,
            validity_period: s.validity_period,
            version: s.version
          }
        end)
    })
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
