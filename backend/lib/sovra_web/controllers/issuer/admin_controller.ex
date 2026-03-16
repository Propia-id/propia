defmodule SovraWeb.Issuer.AdminController do
  use SovraWeb, :controller

  alias Sovra.Issuer

  def get_issuer(conn, _params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id

    case Issuer.get_issuer(issuer_id) do
      {:ok, issuer} ->
        json(conn, %{
          id: issuer.id,
          name: issuer.name,
          did: issuer.did,
          eoa_address: issuer.eoa_address,
          status: issuer.status
        })

      {:error, _} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})
    end
  end

  def create_schema(conn, params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id

    attrs = %{
      schema_id: params["schema_id"],
      credential_type: params["credential_type"],
      name: params["name"],
      claims: normalize_claims(params["claims"]),
      validity_period: to_string(params["validity_period"] || "1y")
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
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        conn |> put_status(500) |> json(%{error: inspect(reason)})
    end
  end

  def list_schemas(conn, _params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id
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

  def delete_schema(conn, %{"id" => schema_id}) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id

    case Issuer.delete_schema(issuer_id, schema_id) do
      {:ok, _} ->
        conn |> put_status(204) |> text("")

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})
    end
  end

  def create_offer(conn, params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id

    case Issuer.create_credential_offer(
           issuer_id,
           params["schema_id"],
           params["holder_did"],
           params["claims"] || %{}
         ) do
      {:ok, %{offer: offer, offer_uri: offer_uri}} ->
        conn
        |> put_status(201)
        |> json(%{
          id: offer.id,
          status: offer.status,
          holder_did: offer.holder_did,
          offer_uri: offer_uri,
          expires_at: DateTime.to_iso8601(offer.expires_at)
        })

      {:error, {:missing_claims, missing}} ->
        conn |> put_status(422) |> json(%{error: "missing_claims", details: missing})

      {:error, :key_not_found} ->
        conn
        |> put_status(500)
        |> json(%{
          error: "signing_key_not_found",
          message:
            "Issuer signing key is unavailable. Re-register the issuer if the server was restarted."
        })

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})

      {:error, :issuer_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: to_string(reason)})
    end
  end

  def list_offers(conn, _params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id
    offers = Issuer.list_offers(issuer_id)

    json(conn, %{
      offers:
        Enum.map(offers, fn o ->
          %{
            id: o.id,
            holder_did: o.holder_did,
            status: o.status,
            expires_at: DateTime.to_iso8601(o.expires_at),
            inserted_at: DateTime.to_iso8601(o.inserted_at),
            schema: %{
              id: o.schema.id,
              credential_type: o.schema.credential_type,
              name: o.schema.name
            }
          }
        end)
    })
  end

  def list_issued_credentials(conn, _params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id
    credentials = Issuer.list_issued_credentials(issuer_id)

    json(conn, %{
      credentials:
        Enum.map(credentials, fn c ->
          %{
            id: c.id,
            holder_did: c.holder_did,
            status: c.status,
            issued_at: DateTime.to_iso8601(c.issued_at),
            expires_at: DateTime.to_iso8601(c.expires_at),
            schema: %{
              id: c.schema.id,
              credential_type: c.schema.credential_type,
              name: c.schema.name
            }
          }
        end)
    })
  end

  defp normalize_claims(%{"claims" => claims}) when is_list(claims), do: claims
  defp normalize_claims(claims) when is_list(claims), do: claims
  defp normalize_claims(other), do: other

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
