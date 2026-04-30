defmodule SovraWeb.Issuer.AdminController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer
  alias Sovra.Issuer.Accounts
  alias Sovra.Workspaces

  tags(["Issuer Admin"])
  security([%{"IssuerCookieAuth" => []}])

  operation(:create_issuer_account,
    summary: "Create issuer account (super-admin)",
    description: "Create a new issuer account. Requires admin role.",
    request_body:
      {"Issuer account params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:email, :password, :issuer_name],
         properties: %{
           email: %OpenApiSpex.Schema{type: :string, format: :email},
           password: %OpenApiSpex.Schema{type: :string},
           issuer_name: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      201 =>
        {"Issuer created", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             issuer: %OpenApiSpex.Schema{
               type: :object,
               properties: %{
                 id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                 name: %OpenApiSpex.Schema{type: :string},
                 did: %OpenApiSpex.Schema{type: :string},
                 status: %OpenApiSpex.Schema{type: :string}
               }
             },
             email: %OpenApiSpex.Schema{type: :string}
           }
         }},
      422 =>
        {"Validation error", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             error: %OpenApiSpex.Schema{type: :string},
             details: %OpenApiSpex.Schema{type: :object}
           }
         }}
    }
  )

  operation(:get_issuer,
    summary: "Get issuer profile",
    description: "Get the authenticated issuer's profile.",
    responses: %{
      200 =>
        {"Issuer profile", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             name: %OpenApiSpex.Schema{type: :string},
             did: %OpenApiSpex.Schema{type: :string},
             eoa_address: %OpenApiSpex.Schema{type: :string},
             status: %OpenApiSpex.Schema{type: :string}
           }
         }},
      404 =>
        {"Issuer not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:create_schema,
    summary: "Create credential schema",
    description: "Create a new credential schema for the authenticated issuer.",
    request_body:
      {"Schema params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:schema_id, :credential_type, :name, :claims],
         properties: %{
           schema_id: %OpenApiSpex.Schema{type: :string},
           credential_type: %OpenApiSpex.Schema{type: :string},
           name: %OpenApiSpex.Schema{type: :string},
           claims: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :object}},
           validity_period: %OpenApiSpex.Schema{type: :string, example: "1y"}
         }
       }},
    responses: %{
      201 =>
        {"Schema created", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             schema_id: %OpenApiSpex.Schema{type: :string},
             credential_type: %OpenApiSpex.Schema{type: :string},
             name: %OpenApiSpex.Schema{type: :string},
             claims: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :object}},
             validity_period: %OpenApiSpex.Schema{type: :string}
           }
         }},
      422 =>
        {"Validation error", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             error: %OpenApiSpex.Schema{type: :string},
             details: %OpenApiSpex.Schema{type: :object}
           }
         }}
    }
  )

  operation(:list_schemas,
    summary: "List credential schemas",
    description: "List all credential schemas for the authenticated issuer.",
    responses: %{
      200 =>
        {"Schema list", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             schemas: %OpenApiSpex.Schema{
               type: :array,
               items: %OpenApiSpex.Schema{
                 type: :object,
                 properties: %{
                   id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                   schema_id: %OpenApiSpex.Schema{type: :string},
                   credential_type: %OpenApiSpex.Schema{type: :string},
                   name: %OpenApiSpex.Schema{type: :string},
                   claims: %OpenApiSpex.Schema{
                     type: :array,
                     items: %OpenApiSpex.Schema{type: :object}
                   },
                   validity_period: %OpenApiSpex.Schema{type: :string},
                   version: %OpenApiSpex.Schema{type: :integer}
                 }
               }
             }
           }
         }}
    }
  )

  operation(:delete_schema,
    summary: "Delete credential schema",
    description: "Delete a credential schema by ID.",
    parameters: [
      id: [in: :path, type: :string, description: "Schema UUID", required: true]
    ],
    responses: %{
      204 => {"Schema deleted", nil, nil},
      404 =>
        {"Schema not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:list_offers,
    summary: "List credential offers",
    description: "List all credential offers for the authenticated issuer.",
    responses: %{
      200 =>
        {"Offer list", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             offers: %OpenApiSpex.Schema{
               type: :array,
               items: %OpenApiSpex.Schema{
                 type: :object,
                 properties: %{
                   id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                   holder_did: %OpenApiSpex.Schema{type: :string},
                   status: %OpenApiSpex.Schema{type: :string},
                   expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
                   inserted_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
                   schema: %OpenApiSpex.Schema{
                     type: :object,
                     properties: %{
                       id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                       credential_type: %OpenApiSpex.Schema{type: :string},
                       name: %OpenApiSpex.Schema{type: :string}
                     }
                   }
                 }
               }
             }
           }
         }}
    }
  )

  @credential_object %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      holder_did: %OpenApiSpex.Schema{type: :string},
      status: %OpenApiSpex.Schema{type: :string},
      issued_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
      expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
      schema: %OpenApiSpex.Schema{
        type: :object,
        properties: %{
          id: %OpenApiSpex.Schema{type: :string, format: :uuid},
          credential_type: %OpenApiSpex.Schema{type: :string},
          name: %OpenApiSpex.Schema{type: :string}
        }
      }
    }
  }

  operation(:list_issued_credentials,
    summary: "List issued credentials",
    description: "List all credentials issued by the authenticated workspace.",
    responses: %{
      200 =>
        {"Credential list", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             credentials: %OpenApiSpex.Schema{type: :array, items: @credential_object}
           }
         }}
    }
  )

  operation(:show_issued_credential,
    summary: "Show a credential by id",
    description:
      "Return metadata for a credential. The same id covers the full lifecycle: " <>
        "while the holder hasn't claimed yet the response has `status: \"pending\"` " <>
        "(or `\"expired\"` if the offer window passed) with a null `holder_did` " <>
        "and `issued_at`; once claimed it returns the issued state. The signed " <>
        "SD-JWT is delivered once via the `credential.issued` webhook and is not " <>
        "stored server-side.",
    parameters: [
      id: [in: :path, type: :string, description: "Credential UUID", required: true]
    ],
    responses: %{
      200 => {"Credential", "application/json", @credential_object},
      404 =>
        {"Credential not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  def create_issuer_account(conn, %{
        "email" => email,
        "password" => password,
        "issuer_name" => issuer_name
      }) do
    case Accounts.register_issuer(email, password, issuer_name) do
      {:ok, %{workspace: workspace} = result} ->
        conn
        |> put_status(201)
        |> json(%{
          issuer: %{
            id: workspace.id,
            name: workspace.name,
            did: workspace.did,
            status: workspace.status
          },
          webhook_secret: Map.get(result, :webhook_secret),
          email: String.downcase(email)
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})

      {:error, _reason} ->
        conn |> put_status(422) |> json(%{error: "registration_failed"})
    end
  end

  def list_issuers(conn, _params) do
    workspaces = Workspaces.list_workspaces()

    json(conn, %{
      issuers:
        Enum.map(workspaces, fn w ->
          %{id: w.id, name: w.name, did: w.did, status: w.status, email: w.email}
        end)
    })
  end

  def get_issuer(conn, _params) do
    workspace_id = conn.assigns.current_issuer_account.workspace_id

    case Workspaces.get_workspace(workspace_id) do
      {:ok, workspace} ->
        json(conn, %{
          id: workspace.id,
          name: workspace.name,
          did: workspace.did,
          eoa_address: workspace.eoa_address,
          status: workspace.status
        })

      {:error, _} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})
    end
  end

  def create_schema(conn, params) do
    workspace_id = conn.assigns.current_issuer_account.workspace_id

    attrs = %{
      schema_id: params["schema_id"],
      credential_type: params["credential_type"],
      name: params["name"],
      claims: normalize_claims(params["claims"]),
      validity_period: to_string(params["validity_period"] || "1y")
    }

    case Issuer.create_schema(workspace_id, attrs) do
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

      {:error, _reason} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  def list_schemas(conn, _params) do
    workspace_id = conn.assigns.current_issuer_account.workspace_id
    schemas = Issuer.list_schemas(workspace_id)

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
    workspace_id = conn.assigns.current_issuer_account.workspace_id

    case Issuer.delete_schema(workspace_id, schema_id) do
      {:ok, _} ->
        conn |> put_status(204) |> text("")

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})
    end
  end

  def list_offers(conn, _params) do
    workspace_id = conn.assigns.current_issuer_account.workspace_id
    offers = Issuer.list_offers(workspace_id)

    json(conn, %{
      offers:
        Enum.map(offers, fn o ->
          %{
            id: o.id,
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

  operation(:update_credential_status,
    summary: "Change a credential's status",
    description:
      "Idempotent status transition. Allowed values: `revoked` (permanent), " <>
        "`suspended` (reversible), `issued` (un-suspend a suspended credential). " <>
        "On the dashboard pipeline, requires workspace admin; on the API-key " <>
        "pipeline, the workspace's API key is sufficient.",
    parameters: [
      id: [in: :path, type: :string, description: "Credential UUID", required: true],
      status: [
        in: :path,
        type: :string,
        description: "Target status: `revoked`, `suspended`, or `issued`",
        required: true
      ]
    ],
    responses: %{
      200 =>
        {"Status updated", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             status: %OpenApiSpex.Schema{type: :string}
           }
         }},
      400 =>
        {"Unknown target status", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      403 =>
        {"Workspace admin required", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      404 =>
        {"Credential not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      422 =>
        {"Invalid transition", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  def list_issued_credentials(conn, _params) do
    workspace_id = conn.assigns.current_workspace_id
    credentials = Issuer.list_issued_credentials(workspace_id)

    json(conn, %{credentials: Enum.map(credentials, &credential_view/1)})
  end

  def show_issued_credential(conn, %{"id" => credential_id}) do
    workspace_id = conn.assigns.current_workspace_id

    case Issuer.get_credential(workspace_id, credential_id) do
      {:ok, {:issued, cred}} ->
        json(conn, credential_view(cred))

      {:ok, {:pending, offer}} ->
        json(conn, pending_credential_view(offer))

      {:error, :credential_not_found} ->
        conn |> put_status(404) |> json(%{error: "credential_not_found"})
    end
  end

  @status_transitions %{
    "revoked" => &Sovra.Issuer.revoke_credential/2,
    "suspended" => &Sovra.Issuer.suspend_credential/2,
    "issued" => &Sovra.Issuer.unsuspend_credential/2
  }

  def update_credential_status(conn, %{"id" => credential_id, "status" => status}) do
    case Map.fetch(@status_transitions, status) do
      {:ok, fun} ->
        workspace_id = conn.assigns.current_workspace_id

        case fun.(workspace_id, credential_id) do
          {:ok, cred} ->
            json(conn, %{id: cred.id, status: cred.status})

          {:error, :credential_not_found} ->
            conn |> put_status(404) |> json(%{error: "credential_not_found"})

          {:error, :credential_not_yet_issued} ->
            conn |> put_status(422) |> json(%{error: "credential_not_yet_issued"})

          {:error, :invalid_status_transition} ->
            conn |> put_status(422) |> json(%{error: "invalid_status_transition"})

          {:error, reason} ->
            conn |> put_status(422) |> json(%{error: to_string(reason)})
        end

      :error ->
        conn |> put_status(400) |> json(%{error: "unknown_status"})
    end
  end

  defp credential_view(c) do
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
  end

  defp pending_credential_view(offer) do
    status =
      if DateTime.compare(DateTime.utc_now(), offer.expires_at) == :gt,
        do: "expired",
        else: "pending"

    %{
      id: offer.id,
      holder_did: nil,
      status: status,
      issued_at: nil,
      expires_at: DateTime.to_iso8601(offer.expires_at),
      schema: %{
        id: offer.schema.id,
        credential_type: offer.schema.credential_type,
        name: offer.schema.name
      }
    }
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
