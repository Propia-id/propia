defmodule SovraWeb.Issuer.AdminController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Accounts
  alias Sovra.Documents
  alias Sovra.Issuer
  alias Sovra.Workspaces

  tags(["Issuer Admin"])
  security([%{"UserCookieAuth" => []}])

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
           issuer_name: %OpenApiSpex.Schema{type: :string},
           full_name: %OpenApiSpex.Schema{type: :string}
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
           validity_period: %OpenApiSpex.Schema{type: :string, example: "1y"},
           kind: %OpenApiSpex.Schema{
             type: :string,
             enum: ["credential", "document"],
             default: "credential",
             description:
               "`credential` is issued to a wallet over OID4VCI and bound to a holder key. " <>
                 "`document` is signed directly by the issuer, with no holder, and is the " <>
                 "only kind `POST /dashboard/issuer/documents` accepts."
           }
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

  operation(:revise_schema,
    summary: "Revise credential schema (new version)",
    description:
      "Insert a new version of an existing schema, preserving prior versions and credentials issued under them.",
    parameters: [
      schema_id: [in: :path, type: :string, description: "Schema identifier", required: true]
    ],
    request_body:
      {"Schema revision params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:name, :claims, :base_version],
         properties: %{
           name: %OpenApiSpex.Schema{type: :string},
           claims: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :object}},
           validity_period: %OpenApiSpex.Schema{type: :string, example: "1y"},
           base_version: %OpenApiSpex.Schema{
             type: :integer,
             description:
               "The version observed when editing began. Server rejects with 409 schema_revision_conflict if a newer version exists."
           }
         }
       }},
    responses: %{
      201 =>
        {"Schema revised", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             schema_id: %OpenApiSpex.Schema{type: :string},
             credential_type: %OpenApiSpex.Schema{type: :string},
             name: %OpenApiSpex.Schema{type: :string},
             claims: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :object}},
             validity_period: %OpenApiSpex.Schema{type: :string},
             version: %OpenApiSpex.Schema{type: :integer}
           }
         }},
      404 =>
        {"Schema not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      409 =>
        {"Revision conflict", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
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
         }},
      409 =>
        {"Schema is in use", "application/json",
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

  def create_issuer_account(
        conn,
        %{"email" => email, "password" => password, "issuer_name" => issuer_name} = params
      ) do
    full_name = Map.get(params, "full_name") || email |> String.split("@") |> hd()

    case Accounts.register_user(%{
           email: email,
           password: password,
           full_name: full_name,
           workspace_name: issuer_name
         }) do
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
    workspace_id = conn.assigns.current_user.workspace_id

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
    workspace_id = conn.assigns.current_user.workspace_id

    attrs = %{
      schema_id: params["schema_id"],
      credential_type: params["credential_type"],
      name: params["name"],
      claims: normalize_claims(params["claims"]),
      validity_period: to_string(params["validity_period"] || "1y"),
      kind: params["kind"] || "credential"
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
          validity_period: schema.validity_period,
          kind: schema.kind
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})

      {:error, :workspace_not_provisioned} ->
        conn |> put_status(409) |> json(%{error: "workspace_not_provisioned"})

      {:error, _reason} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  @error_object %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      error: %OpenApiSpex.Schema{type: :string},
      details: %OpenApiSpex.Schema{type: :object, nullable: true}
    }
  }

  operation(:update_layout,
    summary: "Save a document schema's page layout",
    description:
      "Where each field sits on the rendered page, for the latest version of a document " <>
        "schema. Presentation only: it creates no schema revision and is not covered by " <>
        "the signature. A revision copies the layout forward.",
    parameters: [
      schema_id: [in: :path, type: :string, description: "The schema's own id", required: true]
    ],
    request_body:
      {"Layout", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:layout],
         properties: %{
           layout: %OpenApiSpex.Schema{
             type: :object,
             description:
               "`page` sizes the sheet (A4 at 96dpi by default), `background` is a data URI, " <>
                 "and `elements` positions `field`, `text`, `line`, `box` and `image` entries. " <>
                 "Built by the dashboard's layout editor. 3 MB serialised, images included."
           }
         }
       }},
    responses: %{
      200 =>
        {"Layout saved", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             schema_id: %OpenApiSpex.Schema{type: :string},
             layout: %OpenApiSpex.Schema{type: :object}
           }
         }},
      404 => {"Schema not found", "application/json", @error_object},
      413 => {"Layout over 3 MB", "application/json", @error_object},
      422 => {"Not a document schema, or invalid layout", "application/json", @error_object}
    }
  )

  def update_layout(conn, %{"schema_id" => schema_id} = params) do
    workspace_id = conn.assigns.current_user.workspace_id

    case Documents.update_layout(workspace_id, schema_id, params["layout"]) do
      {:ok, record} ->
        json(conn, %{schema_id: schema_id, layout: record.layout})

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})

      {:error, {:wrong_schema_kind, kind}} ->
        conn
        |> put_status(422)
        |> json(%{
          error: "wrong_schema_kind",
          details: "layouts only apply to documents, got #{kind}"
        })

      {:error, :layout_too_large} ->
        conn
        |> put_status(413)
        |> json(%{
          error: "layout_too_large",
          details: "the layout, including embedded images, is over 3 MB"
        })

      {:error, :invalid_layout} ->
        conn |> put_status(422) |> json(%{error: "invalid_layout"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def list_schemas(conn, _params) do
    workspace_id = conn.assigns.current_user.workspace_id
    schemas = Issuer.list_schemas(workspace_id)
    # One query for every layout, rather than one per schema.
    layouts = Documents.layouts_for(Enum.map(schemas, & &1.id))

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
            version: s.version,
            kind: s.kind,
            layout: Map.get(layouts, s.id)
          }
        end)
    })
  end

  def revise_schema(conn, %{"schema_id" => schema_id} = params) do
    case parse_base_version(params["base_version"]) do
      :error ->
        conn
        |> put_status(422)
        |> json(%{
          error: "validation_error",
          details: %{base_version: ["must be a positive integer"]}
        })

      {:ok, base_version} ->
        workspace_id = conn.assigns.current_user.workspace_id

        attrs = %{
          name: params["name"],
          claims: normalize_claims(params["claims"]),
          validity_period: to_string(params["validity_period"] || "1y")
        }

        case Issuer.revise_schema(workspace_id, schema_id, base_version, attrs) do
          {:ok, schema} ->
            conn
            |> put_status(201)
            |> json(%{
              id: schema.id,
              schema_id: schema.schema_id,
              credential_type: schema.credential_type,
              name: schema.name,
              claims: schema.claims,
              validity_period: schema.validity_period,
              version: schema.version,
              kind: schema.kind
            })

          {:error, :schema_not_found} ->
            conn |> put_status(404) |> json(%{error: "schema_not_found"})

          {:error, :schema_revision_conflict} ->
            conn |> put_status(409) |> json(%{error: "schema_revision_conflict"})

          {:error, status} when status in [:workspace_inactive, :organization_inactive] ->
            conn |> put_status(403) |> json(%{error: to_string(status)})

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(422)
            |> json(%{error: "validation_error", details: changeset_errors(changeset)})
        end
    end
  end

  defp parse_base_version(v) when is_integer(v) and v >= 1, do: {:ok, v}
  defp parse_base_version(_), do: :error

  def delete_schema(conn, %{"id" => schema_id}) do
    case parse_uuid_or_404(conn, schema_id, "schema_not_found") do
      {:halt, conn} ->
        conn

      {:ok, schema_id} ->
        workspace_id = conn.assigns.current_user.workspace_id

        case Issuer.delete_schema(workspace_id, schema_id) do
          {:ok, _} ->
            conn |> put_status(204) |> text("")

          {:error, :schema_not_found} ->
            conn |> put_status(404) |> json(%{error: "schema_not_found"})

          {:error, :schema_in_use} ->
            conn |> put_status(409) |> json(%{error: "schema_in_use"})

          {:error, status} when status in [:workspace_inactive, :organization_inactive] ->
            conn |> put_status(403) |> json(%{error: to_string(status)})
        end
    end
  end

  operation(:get_design,
    summary: "Get credential design",
    description: "Get the credential design associated with a schema.",
    parameters: [
      schema_id: [in: :path, type: :string, description: "Schema identifier", required: true]
    ],
    responses: %{
      200 => {"Design", "application/json", %OpenApiSpex.Schema{type: :object}},
      404 =>
        {"Not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:upsert_design,
    summary: "Create or update credential design",
    description: "Create or update the credential design associated with a schema.",
    parameters: [
      schema_id: [in: :path, type: :string, description: "Schema identifier", required: true]
    ],
    request_body:
      {"Design params", "application/json",
       %OpenApiSpex.Schema{type: :object, description: "DIF-shaped output descriptor body"}},
    responses: %{
      200 => {"Design updated", "application/json", %OpenApiSpex.Schema{type: :object}},
      201 => {"Design created", "application/json", %OpenApiSpex.Schema{type: :object}},
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

  operation(:delete_design,
    summary: "Delete credential design",
    description: "Delete the credential design for a schema.",
    parameters: [
      schema_id: [in: :path, type: :string, description: "Schema identifier", required: true]
    ],
    responses: %{
      204 => {"Deleted", nil, nil},
      404 =>
        {"Not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  def get_design(conn, %{"schema_id" => schema_id}) do
    workspace_id = conn.assigns.current_user.workspace_id

    case Issuer.get_design(workspace_id, schema_id) do
      {:ok, design} -> json(conn, serialize_design(design))
      {:error, :schema_not_found} -> conn |> put_status(404) |> json(%{error: "schema_not_found"})
      {:error, :design_not_found} -> conn |> put_status(404) |> json(%{error: "design_not_found"})
    end
  end

  def upsert_design(conn, %{"schema_id" => schema_id} = params) do
    workspace_id = conn.assigns.current_user.workspace_id
    attrs = Map.drop(params, ["schema_id"])

    case Issuer.upsert_design(workspace_id, schema_id, attrs) do
      {:ok, design} ->
        conn |> put_status(200) |> json(serialize_design(design))

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def delete_design(conn, %{"schema_id" => schema_id}) do
    workspace_id = conn.assigns.current_user.workspace_id

    case Issuer.delete_design(workspace_id, schema_id) do
      {:ok, _} -> conn |> put_status(204) |> text("")
      {:error, :schema_not_found} -> conn |> put_status(404) |> json(%{error: "schema_not_found"})
      {:error, :design_not_found} -> conn |> put_status(404) |> json(%{error: "design_not_found"})
    end
  end

  defp serialize_design(design) do
    %{
      id: design.id,
      credential_schema_id: design.credential_schema_id,
      name: design.name,
      description: design.description,
      display: embed_to_map(design.display),
      styles: embed_to_map(design.styles),
      back: embed_to_map(design.back),
      version: design.version
    }
  end

  defp embed_to_map(nil), do: nil

  defp embed_to_map(struct) when is_struct(struct) do
    struct
    |> Map.from_struct()
    |> Map.drop([:__meta__])
    |> Map.new(fn {k, v} -> {k, embed_value(v)} end)
  end

  defp embed_value(nil), do: nil
  defp embed_value(list) when is_list(list), do: Enum.map(list, &embed_value/1)
  defp embed_value(%DateTime{} = dt), do: dt
  defp embed_value(%Date{} = d), do: d
  defp embed_value(%NaiveDateTime{} = dt), do: dt
  defp embed_value(struct) when is_struct(struct), do: embed_to_map(struct)
  defp embed_value(other), do: other

  def list_offers(conn, _params) do
    workspace_id = conn.assigns.current_user.workspace_id
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
              schema_id: o.schema.schema_id,
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
    case parse_uuid_or_404(conn, credential_id, "credential_not_found") do
      {:halt, conn} ->
        conn

      {:ok, credential_id} ->
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
  end

  @status_transitions %{
    "revoked" => &Sovra.Issuer.revoke_credential/2,
    "suspended" => &Sovra.Issuer.suspend_credential/2,
    "issued" => &Sovra.Issuer.unsuspend_credential/2
  }

  def update_credential_status(conn, %{"id" => credential_id, "status" => status}) do
    case parse_uuid_or_404(conn, credential_id, "credential_not_found") do
      {:halt, conn} ->
        conn

      {:ok, credential_id} ->
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

              {:error, :workspace_not_provisioned} ->
                conn |> put_status(409) |> json(%{error: "workspace_not_provisioned"})

              {:error, :invalid_status_transition} ->
                conn |> put_status(422) |> json(%{error: "invalid_status_transition"})

              {:error, reason} ->
                conn |> put_status(422) |> json(%{error: to_string(reason)})
            end

          :error ->
            conn |> put_status(400) |> json(%{error: "unknown_status"})
        end
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
        schema_id: c.schema.schema_id,
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

  # Validates a path UUID before it reaches Ecto. A malformed UUID would otherwise
  # raise Ecto.Query.CastError → unhandled 500. Returns either {:ok, uuid} for the
  # caller to continue, or {:halt, conn} with a 404 already rendered.
  defp parse_uuid_or_404(conn, id, error_code) do
    case Ecto.UUID.cast(id) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:halt, conn |> put_status(404) |> json(%{error: error_code})}
    end
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
