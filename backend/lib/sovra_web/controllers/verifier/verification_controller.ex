defmodule SovraWeb.Verifier.VerificationController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Verification

  tags(["Verifier OID4VP"])

  @request_body %OpenApiSpex.Schema{
    type: :object,
    required: [:dcql_query],
    properties: %{
      dcql_query: %OpenApiSpex.Schema{
        type: :object,
        description: "DCQL query specifying required credentials"
      }
    }
  }

  @response_body %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      session_id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      authorization_request_uri: %OpenApiSpex.Schema{
        type: :string,
        description: "Pass-by-value URI \u2014 self-contained, all parameters inline."
      },
      authorization_request_uri_ref: %OpenApiSpex.Schema{
        type: :string,
        description:
          "Pass-by-reference URI \u2014 short, points at /api/v1/verify/request/:id which serves the full request object as JSON. Use when DCQL queries grow large enough to make the QR dense."
      },
      status: %OpenApiSpex.Schema{type: :string},
      expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"}
    }
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  operation(:create,
    summary: "Create OID4VP verification session",
    description:
      "Create a verification session with a DCQL query. Returns a session id " <>
        "and an OID4VP authorization request URI presentable as a QR code.",
    request_body: {"Verification request", "application/json", @request_body},
    responses: %{
      201 => {"Session created", "application/json", @response_body},
      400 => {"Missing or invalid DCQL", "application/json", @error},
      401 => {"Missing or invalid auth", "application/json", @error},
      403 => {"Workspace or organization inactive", "application/json", @error},
      404 => {"Workspace not found", "application/json", @error}
    }
  )

  def create(conn, params) do
    workspace_id = conn.assigns.current_workspace_id

    case fetch_dcql(params) do
      {:ok, dcql} ->
        handle_create(conn, workspace_id, dcql)

      {:error, code} ->
        conn |> put_status(400) |> json(%{error: code})
    end
  end

  @session_view %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      session_id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      status: %OpenApiSpex.Schema{type: :string},
      dcql_query: %OpenApiSpex.Schema{type: :object},
      holder_did: %OpenApiSpex.Schema{type: :string, nullable: true},
      presentation_data: %OpenApiSpex.Schema{type: :object, nullable: true},
      error: %OpenApiSpex.Schema{type: :string, nullable: true},
      expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
      completed_at: %OpenApiSpex.Schema{
        type: :string,
        format: :"date-time",
        nullable: true
      },
      inserted_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"}
    }
  }

  @list_response %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      sessions: %OpenApiSpex.Schema{type: :array, items: @session_view},
      limit: %OpenApiSpex.Schema{type: :integer},
      offset: %OpenApiSpex.Schema{type: :integer}
    }
  }

  operation(:show,
    summary: "Get an OID4VP verification session",
    description:
      "Fetch the current state of a verification session owned by the authenticated workspace.",
    parameters: [id: [in: :path, type: :string, required: true]],
    responses: %{
      200 => {"Session", "application/json", @session_view},
      401 => {"Missing or invalid auth", "application/json", @error},
      403 => {"Workspace or organization inactive", "application/json", @error},
      404 => {"Session not found", "application/json", @error}
    }
  )

  def show(conn, %{"id" => id}) do
    workspace_id = conn.assigns.current_workspace_id

    case Verification.get_session(workspace_id, id) do
      {:ok, session} ->
        json(conn, render_session(session))

      {:error, :session_not_found} ->
        conn |> put_status(404) |> json(%{error: "session_not_found"})

      {:error, :workspace_inactive} ->
        conn |> put_status(403) |> json(%{error: "workspace_inactive"})

      {:error, :organization_inactive} ->
        conn |> put_status(403) |> json(%{error: "organization_inactive"})

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "workspace_not_found"})
    end
  end

  operation(:index,
    summary: "List OID4VP verification sessions",
    description:
      "List sessions owned by the authenticated workspace, newest first. " <>
        "Optional `status` filter and `limit` / `offset` pagination (default " <>
        "limit 50, max 200).",
    parameters: [
      status: [in: :query, type: :string, required: false],
      limit: [in: :query, type: :integer, required: false],
      offset: [in: :query, type: :integer, required: false]
    ],
    responses: %{
      200 => {"Session list", "application/json", @list_response},
      401 => {"Missing or invalid auth", "application/json", @error},
      403 => {"Workspace or organization inactive", "application/json", @error}
    }
  )

  def index(conn, params) do
    workspace_id = conn.assigns.current_workspace_id

    opts =
      []
      |> maybe_put(:status, params["status"])
      |> maybe_put(:limit, parse_int(params["limit"]))
      |> maybe_put(:offset, parse_int(params["offset"]))

    case Verification.list_sessions(workspace_id, opts) do
      {:ok, sessions} ->
        json(conn, %{
          sessions: Enum.map(sessions, &render_session/1),
          limit: Keyword.get(opts, :limit, 50),
          offset: Keyword.get(opts, :offset, 0)
        })

      {:error, :workspace_inactive} ->
        conn |> put_status(403) |> json(%{error: "workspace_inactive"})

      {:error, :organization_inactive} ->
        conn |> put_status(403) |> json(%{error: "organization_inactive"})

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "workspace_not_found"})
    end
  end

  defp render_session(s) do
    %{
      session_id: s.id,
      status: s.status,
      dcql_query: s.dcql_query,
      holder_did: s.holder_did,
      presentation_data: s.presentation_data,
      error: s.error,
      expires_at: DateTime.to_iso8601(s.expires_at),
      completed_at: s.completed_at && DateTime.to_iso8601(s.completed_at),
      inserted_at: DateTime.to_iso8601(s.inserted_at)
    }
  end

  defp maybe_put(opts, _key, nil), do: opts
  defp maybe_put(opts, key, value), do: Keyword.put(opts, key, value)

  defp parse_int(nil), do: nil
  defp parse_int(v) when is_integer(v), do: v

  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, ""} -> n
      _ -> nil
    end
  end

  defp parse_int(_), do: nil

  defp fetch_dcql(%{"dcql_query" => dcql}) when is_map(dcql), do: {:ok, dcql}
  defp fetch_dcql(%{"dcql_query" => _}), do: {:error, "invalid_dcql_query"}
  defp fetch_dcql(_), do: {:error, "missing_dcql_query"}

  defp handle_create(conn, workspace_id, dcql) do
    case Verification.create_session(workspace_id, dcql) do
      {:ok, %{session: s, authorization_request_uri: uri, authorization_request_uri_ref: uri_ref}} ->
        conn
        |> put_status(201)
        |> json(%{
          session_id: s.id,
          authorization_request_uri: uri,
          authorization_request_uri_ref: uri_ref,
          status: s.status,
          expires_at: DateTime.to_iso8601(s.expires_at)
        })

      {:error, :invalid_dcql_query} ->
        conn |> put_status(400) |> json(%{error: "invalid_dcql_query"})

      {:error, :workspace_inactive} ->
        conn |> put_status(403) |> json(%{error: "workspace_inactive"})

      {:error, :workspace_not_provisioned} ->
        conn |> put_status(409) |> json(%{error: "workspace_not_provisioned"})

      {:error, :organization_inactive} ->
        conn |> put_status(403) |> json(%{error: "organization_inactive"})

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "workspace_not_found"})

      {:error, %Ecto.Changeset{}} ->
        conn |> put_status(422) |> json(%{error: "validation_error"})
    end
  end
end
