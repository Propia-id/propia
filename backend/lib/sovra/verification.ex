defmodule Sovra.Verification do
  @moduledoc """
  OpenID4VP credential verification — verification session lifecycle.

  A verifier workspace creates a session with a DCQL query specifying which
  credentials are required. The system generates an OID4VP authorization
  request URI (presentable as a QR code). The wallet responds via direct_post
  to the response endpoint, which is handled in a later phase.
  """

  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Repo
  alias Sovra.Verification.Session
  alias Sovra.Verification.Verifier
  alias Sovra.Workspaces

  import Ecto.Query

  @session_ttl_seconds 600
  @list_default_limit 50
  @list_max_limit 200

  @doc """
  Submit a holder-signed vp_token against a pending verification session
  (looked up by its `state` parameter). Delegates to
  `Sovra.Verification.Verifier`. See that module for the full pipeline.
  """
  defdelegate submit_presentation(session_state, vp_token, opts \\ []), to: Verifier

  @doc """
  Look up a session by its public `state` value (used by the direct_post
  handler to map a wallet response to its session).
  """
  def get_session_by_state(state) when is_binary(state) do
    case Repo.get_by(Session, state: state) do
      nil -> {:error, :session_not_found}
      session -> {:ok, session}
    end
  end

  @doc """
  Look up a session by its UUID.
  """
  def get_session(id) when is_binary(id) do
    case Repo.get(Session, id) do
      nil -> {:error, :session_not_found}
      session -> {:ok, session}
    end
  end

  @doc """
  Workspace-scoped session lookup. Verifies the session belongs to the
  active workspace; returns `{:error, :session_not_found}` for cross-tenant
  access (we don't disclose existence).
  """
  def get_session(workspace_id, id) when is_binary(workspace_id) and is_binary(id) do
    with {:ok, _workspace} <- Workspaces.get_active_workspace(workspace_id) do
      case Repo.get_by(Session, id: id, workspace_id: workspace_id) do
        nil -> {:error, :session_not_found}
        session -> {:ok, session}
      end
    end
  end

  @doc """
  List verification sessions for a workspace, newest first. Optional
  `:status` filter and `:limit` / `:offset` pagination (default limit 50,
  max 200).
  """
  def list_sessions(workspace_id, opts \\ []) when is_binary(workspace_id) do
    with {:ok, _workspace} <- Workspaces.get_active_workspace(workspace_id) do
      limit =
        opts
        |> Keyword.get(:limit, @list_default_limit)
        |> min(@list_max_limit)
        |> max(1)

      offset = opts |> Keyword.get(:offset, 0) |> max(0)

      query =
        from s in Session,
          where: s.workspace_id == ^workspace_id,
          order_by: [desc: s.inserted_at],
          limit: ^limit,
          offset: ^offset

      query =
        case Keyword.get(opts, :status) do
          nil ->
            query

          status when status in ~w(pending completed failed expired) ->
            from s in query, where: s.status == ^status

          _ ->
            query
        end

      {:ok, Repo.all(query)}
    end
  end

  @doc """
  Create a new verification session for the given workspace.

  Returns `{:ok, %{session, authorization_request_uri}}` on success, or one of:
  `{:error, :workspace_not_found}`, `{:error, :workspace_inactive}`,
  `{:error, :organization_inactive}`, `{:error, :invalid_dcql_query}`,
  `{:error, %Ecto.Changeset{}}`.
  """
  def create_session(workspace_id, dcql_query, opts \\ []) when is_map(dcql_query) do
    ttl = Keyword.get(opts, :ttl_seconds, @session_ttl_seconds)

    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id),
         :ok <- Workspaces.assert_provisioned(workspace),
         :ok <- validate_dcql(dcql_query) do
      nonce = random_token(16)
      state = random_token(16)

      expires_at =
        DateTime.utc_now() |> DateTime.add(ttl, :second) |> DateTime.truncate(:second)

      changeset =
        Session.create_changeset(%{
          workspace_id: workspace.id,
          dcql_query: dcql_query,
          nonce: nonce,
          state: state,
          expires_at: expires_at
        })

      with {:ok, session} <- Repo.insert(changeset) do
        uri = build_authorization_request_uri(session, workspace)
        uri_ref = build_authorization_request_uri_ref(session, workspace)

        {:ok,
         %{
           session: session,
           authorization_request_uri: uri,
           authorization_request_uri_ref: uri_ref
         }}
      end
    end
  end

  defp validate_dcql(%{"credentials" => [_ | _]}), do: :ok
  defp validate_dcql(_), do: {:error, :invalid_dcql_query}

  defp build_authorization_request_uri(session, workspace) do
    params = URI.encode_query(build_request_params(session, workspace, json: true))
    "openid4vp://?" <> params
  end

  @doc """
  Build the OID4VP authorization request object for a session, suitable for
  returning as JSON from the pass-by-reference `request_uri` endpoint. The
  same fields are embedded inline in the pass-by-value URI form.
  """
  def build_request_object(%Session{} = session, workspace) do
    build_request_params(session, workspace, json: false)
  end

  defp build_request_params(session, workspace, opts) do
    base = ClaimUtils.base_url()
    response_uri = "#{base}/wallet/verifier/direct_post/#{session.id}"
    json_dcql? = Keyword.get(opts, :json, false)

    %{
      "client_id" => "verifier:#{workspace.id}",
      "response_type" => "vp_token",
      "response_mode" => "direct_post",
      "response_uri" => response_uri,
      "nonce" => session.nonce,
      "state" => session.state,
      "dcql_query" =>
        if(json_dcql?, do: Jason.encode!(session.dcql_query), else: session.dcql_query)
    }
  end

  @doc """
  Build the short-form OID4VP URI that points at this server's
  pass-by-reference request endpoint.
  """
  def build_authorization_request_uri_ref(%Session{} = session, workspace) do
    base = ClaimUtils.base_url()
    request_uri = "#{base}/wallet/verifier/request/#{session.id}"

    params =
      URI.encode_query(%{
        "client_id" => "verifier:#{workspace.id}",
        "request_uri" => request_uri
      })

    "openid4vp://?" <> params
  end

  defp random_token(bytes) do
    :crypto.strong_rand_bytes(bytes) |> Base.url_encode64(padding: false)
  end
end
