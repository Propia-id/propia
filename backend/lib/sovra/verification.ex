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
  alias Sovra.Verification.RequestObject
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
  `{:error, %Ecto.Changeset{}}`, or whatever the signer returns when the
  request object cannot be signed — a session with no signed request is no
  session at all, so nothing is persisted in that case.
  """
  def create_session(workspace_id, dcql_query, opts \\ []) when is_map(dcql_query) do
    ttl = Keyword.get(opts, :ttl_seconds, @session_ttl_seconds)

    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id),
         :ok <- Workspaces.assert_provisioned(workspace),
         :ok <- validate_dcql(dcql_query),
         draft = draft_session(workspace, dcql_query, ttl),
         {:ok, request_object} <- RequestObject.sign(workspace, draft),
         {:ok, session} <- insert_session(draft, workspace, request_object) do
      {:ok,
       %{
         session: session,
         authorization_request_uri: build_authorization_request_uri(session),
         authorization_request_uri_ref: build_authorization_request_uri_ref(session)
       }}
    end
  end

  # The id is minted here rather than by the insert because it is part of the
  # `response_uri` the request object commits to: the request has to be signed
  # before the row it belongs to exists.
  defp draft_session(workspace, dcql_query, ttl) do
    %Session{
      id: Ecto.UUID.generate(),
      workspace_id: workspace.id,
      dcql_query: dcql_query,
      nonce: random_token(16),
      state: random_token(16),
      expires_at: DateTime.utc_now() |> DateTime.add(ttl, :second) |> DateTime.truncate(:second)
    }
  end

  defp insert_session(%Session{} = draft, workspace, request_object) do
    %Session{id: draft.id}
    |> Session.create_changeset(%{
      workspace_id: draft.workspace_id,
      dcql_query: draft.dcql_query,
      nonce: draft.nonce,
      state: draft.state,
      expires_at: draft.expires_at,
      client_id: RequestObject.client_id(workspace),
      request_object: request_object
    })
    |> Repo.insert()
  end

  defp validate_dcql(%{"credentials" => [_ | _]}), do: :ok
  defp validate_dcql(_), do: {:error, :invalid_dcql_query}

  @doc """
  Build the pass-by-value OID4VP URI for a session: the signed request object
  inline as `request`, alongside the `client_id` OID4VP requires to appear as
  a query parameter as well.

  Returns `nil` for a session minted before request signing landed, which has
  no request object to carry — such a session has at most its 10-minute TTL
  left to live.
  """
  def build_authorization_request_uri(%Session{request_object: jwt} = session)
      when is_binary(jwt) do
    "openid4vp://?" <>
      URI.encode_query(%{"client_id" => session.client_id, "request" => jwt})
  end

  def build_authorization_request_uri(%Session{}), do: nil

  @doc """
  The signed OID4VP authorization request (JAR) for a session, as served by the
  pass-by-reference `request_uri` endpoint. `nil` for a session minted before
  request signing landed.
  """
  def build_request_object(%Session{request_object: jwt}), do: jwt

  @doc """
  Build the short-form OID4VP URI that points at this server's
  pass-by-reference request endpoint. The QR stays small; the wallet fetches
  the signed request object from `request_uri`.
  """
  def build_authorization_request_uri_ref(%Session{request_object: jwt} = session)
      when is_binary(jwt) do
    request_uri = "#{ClaimUtils.base_url()}/wallet/verifier/request/#{session.id}"

    "openid4vp://?" <>
      URI.encode_query(%{"client_id" => session.client_id, "request_uri" => request_uri})
  end

  def build_authorization_request_uri_ref(%Session{}), do: nil

  defp random_token(bytes) do
    :crypto.strong_rand_bytes(bytes) |> Base.url_encode64(padding: false)
  end
end
