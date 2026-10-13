defmodule SovraWeb.Workspaces.WebhookControllerTest do
  use SovraWeb.ConnCase, async: false

  alias Sovra.Auth.UserSession
  alias Sovra.Webhooks
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace

  setup do
    %{workspace: ws, owner: owner} = fixture_workspace()
    {:ok, token} = UserSession.create(owner.id, ws.id, owner.is_admin)
    %{workspace: ws, token: token}
  end

  defp authed(conn, token), do: put_req_header(conn, "authorization", "Bearer #{token}")

  defp webhooks_path(ws, suffix \\ ""), do: "/dashboard/workspaces/#{ws.id}/webhooks#{suffix}"

  test "admin creates, lists, updates, rotates and deletes an endpoint", %{
    conn: conn,
    workspace: ws,
    token: token
  } do
    created =
      conn
      |> authed(token)
      |> post(webhooks_path(ws), %{
        "url" => "https://example.com/hook",
        "events" => ["credential.issued", "presentation.verified"]
      })
      |> json_response(201)

    assert String.starts_with?(created["secret"], "whsec_")
    id = created["webhook"]["id"]

    assert %{
             "url" => "https://example.com/hook",
             "events" => ["credential.issued", "presentation.verified"],
             "enabled" => true
           } = created["webhook"]

    listed = build_conn() |> authed(token) |> get(webhooks_path(ws)) |> json_response(200)
    assert [%{"id" => ^id} = listed_webhook] = listed["webhooks"]
    refute Map.has_key?(listed_webhook, "secret")
    refute Map.has_key?(listed_webhook, "secret_key_id")

    updated =
      build_conn()
      |> authed(token)
      |> patch(webhooks_path(ws, "/#{id}"), %{
        "enabled" => false,
        "events" => ["credential.revoked"]
      })
      |> json_response(200)

    assert %{"enabled" => false, "events" => ["credential.revoked"]} = updated

    rotated =
      build_conn()
      |> authed(token)
      |> post(webhooks_path(ws, "/#{id}/rotate_secret"))
      |> json_response(200)

    assert String.starts_with?(rotated["secret"], "whsec_")
    refute rotated["secret"] == created["secret"]

    assert build_conn() |> authed(token) |> delete(webhooks_path(ws, "/#{id}")) |> response(204)
    assert {:ok, []} = Webhooks.list_webhooks(ws.id)
  end

  test "422 with details on invalid input", %{conn: conn, workspace: ws, token: token} do
    resp =
      conn
      |> authed(token)
      |> post(webhooks_path(ws), %{"url" => "ftp://nope", "events" => ["credential.exploded"]})
      |> json_response(422)

    assert %{"error" => "validation_error", "details" => %{"url" => _, "events" => _}} = resp
  end

  test "422 once the workspace has the maximum number of endpoints", %{
    conn: conn,
    workspace: ws,
    token: token
  } do
    for _ <- 1..Webhooks.max_webhooks_per_workspace(), do: fixture_webhook(ws)

    conn =
      conn
      |> authed(token)
      |> post(webhooks_path(ws), %{
        "url" => "https://example.com/hook",
        "events" => ["credential.issued"]
      })

    assert json_response(conn, 422) == %{"error" => "webhook_limit_reached"}
  end

  test "404 for another workspace's endpoint", %{conn: conn, workspace: ws, token: token} do
    %{webhook: foreign} = fixture_webhook(fixture_workspace().workspace)

    for req <- [
          &patch(&1, webhooks_path(ws, "/#{foreign.id}"), %{"enabled" => false}),
          &delete(&1, webhooks_path(ws, "/#{foreign.id}")),
          &post(&1, webhooks_path(ws, "/#{foreign.id}/rotate_secret"))
        ] do
      conn = conn |> recycle() |> authed(token) |> req.()
      assert json_response(conn, 404) == %{"error" => "webhook_not_found"}
    end

    assert Sovra.Repo.reload!(foreign).enabled
  end

  test "409 when the workspace is inactive", %{conn: conn, workspace: ws, token: token} do
    ws |> Workspace.status_changeset("suspended") |> Sovra.Repo.update!()

    conn = conn |> authed(token) |> get(webhooks_path(ws))
    assert json_response(conn, 409) == %{"error" => "workspace_inactive"}
  end

  test "a plain member gets 403", %{conn: conn, workspace: ws} do
    member = fixture_user()
    {:ok, _} = Workspaces.add_member(ws.id, member.id, "member")
    {:ok, token} = UserSession.create(member.id, ws.id, member.is_admin)

    conn = conn |> authed(token) |> get(webhooks_path(ws))
    assert json_response(conn, 403) == %{"error" => "workspace_admin_required"}
  end
end
