defmodule Sovra.WebhooksTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Crypto.StoredKey
  alias Sovra.Webhooks
  alias Sovra.Webhooks.DeliveryJob
  alias Sovra.Webhooks.Webhook
  alias Sovra.Workspaces.Workspace

  setup do
    on_exit(fn -> Application.delete_env(:sovra, :webhook_req_opts) end)
    %{workspace: fixture_workspace().workspace}
  end

  describe "create_webhook/2" do
    test "persists the endpoint and reveals its own secret once", %{workspace: ws} do
      {:ok, %{webhook: webhook, secret: secret}} =
        Webhooks.create_webhook(ws.id, %{
          "url" => "https://example.com/hook",
          "events" => ["credential.issued", "credential.revoked"]
        })

      assert webhook.workspace_id == ws.id
      assert webhook.url == "https://example.com/hook"
      assert webhook.events == ["credential.issued", "credential.revoked"]
      assert webhook.enabled
      assert String.starts_with?(secret, "whsec_")
      assert Repo.get_by(StoredKey, key_id: webhook.secret_key_id)
    end

    test "each endpoint gets a distinct secret", %{workspace: ws} do
      %{webhook: a, secret: secret_a} = fixture_webhook(ws)
      %{webhook: b, secret: secret_b} = fixture_webhook(ws)

      refute a.secret_key_id == b.secret_key_id
      refute secret_a == secret_b
    end

    test "ignores a client-supplied workspace_id and secret_key_id", %{workspace: ws} do
      other = fixture_workspace().workspace

      {:ok, %{webhook: webhook}} =
        Webhooks.create_webhook(ws.id, %{
          "url" => "https://example.com/hook",
          "events" => ["credential.issued"],
          "workspace_id" => other.id,
          "secret_key_id" => "webhook-chosen"
        })

      assert webhook.workspace_id == ws.id
      refute webhook.secret_key_id == "webhook-chosen"
    end

    test "deduplicates events", %{workspace: ws} do
      %{webhook: webhook} =
        fixture_webhook(ws, events: ["credential.issued", "credential.issued"])

      assert webhook.events == ["credential.issued"]
    end

    test "rejects an invalid URL, no events, and unknown events", %{workspace: ws} do
      assert {:error, cs} =
               Webhooks.create_webhook(ws.id, %{"url" => "not-a-url", "events" => []})

      assert %{url: [_], events: [_]} = errors_on(cs)

      assert {:error, cs} =
               Webhooks.create_webhook(ws.id, %{
                 "url" => "https://example.com/hook",
                 "events" => ["credential.issued", "credential.exploded"]
               })

      assert %{events: ["has an invalid entry"]} = errors_on(cs)
    end

    test "leaves no secret behind when validation fails", %{workspace: ws} do
      before = Repo.aggregate(StoredKey, :count)
      {:error, _} = Webhooks.create_webhook(ws.id, %{"url" => "nope", "events" => []})
      assert Repo.aggregate(StoredKey, :count) == before
    end

    test "caps endpoints per workspace", %{workspace: ws} do
      for _ <- 1..Webhooks.max_webhooks_per_workspace(), do: fixture_webhook(ws)

      assert {:error, :webhook_limit_reached} =
               Webhooks.create_webhook(ws.id, %{
                 url: "https://example.com/one-too-many",
                 events: ["credential.issued"]
               })

      # Another workspace's endpoints don't count against this one.
      assert %{webhook: _} = fixture_webhook(fixture_workspace().workspace)
    end

    test "refuses an inactive workspace", %{workspace: ws} do
      ws |> Workspace.status_changeset("suspended") |> Repo.update!()

      assert {:error, :workspace_inactive} =
               Webhooks.create_webhook(ws.id, %{
                 url: "https://example.com/hook",
                 events: ["credential.issued"]
               })
    end
  end

  describe "list_webhooks/1" do
    test "returns only the workspace's endpoints, oldest first", %{workspace: ws} do
      %{webhook: first} = fixture_webhook(ws)
      %{webhook: second} = fixture_webhook(ws)
      fixture_webhook(fixture_workspace().workspace)

      assert {:ok, [a, b]} = Webhooks.list_webhooks(ws.id)
      assert Enum.sort([a.id, b.id]) == Enum.sort([first.id, second.id])
    end
  end

  describe "update_webhook/3" do
    test "changes URL, events and enabled", %{workspace: ws} do
      %{webhook: webhook} = fixture_webhook(ws)

      {:ok, updated} =
        Webhooks.update_webhook(ws.id, webhook.id, %{
          "url" => "https://new.example.com/hook",
          "events" => ["presentation.verified"],
          "enabled" => false
        })

      assert updated.url == "https://new.example.com/hook"
      assert updated.events == ["presentation.verified"]
      refute updated.enabled
    end

    test "rejects clearing the events", %{workspace: ws} do
      %{webhook: webhook} = fixture_webhook(ws)
      assert {:error, cs} = Webhooks.update_webhook(ws.id, webhook.id, %{"events" => []})
      assert %{events: [_]} = errors_on(cs)
    end

    test "cannot reach another workspace's endpoint", %{workspace: ws} do
      %{webhook: foreign} = fixture_webhook(fixture_workspace().workspace)

      assert {:error, :webhook_not_found} =
               Webhooks.update_webhook(ws.id, foreign.id, %{"enabled" => false})

      assert Repo.reload!(foreign).enabled
    end
  end

  describe "delete_webhook/2" do
    test "removes the endpoint and its secret", %{workspace: ws} do
      %{webhook: webhook} = fixture_webhook(ws)

      assert {:ok, _} = Webhooks.delete_webhook(ws.id, webhook.id)
      refute Repo.get(Webhook, webhook.id)
      refute Repo.get_by(StoredKey, key_id: webhook.secret_key_id)
    end

    test "cannot reach another workspace's endpoint", %{workspace: ws} do
      %{webhook: foreign} = fixture_webhook(fixture_workspace().workspace)

      assert {:error, :webhook_not_found} = Webhooks.delete_webhook(ws.id, foreign.id)
      assert Repo.get(Webhook, foreign.id)
    end
  end

  describe "rotate_webhook_secret/2" do
    test "returns a new secret, which then signs deliveries", %{workspace: ws} do
      %{webhook: webhook, secret: original} = fixture_webhook(ws)

      assert {:ok, %{secret: rotated}} = Webhooks.rotate_webhook_secret(ws.id, webhook.id)
      refute rotated == original

      {:ok, [job]} = Webhooks.enqueue(ws.id, "credential.issued", %{"x" => 1})
      assert %{signature: sig, body: body} = deliver_capturing(job)
      assert sig == sign(rotated, body)
    end

    test "cannot reach another workspace's endpoint", %{workspace: ws} do
      %{webhook: foreign} = fixture_webhook(fixture_workspace().workspace)
      assert {:error, :webhook_not_found} = Webhooks.rotate_webhook_secret(ws.id, foreign.id)
    end
  end

  describe "enqueue/3" do
    test "enqueues one delivery per subscribed, enabled endpoint", %{workspace: ws} do
      %{webhook: all} = fixture_webhook(ws)
      %{webhook: issued_only} = fixture_webhook(ws, events: ["credential.issued"])
      fixture_webhook(ws, events: ["presentation.verified"])
      fixture_webhook(ws, enabled: false)
      fixture_webhook(fixture_workspace().workspace)

      {:ok, jobs} = Webhooks.enqueue(ws.id, "credential.issued", %{"credential_id" => "abc"})

      assert jobs |> Enum.map(& &1.args.webhook_id) |> Enum.sort() ==
               Enum.sort([all.id, issued_only.id])

      # One event, one id: a receiver behind two endpoints deduplicates on it.
      assert [payload_id] = jobs |> Enum.map(& &1.args.payload["id"]) |> Enum.uniq()

      assert_enqueued(
        worker: DeliveryJob,
        queue: :webhooks,
        args: %{
          "webhook_id" => issued_only.id,
          "workspace_id" => ws.id,
          "event" => "credential.issued",
          "delivery_id" => payload_id,
          "payload" => %{
            "id" => payload_id,
            "event" => "credential.issued",
            "workspace_id" => ws.id,
            "data" => %{"credential_id" => "abc"}
          }
        }
      )
    end

    test "enqueues nothing when no endpoint is subscribed", %{workspace: ws} do
      fixture_webhook(ws, events: ["presentation.verified"])

      assert {:ok, []} = Webhooks.enqueue(ws.id, "credential.issued", %{})
      refute_enqueued(worker: DeliveryJob)
    end

    test "rejects an event type outside the catalogue", %{workspace: ws} do
      assert_raise FunctionClauseError, fn ->
        Webhooks.enqueue(ws.id, "credential.exploded", %{})
      end
    end
  end

  describe "DeliveryJob.perform/1" do
    test "signs with the endpoint's own secret and posts", %{workspace: ws} do
      fixture_webhook(ws, events: ["credential.revoked"])
      %{secret: secret} = fixture_webhook(ws, events: ["credential.issued"])

      {:ok, [job]} = Webhooks.enqueue(ws.id, "credential.issued", %{"x" => 1})

      assert %{result: :ok, event: "credential.issued", signature: sig, body: body} =
               deliver_capturing(job)

      assert sig == sign(secret, body)
    end

    test "4xx response is discarded (won't retry)", %{workspace: ws} do
      stub_status(422)
      assert {:discard, {:client_error, 422}} = perform_one(ws)
    end

    test "5xx response retries", %{workspace: ws} do
      stub_status(503)
      assert {:error, {:remote_error, 503}} = perform_one(ws)
    end

    test "skips an endpoint deleted since the enqueue", %{workspace: ws} do
      %{webhook: webhook} = fixture_webhook(ws)
      {:ok, [job]} = Webhooks.enqueue(ws.id, "credential.issued", %{})
      {:ok, _} = Webhooks.delete_webhook(ws.id, webhook.id)

      assert :ok = perform_job(DeliveryJob, job.args)
    end

    test "skips an endpoint disabled or unsubscribed since the enqueue", %{workspace: ws} do
      stub_status(500)
      %{webhook: webhook} = fixture_webhook(ws)
      {:ok, [job]} = Webhooks.enqueue(ws.id, "credential.issued", %{})

      {:ok, _} = Webhooks.update_webhook(ws.id, webhook.id, %{enabled: false})
      assert :ok = perform_job(DeliveryJob, job.args)

      {:ok, _} =
        Webhooks.update_webhook(ws.id, webhook.id, %{
          enabled: true,
          events: ["credential.revoked"]
        })

      assert :ok = perform_job(DeliveryJob, job.args)
    end
  end

  describe "workspace creation" do
    test "starts with no endpoints" do
      %{workspace: ws} = fixture_workspace()
      assert {:ok, []} = Webhooks.list_webhooks(ws.id)
    end
  end

  defp perform_one(ws) do
    fixture_webhook(ws)
    {:ok, [job]} = Webhooks.enqueue(ws.id, "credential.issued", %{"x" => 1})
    perform_job(DeliveryJob, job.args)
  end

  defp stub_status(status) do
    Application.put_env(:sovra, :webhook_req_opts,
      plug: fn conn -> Plug.Conn.send_resp(conn, status, "") end
    )
  end

  # Delivers `job` against a plug that reports what it received back to the
  # test process.
  defp deliver_capturing(job) do
    test = self()

    Application.put_env(:sovra, :webhook_req_opts,
      plug: fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        [sig] = Plug.Conn.get_req_header(conn, "x-sovra-signature")
        [event] = Plug.Conn.get_req_header(conn, "x-sovra-event")
        send(test, {:delivered, %{signature: sig, body: body, event: event}})
        Plug.Conn.send_resp(conn, 200, "")
      end
    )

    result = perform_job(DeliveryJob, job.args)
    assert_received {:delivered, received}
    Map.put(received, :result, result)
  end

  defp sign(secret, body) do
    "sha256=" <> Base.encode16(:crypto.mac(:hmac, :sha256, secret, body), case: :lower)
  end
end
