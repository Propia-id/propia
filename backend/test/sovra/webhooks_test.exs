defmodule Sovra.WebhooksTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Webhooks
  alias Sovra.Webhooks.DeliveryJob

  defp create_workspace(webhook_url) do
    fixture_workspace(name: "Acme", webhook_url: webhook_url).workspace
  end

  describe "enqueue/3" do
    test "inserts an Oban job with the expected payload shape" do
      ws = create_workspace("https://example.com/hook")

      {:ok, _job} =
        Webhooks.enqueue(ws.id, "credential.issued", %{"credential_id" => "abc"})

      assert_enqueued(
        worker: DeliveryJob,
        queue: :webhooks,
        args: %{
          "workspace_id" => ws.id,
          "event" => "credential.issued",
          "payload" => %{
            "event" => "credential.issued",
            "workspace_id" => ws.id,
            "data" => %{"credential_id" => "abc"}
          }
        }
      )
    end
  end

  describe "DeliveryJob.perform/1" do
    test "no-op when the workspace has no webhook_url" do
      ws = create_workspace(nil)

      {:ok, job} = Webhooks.enqueue(ws.id, "credential.issued", %{"x" => 1})
      assert :ok = perform_job(DeliveryJob, job.args)
    end

    test "discards when the workspace doesn't exist" do
      args = %{
        "workspace_id" => Ecto.UUID.generate(),
        "event" => "credential.issued",
        "payload" => %{"event" => "credential.issued"}
      }

      assert {:discard, :workspace_not_found} = perform_job(DeliveryJob, args)
    end

    test "signs and posts; 2xx → :ok" do
      Req.Test.stub(:sovra_webhook_client, fn conn ->
        assert Plug.Conn.get_req_header(conn, "x-sovra-event") == ["credential.issued"]
        assert [sig] = Plug.Conn.get_req_header(conn, "x-sovra-signature")
        assert String.starts_with?(sig, "sha256=")
        Req.Test.json(conn, %{ok: true})
      end)

      assert :ok = run_delivery_against_stub()
    end

    test "4xx response is discarded (won't retry)" do
      Req.Test.stub(:sovra_webhook_client, fn conn ->
        conn |> Plug.Conn.put_status(422) |> Req.Test.json(%{error: "bad"})
      end)

      assert {:discard, {:client_error, 422}} = run_delivery_against_stub()
    end

    test "5xx response retries" do
      Req.Test.stub(:sovra_webhook_client, fn conn ->
        conn |> Plug.Conn.put_status(503) |> Req.Test.json(%{error: "oops"})
      end)

      assert {:error, {:remote_error, 503}} = run_delivery_against_stub()
    end
  end

  # Helper: fires the job through a Req.Test plug so outbound HTTP is captured.
  # Uses a local endpoint URL; the stub's response dictates the outcome.
  defp run_delivery_against_stub do
    ws =
      create_workspace("http://unused-but-intercepted.example")
      |> apply_req_plug()

    {:ok, job} = Webhooks.enqueue(ws.id, "credential.issued", %{"x" => 1})
    perform_job(DeliveryJob, job.args)
  end

  defp apply_req_plug(workspace) do
    Application.put_env(:sovra, :webhook_req_opts, plug: {Req.Test, :sovra_webhook_client})
    workspace
  end
end
