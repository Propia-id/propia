defmodule Sovra.Webhooks.DeliveryJob do
  @moduledoc """
  Oban worker that delivers a signed webhook POST to a workspace's configured
  `webhook_url`. The HMAC signature is computed by `Sovra.Crypto.HmacKeyStore`
  (`DatabaseHmacStore` — the secret is stored so it can be revealed to the
  customer once, since KMS HMAC keys are non-exportable).

  Retry semantics:
  - 2xx → success.
  - 4xx → `:discard` (consumer bug, not transient; retrying won't help).
  - 5xx / transport error / timeout → raise → Oban retries with backoff up
    to `max_attempts` (configured at enqueue time, default 8).
  """

  use Oban.Worker, queue: :webhooks, max_attempts: 8

  alias Sovra.Crypto.HmacKeyStore
  alias Sovra.Repo
  alias Sovra.Workspaces.Workspace

  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{
        args: %{"workspace_id" => workspace_id, "event" => event, "payload" => payload}
      }) do
    case Repo.get(Workspace, workspace_id) do
      nil ->
        {:discard, :workspace_not_found}

      %Workspace{webhook_url: nil} ->
        :ok

      %Workspace{webhook_secret_key_id: nil} ->
        {:discard, :webhook_secret_not_configured}

      %Workspace{webhook_url: url, webhook_secret_key_id: key_id} ->
        deliver(url, key_id, event, payload)
    end
  end

  defp deliver(url, key_id, event, payload) do
    body = Jason.encode!(payload)

    with {:ok, sig} <- HmacKeyStore.hmac(key_id, body),
         signature_header = "sha256=" <> Base.encode16(sig, case: :lower),
         start = System.monotonic_time(),
         req_opts =
           Keyword.merge(
             [
               body: body,
               headers: [
                 {"content-type", "application/json"},
                 {"x-sovra-signature", signature_header},
                 {"x-sovra-event", event}
               ],
               receive_timeout: 5_000,
               retry: false
             ],
             Application.get_env(:sovra, :webhook_req_opts, [])
           ),
         {:ok, resp} <- Req.post(url, req_opts) do
      duration = System.monotonic_time() - start

      :telemetry.execute(
        [:sovra, :webhook, :delivery],
        %{duration: duration},
        %{event: event, status: resp.status}
      )

      classify(resp.status, event)
    else
      {:error, reason} ->
        Logger.warning("Webhook delivery transport error: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp classify(status, _event) when status in 200..299, do: :ok

  defp classify(status, event) when status in 400..499 do
    Logger.warning("Webhook delivery got #{status} for event #{event}; discarding")
    {:discard, {:client_error, status}}
  end

  defp classify(status, _event), do: {:error, {:remote_error, status}}
end
