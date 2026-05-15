defmodule Sovra.Crypto.VaultTokenRenewer do
  @moduledoc """
  Periodically renews the OpenBao/Vault periodic token to prevent expiration.

  The token value itself doesn't change — renewal just extends the TTL.

  Behaviour:
  - On boot, immediately attempts a renewal (non-blocking) so every restart
    extends the token's lifetime. This is what keeps the token healthy on
    environments that restart more often than the periodic interval.
  - On success, logs at `:info` (visible in prod) and schedules the next
    renewal at `interval`.
  - On failure, logs at `:error` for the first failure of a streak (so it
    shows in the default prod filter), `:warning` for subsequent retries,
    and reschedules at `retry_interval` for the first
    `max_consecutive_failures` attempts. After that it falls back to
    `degraded_interval` — a *bounded* sustained cadence (default 10 min)
    so the renewer keeps trying within the token's `period` window
    instead of going silent until the next full `interval` tick. The
    journal therefore shows a steady warning heartbeat for the duration
    of an outage, and the token has a fighting chance of being renewed
    before its `period` elapses.
  """

  use GenServer

  require Logger

  # Default: renew every 48 hours (for a 96h-period token)
  @default_interval_ms 48 * 60 * 60 * 1000
  @default_retry_interval_ms 60 * 1000
  @default_degraded_interval_ms 10 * 60 * 1000
  @default_max_consecutive_failures 5

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    config = renewer_config()

    state = %{
      interval: config.interval,
      retry_interval: config.retry_interval,
      degraded_interval: config.degraded_interval,
      max_consecutive_failures: config.max_consecutive_failures,
      consecutive_failures: 0
    }

    Logger.info(
      "VaultTokenRenewer started, renewing every #{div(state.interval, 3_600_000)} hours"
    )

    # Trigger an immediate renewal so every restart extends the token. Done
    # via send/2 rather than synchronously inside init/1 so a transient Vault
    # outage at boot doesn't keep the supervision tree from starting.
    send(self(), :renew)

    {:ok, state}
  end

  @impl true
  def handle_info(:renew, state) do
    new_state =
      case renew_token() do
        {:ok, info} ->
          suffix = format_renew_info(info)

          if state.consecutive_failures > 0 do
            Logger.info(
              "Vault token renewed (recovered after #{state.consecutive_failures} failure(s))" <>
                suffix
            )
          else
            Logger.info("Vault token renewed" <> suffix)
          end

          schedule_renewal(state.interval)
          %{state | consecutive_failures: 0}

        {:error, reason} ->
          failures = state.consecutive_failures + 1

          if failures == 1 do
            Logger.error(
              "Vault token renewal failed (consecutive=#{failures}): #{inspect(reason)}"
            )
          else
            Logger.warning(
              "Vault token renewal failed (consecutive=#{failures}): #{inspect(reason)}"
            )
          end

          next_in =
            if failures >= state.max_consecutive_failures do
              state.degraded_interval
            else
              state.retry_interval
            end

          schedule_renewal(next_in)
          %{state | consecutive_failures: failures}
      end

    {:noreply, new_state}
  end

  defp schedule_renewal(interval) do
    Process.send_after(self(), :renew, interval)
  end

  defp renew_token do
    do_renew_token()
  rescue
    e ->
      {:error, {:vault_renew_exception, Exception.message(e)}}
  catch
    :exit, reason ->
      {:error, {:vault_renew_exit, inspect(reason)}}
  end

  defp do_renew_token do
    config = Application.fetch_env!(:sovra, :vault)
    url = Keyword.fetch!(config, :url)
    token = Keyword.fetch!(config, :token)
    req_opts = Keyword.get(config, :vault_req_opts, [])

    opts =
      Keyword.merge(
        [
          url: "#{url}/v1/auth/token/renew-self",
          headers: [{"x-vault-token", token}],
          json: %{}
        ],
        req_opts
      )

    case Req.post(opts) do
      {:ok, %{status: 200, body: body}} -> {:ok, parse_renew_response(body)}
      {:ok, %{status: status, body: body}} -> {:error, {:vault_renew_error, status, body}}
      {:error, reason} -> {:error, {:vault_renew_error, reason}}
    end
  end

  # Pulls `policies` and `lease_duration` out of Vault's renew-self response.
  # Surfacing these in the success log catches the wrong-policy class of bug
  # where `renew-self` keeps succeeding (it's in the `default` policy) while
  # the token can't actually do anything else, and gives operators a TTL
  # heartbeat without needing a separate metrics pipeline.
  defp parse_renew_response(%{"auth" => auth}) when is_map(auth) do
    %{
      policies: auth["policies"] || auth["token_policies"],
      lease_duration: auth["lease_duration"]
    }
  end

  defp parse_renew_response(_), do: %{policies: nil, lease_duration: nil}

  defp format_renew_info(%{policies: policies, lease_duration: ttl}) do
    parts =
      []
      |> maybe_part(policies, fn p -> "policies=#{inspect(p)}" end)
      |> maybe_part(ttl, fn t -> "ttl=#{t}s" end)
      |> Enum.reverse()

    case parts do
      [] -> ""
      _ -> " (" <> Enum.join(parts, ", ") <> ")"
    end
  end

  defp maybe_part(acc, nil, _fmt), do: acc
  defp maybe_part(acc, value, fmt), do: [fmt.(value) | acc]

  defp renewer_config do
    config = Application.get_env(:sovra, :vault, [])

    %{
      interval: Keyword.get(config, :token_renewal_interval_ms, @default_interval_ms),
      retry_interval:
        Keyword.get(config, :token_renewal_retry_interval_ms, @default_retry_interval_ms),
      degraded_interval:
        Keyword.get(
          config,
          :token_renewal_degraded_interval_ms,
          @default_degraded_interval_ms
        ),
      max_consecutive_failures:
        Keyword.get(
          config,
          :token_renewal_max_consecutive_failures,
          @default_max_consecutive_failures
        )
    }
  end
end
