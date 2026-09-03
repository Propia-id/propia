defmodule Sovra.ObanLoggerTest do
  @moduledoc """
  Oban's default logger is attached for `journalctl` only. Its payload carries
  no `message` key, so when it is emitted as a JSON *string* New Relic parses it
  into attributes and files a blank-message record — two per job, plus two a
  minute forever from the ExpiredSessionsSweeper cron. `encode: false` makes it
  a report instead, which `NewRelic.LogsInContext` does not forward.

  This asserts the shape rather than the option, because the shape is what
  decides whether these reach New Relic.
  """

  use Sovra.DataCase, async: false

  defmodule Probe do
    @moduledoc false
    def log(%{msg: msg, meta: meta}, %{config: %{pid: pid}}) do
      send(pid, {:probe, msg, meta[:domain]})
      :ok
    end
  end

  test "job logs are reports, so New Relic never sees them" do
    handler = :"probe_#{System.unique_integer([:positive])}"

    :ok =
      :logger.add_handler(handler, Probe, %{level: :all, config: %{pid: self()}})

    on_exit(fn -> :logger.remove_handler(handler) end)

    %{workspace_id: Ecto.UUID.generate()}
    |> Sovra.Workspaces.WorkspaceProvisioningJob.new()
    |> Oban.insert()

    Oban.drain_queue(queue: :provisioning, with_safety: false)

    oban_logs = drain([])
    assert oban_logs != [], "expected Oban's default logger to be attached"

    for {msg, domain} <- oban_logs do
      # A {:string, _} here would be the JSON form, which New Relic parses into
      # a record with an empty message column.
      assert match?({:report, _}, msg),
             "Oban log reached the handler as #{inspect(elem(msg, 0))}, not a report"

      # LogsInContext forwards a report only when the domain is exactly
      # [:elixir]; anything else falls through to its catch-all `:ignore`.
      assert domain == [:elixir, :oban]
      refute domain == [:elixir]
    end
  end

  defp drain(acc) do
    receive do
      {:probe, msg, domain} ->
        if is_list(domain) and :oban in domain,
          do: drain([{msg, domain} | acc]),
          else: drain(acc)
    after
      0 -> acc
    end
  end
end
