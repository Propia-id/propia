defmodule Sovra.LogHelpers do
  @moduledoc """
  Assertions over the structured events emitted by `Sovra.Log`.

  These read the events' *metadata*, not formatted text, because that is what
  New Relic alert conditions read: an assertion on the rendered message would
  pass while the attribute an alert matches on was missing. `capture_events/1`
  installs a `:logger` handler that keeps each event's level, message and
  metadata intact.

      {conn, events} = capture_events(fn -> post(conn, ~p"/dashboard/auth/login", params) end)
      assert_event(events, "auth.login.failed", email_domain: "example.com")

  Note that a `:logger` handler is global: with `async: true`, events emitted
  by concurrently running tests are also collected. Always assert on an event
  name plus enough metadata to identify your own event, and prefer
  `assert_event/3` over counting.
  """

  import ExUnit.Assertions

  @doc """
  Runs `fun`, returning `{result, events}` where `events` is every `Sovra.Log`
  event emitted while it ran, oldest first.
  """
  def capture_events(fun) when is_function(fun, 0) do
    ref = make_ref()
    handler_id = :"sovra_log_capture_#{System.unique_integer([:positive])}"

    :ok =
      :logger.add_handler(handler_id, __MODULE__, %{
        level: :all,
        config: %{pid: self(), ref: ref}
      })

    try do
      result = fun.()
      # The handler runs synchronously in the logging process, so everything
      # logged before fun/0 returned is already in the mailbox.
      {result, drain(ref, [])}
    after
      :logger.remove_handler(handler_id)
    end
  end

  @doc """
  Asserts that `events` contains an event named `name` whose metadata contains
  every key/value in `expected`. Returns the matching event.
  """
  def assert_event(events, name, expected \\ []) do
    candidates = Enum.filter(events, &(&1.metadata[:event] == name))

    matching = Enum.filter(candidates, &metadata_matches?(&1, expected))

    case matching do
      [event | _] ->
        event

      [] ->
        flunk("""
        expected an event #{inspect(name)}#{describe(expected)}

        events named #{inspect(name)}: #{inspect(Enum.map(candidates, & &1.metadata), pretty: true)}
        all events seen: #{inspect(Enum.map(events, & &1.metadata[:event]))}
        """)
    end
  end

  @doc "Asserts that no event named `name` was emitted."
  def refute_event(events, name) do
    if Enum.any?(events, &(&1.metadata[:event] == name)) do
      flunk("expected no event #{inspect(name)}, but one was emitted")
    end

    :ok
  end

  defp metadata_matches?(event, expected) do
    Enum.all?(expected, fn {key, value} -> event.metadata[key] == value end)
  end

  defp describe([]), do: ""
  defp describe(expected), do: " with metadata #{inspect(expected)}"

  defp drain(ref, acc) do
    receive do
      {^ref, event} -> drain(ref, [event | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  # ── :logger handler callback ───────────────────────────

  @doc false
  def log(%{level: level, msg: {:string, message}, meta: meta}, %{
        config: %{pid: pid, ref: ref}
      }) do
    send(pid, {ref, %{level: level, message: IO.iodata_to_binary(message), metadata: meta}})
    :ok
  end

  def log(_event, _config), do: :ok
end
