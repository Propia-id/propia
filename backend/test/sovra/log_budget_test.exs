defmodule Sovra.LogBudgetTest do
  @moduledoc """
  New Relic receives at most **10** metadata attributes per log record, and
  discards the rest silently.

  The cap is not ours and is not configurable. `NewRelic.Util.deep_flatten/1`
  slices any map to its first 10 entries — a sensible guard against one
  careless struct exploding into hundreds of attributes — but
  `NewRelic.LogsInContext.custom_metadata/1` wraps the *entire* metadata map in
  one nesting level (`[metadata: log.meta]`) before flattening, so the guard
  lands on everything you log. It then deletes the `metadata.size` marker that
  would have recorded the true count, which is why truncation leaves no trace.
  Verified against new_relic_agent 1.41.0 and unchanged on upstream master.

  Which 10 survive is map iteration order — not a priority anyone chose, and it
  reshuffles when the key set changes. So a call site over budget does not lose
  a predictable tail; it loses an arbitrary five.

  This test parses every `Log.event/3` call site out of `lib/` and fails when
  one exceeds the budget, counting the ambient context the plugs and workers
  put on the process. Without it the only symptom is attributes quietly
  missing in New Relic, which is exactly how this went unnoticed through six
  phases.
  """

  use ExUnit.Case, async: true

  # NewRelic.Util.deep_flatten/1, util.ex:75
  @cap 10

  # Set by Log.put_context/1 before a call site runs, and counted against the
  # same budget because the agent sees one flat metadata map.
  @ambient %{
    # Plug.RequestId + UserSessionPlug/ApiKeyPlug. The require_* plugs add
    # org_id or workspace_id, which every event in those paths already names.
    request: ~w(request_id user_id auth_method),
    # Log.adopt_job_context/1
    job: ~w(request_id oban_job_id oban_attempt),
    # SessionPlug, on the wallet rail
    guardian: ~w(request_id sovra_address auth_method)
  }

  @job_files ~w(workspace_provisioning_job delivery_job mailer_job expired_sessions_sweeper)

  # ethereum/client.ex builds its chain events as `[{:k, v} | context]`, where
  # the tail is `Keyword.take(opts, [:op, :subject_id, :workspace_id])`. The
  # tail's size is not visible to the parser, so it is charged at its maximum.
  @cons_tail_allowance 3

  test "no event exceeds New Relic's 10-attribute ceiling" do
    over =
      call_sites()
      |> Enum.map(fn site ->
        ambient = Enum.reject(ambient_for(site), &(&1 in site.keys))
        tail = if site.dynamic?, do: @cons_tail_allowance, else: 0

        Map.merge(site, %{
          ambient: ambient,
          total: length(site.keys) + length(ambient) + tail
        })
      end)
      |> Enum.filter(&(&1.total > @cap))

    assert over == [], """
    #{length(over)} call site(s) send more than #{@cap} metadata attributes, so
    New Relic will silently drop the excess — see this module's docs.

    #{Enum.map_join(over, "\n", &describe/1)}
    Drop attributes that are a column away from a surviving id, or that the
    event name already implies.
    """
  end

  test "the parser actually finds the call sites" do
    # A parser that silently matched nothing, or missed the cons form, would
    # make the budget check above vacuous.
    sites = call_sites()

    assert length(sites) > 100
    assert Enum.all?(sites, &(&1.keys != [])), "some call site parsed to zero keys"
    assert "event" in (sites |> Enum.flat_map(& &1.keys) |> Enum.uniq())

    # The chain events are the only sites with a runtime tail. A new one should
    # be a deliberate decision, since its size is charged at the maximum.
    dynamic = Enum.filter(sites, & &1.dynamic?)
    assert Enum.all?(dynamic, &String.contains?(&1.file, "ethereum/client.ex"))
    assert length(dynamic) == 6
  end

  defp describe(site) do
    """
      #{site.event} — #{site.total} attributes (#{length(site.keys)} own + #{length(site.ambient)} ambient)
        #{site.file}
        own:     #{Enum.join(site.keys, ", ")}
        ambient: #{Enum.join(site.ambient, ", ")}
    """
  end

  defp ambient_for(%{file: file}) do
    cond do
      String.contains?(file, @job_files) -> @ambient.job
      String.contains?(file, "guardian") -> @ambient.guardian
      true -> @ambient.request
    end
  end

  defp call_sites do
    "lib/**/*.ex"
    |> Path.wildcard()
    |> Enum.reject(&String.ends_with?(&1, "log.ex"))
    |> Enum.flat_map(&sites_in/1)
  end

  # Elixir's own parser rather than a regex: the metadata is written both as a
  # bare keyword list and, in ethereum/client.ex, as `[{:k, v} | context]`, and
  # a regex that silently missed one form would make the budget check vacuous.
  defp sites_in(file) do
    file
    |> File.read!()
    |> Code.string_to_quoted!()
    |> collect_calls()
    |> Enum.map(fn {name, keys, dynamic?} ->
      %{file: file, event: name, keys: keys, dynamic?: dynamic?}
    end)
  end

  defp collect_calls(ast) do
    {_, sites} =
      Macro.prewalk(ast, [], fn
        {{:., _, [{:__aliases__, _, [:Log]}, :event]}, _, [_level, _msg, metadata]} = node, acc ->
          {node, [site(metadata) | acc]}

        node, acc ->
          {node, acc}
      end)

    Enum.reverse(sites)
  end

  # A literal keyword list, or a list whose tail is a runtime keyword list.
  defp site(metadata) when is_list(metadata) do
    {pairs, dynamic?} = flatten_list(metadata)
    keys = for {k, _v} <- pairs, is_atom(k), do: to_string(k)
    {event_name(pairs), keys, dynamic?}
  end

  defp site(_other), do: {"(non-literal metadata)", [], true}

  defp flatten_list(list) do
    Enum.reduce(list, {[], false}, fn
      # `| tail` — the tail's size is not visible here, so the site is counted
      # charged at @cons_tail_allowance instead.
      {:|, _, [head, _tail]}, {pairs, _} -> {pairs ++ [head], true}
      {k, v}, {pairs, dyn} -> {pairs ++ [{k, v}], dyn}
      _other, {pairs, dyn} -> {pairs, dyn}
    end)
  end

  defp event_name(pairs) do
    case List.keyfind(pairs, :event, 0) do
      {:event, name} when is_binary(name) -> name
      # change_credential_status/5 takes the name as an argument; the three
      # lifecycle events share this one call site.
      _ -> "credential.revoked / .suspended / .unsuspended"
    end
  end
end
