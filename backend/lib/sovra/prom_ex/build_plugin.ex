defmodule Sovra.PromEx.BuildPlugin do
  @moduledoc """
  PromEx plugin carrying the build identity of the running release.

  An info series: the value is always 1 and the identity lives in the labels, so
  a query can join on the revision without every other metric becoming
  version-scoped. `env`/`host`/`role` come from the scrape target.

  Polling, not manual: manual families are gathered once at start-up. The
  measurements are compile-time constants, so the poll costs nothing.

  Shared by both exporters — `Sovra.PromEx` on the API nodes and
  `Sovra.Signer.PromEx` on the signer — because the whole point is that every
  role reports the revision its own beam is running.

  Names carry the `sovra_` prefix, not PromEx's, since alert rules reference
  them directly.
  """

  use PromEx.Plugin

  alias Sovra.BuildInfo

  @build_event [:sovra, :build, :stamp]

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate, 60_000)

    Polling.build(
      :build_info_polling_metrics,
      poll_rate,
      {__MODULE__, :execute_build_metrics, []},
      [
        last_value([:sovra, :build, :info],
          event_name: @build_event,
          measurement: :value,
          description:
            "The commit this release was built from, carried as labels; the value is always 1. " <>
              "`revision` is `dev` when no deploy stamped the build, `-dirty` when the tree " <>
              "was unclean.",
          tags: [:revision, :ref, :version]
        ),
        last_value([:sovra, :build, :timestamp, :seconds],
          event_name: @build_event,
          measurement: :built_at_unix,
          description: "Unix time the release was built. Absent for an unstamped build."
        )
      ],
      detach_on_error: false
    )
  end

  @doc false
  def execute_build_metrics do
    # A nil measurement is dropped by the exporter, so an unstamped build leaves
    # the timestamp gauge absent rather than reading as 1970.
    :telemetry.execute(
      @build_event,
      %{value: 1, built_at_unix: BuildInfo.built_at_unix()},
      %{revision: BuildInfo.revision(), ref: BuildInfo.ref(), version: BuildInfo.version()}
    )
  end
end
