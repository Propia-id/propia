defmodule Sovra.BuildInfo do
  @moduledoc """
  Which commit produced the code this node is running.

  Read from `priv/build_info.json`, which the deploy writes before `mix
  release`, at compile time: the values are constants, so callers do no I/O and
  the two probe routes keep their documented no-I/O contract.

  `@external_resource` is required — `_build` outlives a deploy, so without it a
  release that recompiled nothing would report the previous revision.

  Absent file (dev, test, a plain `mix release`) reads as `dev`.
  """

  @path "priv/build_info.json"
  @external_resource @path

  @absent %{"revision" => "dev", "ref" => "dev", "built_at" => nil}

  @info (case File.read(@path) do
           {:ok, raw} ->
             case Jason.decode(raw) do
               {:ok, %{} = info} -> Map.merge(@absent, info)
               # A malformed stamp must not fail the build; BuildInfoMissing alerts on it.
               _ -> @absent
             end

           {:error, _} ->
             @absent
         end)

  # Only non-empty strings survive. A hand-edited stamp with a number where a
  # string belongs would otherwise crash the compile in `DateTime.from_iso8601/1`.
  @stamp Map.new(@absent, fn {key, fallback} ->
           case @info[key] do
             value when is_binary(value) and value != "" -> {key, value}
             _ -> {key, fallback}
           end
         end)

  @revision @stamp["revision"]
  @ref @stamp["ref"]
  @built_at @stamp["built_at"]

  # Parsed once here rather than per scrape.
  @built_at_unix (case @built_at && DateTime.from_iso8601(@built_at) do
                    {:ok, at, _offset} -> DateTime.to_unix(at)
                    _ -> nil
                  end)

  # Compile time: `Mix` is not available inside a release.
  @version Mix.Project.config()[:version]

  @doc "Commit the release was built from; `-dirty` when the tree was unclean, `dev` when unstamped."
  @spec revision() :: String.t()
  def revision, do: @revision

  @doc "First 12 characters of `revision/0`."
  @spec short_revision() :: String.t()
  def short_revision, do: String.slice(@revision, 0, 12)

  @doc "Branch or tag the release was built from."
  @spec ref() :: String.t()
  def ref, do: @ref

  @doc "RFC3339 build time, or nil when unstamped."
  @spec built_at() :: String.t() | nil
  def built_at, do: @built_at

  @doc "Build time as unix seconds, or nil."
  @spec built_at_unix() :: integer() | nil
  def built_at_unix, do: @built_at_unix

  @doc "The `mix.exs` version. A human label; the revision is the identity."
  @spec version() :: String.t()
  def version, do: @version

  @doc "Whether the revision names a real commit. False for an unstamped or dirty build."
  @spec stamped?() :: boolean()
  def stamped?, do: @revision != "dev" and not String.ends_with?(@revision, "-dirty")

  @doc "Every field, as the probe routes and the `app.boot` event report it."
  @spec all() :: %{
          revision: String.t(),
          ref: String.t(),
          version: String.t(),
          built_at: String.t() | nil
        }
  def all, do: %{revision: @revision, ref: @ref, version: @version, built_at: @built_at}
end
