defmodule Sovra.BuildInfoTest do
  use ExUnit.Case, async: true

  alias Sovra.BuildInfo

  # The values are compile-time constants, so these assert the contract rather
  # than a literal: a test hard-coding "dev" would fail on a stamped build.
  describe "all/0" do
    test "carries the four fields the probe routes and the boot log report" do
      assert %{revision: revision, ref: ref, version: version, built_at: built_at} =
               BuildInfo.all()

      assert is_binary(revision) and revision != ""
      assert is_binary(ref) and ref != ""
      assert is_binary(version) and version != ""
      assert is_nil(built_at) or is_binary(built_at)
    end

    test "version is the mix.exs version, not the revision" do
      assert BuildInfo.version() == Mix.Project.config()[:version]
    end
  end

  describe "short_revision/0" do
    test "is a prefix of the full revision, at most 12 characters" do
      short = BuildInfo.short_revision()

      assert String.starts_with?(BuildInfo.revision(), short)
      assert String.length(short) <= 12
    end
  end

  describe "stamped?/0" do
    test "agrees with the revision string" do
      revision = BuildInfo.revision()

      expected = revision != "dev" and not String.ends_with?(revision, "-dirty")

      assert BuildInfo.stamped?() == expected
    end
  end

  describe "built_at_unix/0" do
    # `List.wrap/1` rather than a nil branch: the type checker narrows these
    # constants and would flag the other branch as unreachable.
    test "is the parsed form of built_at, not a clock reading" do
      assert Enum.map(List.wrap(BuildInfo.built_at()), &to_unix/1) ==
               List.wrap(BuildInfo.built_at_unix())
    end
  end

  defp to_unix(built_at) do
    {:ok, parsed, _offset} = DateTime.from_iso8601(built_at)
    DateTime.to_unix(parsed)
  end
end
