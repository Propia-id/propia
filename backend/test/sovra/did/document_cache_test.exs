defmodule Sovra.DID.DocumentCacheTest do
  use ExUnit.Case, async: false

  alias Sovra.DID.DocumentCache

  setup do
    # The cache runs as a named GenServer started by the application supervisor.
    # We clear all entries before each test to keep them isolated.
    :ets.delete_all_objects(:sovra_did_document_cache)
    :ok
  end

  describe "get/1 and put/3" do
    test "returns :miss when no entry exists" do
      assert :miss = DocumentCache.get("did:quarkid:sovra:nope")
    end

    test "returns {:hit, value} after put within TTL" do
      DocumentCache.put("did:x:1", {:ok, [%{x: <<1>>}]}, 60)
      assert {:hit, {:ok, [%{x: <<1>>}]}} = DocumentCache.get("did:x:1")
    end

    test "negative results round-trip just like positive ones" do
      DocumentCache.put("did:x:2", {:error, :did_unresolvable}, 60)
      assert {:hit, {:error, :did_unresolvable}} = DocumentCache.get("did:x:2")
    end

    test "returns :miss after TTL expires" do
      # 1-second TTL — write then wait it out.
      DocumentCache.put("did:x:3", :stale, 1)
      assert {:hit, :stale} = DocumentCache.get("did:x:3")
      Process.sleep(1_100)
      assert :miss = DocumentCache.get("did:x:3")
    end

    test "later put overwrites earlier entry" do
      DocumentCache.put("did:x:4", :first, 60)
      DocumentCache.put("did:x:4", :second, 60)
      assert {:hit, :second} = DocumentCache.get("did:x:4")
    end
  end

  describe "invalidate/1" do
    test "removes an entry" do
      DocumentCache.put("did:x:5", :present, 60)
      assert {:hit, :present} = DocumentCache.get("did:x:5")
      DocumentCache.invalidate("did:x:5")
      assert :miss = DocumentCache.get("did:x:5")
    end

    test "is a no-op when the entry doesn't exist" do
      assert :ok = DocumentCache.invalidate("did:x:never-stored")
    end
  end

  describe "fetch_or_wait/4" do
    test "returns cached value without invoking the fetcher" do
      DocumentCache.put("did:x:cached", {:ok, :precached}, 60)
      counter = :counters.new(1, [])

      result =
        DocumentCache.fetch_or_wait(
          "did:x:cached",
          fn ->
            :counters.add(counter, 1, 1)
            {:ok, :should_not_run}
          end,
          60,
          60
        )

      assert result == {:ok, :precached}
      assert :counters.get(counter, 1) == 0
    end

    test "runs the fetcher on cache miss and caches the success with positive TTL" do
      result =
        DocumentCache.fetch_or_wait(
          "did:x:miss-ok",
          fn -> {:ok, :fresh} end,
          60,
          1
        )

      assert result == {:ok, :fresh}
      assert {:hit, {:ok, :fresh}} = DocumentCache.get("did:x:miss-ok")
    end

    test "caches errors with the negative TTL" do
      DocumentCache.fetch_or_wait(
        "did:x:miss-err",
        fn -> {:error, :nope} end,
        300,
        1
      )

      assert {:hit, {:error, :nope}} = DocumentCache.get("did:x:miss-err")
      Process.sleep(1_100)
      assert :miss = DocumentCache.get("did:x:miss-err")
    end

    test "coalesces concurrent callers — only one fetcher invocation, all get the same result" do
      counter = :counters.new(1, [])

      fetcher = fn ->
        :counters.add(counter, 1, 1)
        # Sleep long enough that all 10 callers arrive before this fetch completes.
        Process.sleep(150)
        {:ok, :one_shot}
      end

      tasks =
        for _ <- 1..10 do
          Task.async(fn ->
            DocumentCache.fetch_or_wait("did:x:stampede", fetcher, 60, 60)
          end)
        end

      results = Task.await_many(tasks, 2_000)

      assert Enum.all?(results, &(&1 == {:ok, :one_shot}))
      assert :counters.get(counter, 1) == 1
    end

    test "different DIDs are not coalesced" do
      counter = :counters.new(1, [])

      fetcher = fn ->
        :counters.add(counter, 1, 1)
        Process.sleep(50)
        {:ok, :ok}
      end

      tasks =
        for i <- 1..5 do
          did = "did:x:distinct-#{i}"
          Task.async(fn -> DocumentCache.fetch_or_wait(did, fetcher, 60, 60) end)
        end

      Task.await_many(tasks, 2_000)
      assert :counters.get(counter, 1) == 5
    end

    test "crashing fetcher returns :fetch_crashed to all waiters and does not cache" do
      result =
        DocumentCache.fetch_or_wait(
          "did:x:crashy",
          fn -> raise "boom" end,
          60,
          60
        )

      assert result == {:error, :fetch_crashed}
      # No cache entry was written, so a subsequent call re-runs the fetcher.
      assert :miss = DocumentCache.get("did:x:crashy")

      assert {:ok, :recovered} =
               DocumentCache.fetch_or_wait(
                 "did:x:crashy",
                 fn -> {:ok, :recovered} end,
                 60,
                 60
               )
    end
  end
end
