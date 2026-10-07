defmodule Sovra.Ethereum.SubmitLockTest do
  use Sovra.DataCase, async: false

  alias Sovra.Ethereum.SubmitLock

  @relayer "0x00000000000000000000000000000000000000Cc"

  test "returns what the submission returns" do
    assert {:ok, "0xhash"} = SubmitLock.run(@relayer, fn -> {:ok, "0xhash"} end)
  end

  # A revert's reason is a map the registries search for a selector, so it has
  # to come out of the lock exactly as it went in.
  test "passes a failure through unchanged" do
    reason = %{"code" => 3, "data" => "0x3a81d6fc"}
    assert {:error, ^reason} = SubmitLock.run(@relayer, fn -> {:error, reason} end)
  end

  # Another node is another Postgres session, which the sandbox cannot stand in
  # for, so this one holds the lock from a connection of its own.
  test "waits out another session's submission, and gives up after the timeout" do
    {:ok, other} = Postgrex.start_link(Keyword.drop(Repo.config(), [:pool, :pool_size]))
    key = SubmitLock.key(@relayer)
    Postgrex.query!(other, "SELECT pg_advisory_lock($1)", [key])

    previous = Application.get_env(:sovra, :submit_lock_wait_timeout_ms)
    Application.put_env(:sovra, :submit_lock_wait_timeout_ms, 300)

    try do
      assert {:error, :relayer_lock_unavailable} =
               SubmitLock.run(@relayer, fn -> flunk("ran while another session held the lock") end)

      # Another relayer's lock is a different key.
      assert {:ok, :other_relayer} =
               SubmitLock.run("0x00000000000000000000000000000000000000dd", fn ->
                 {:ok, :other_relayer}
               end)

      Postgrex.query!(other, "SELECT pg_advisory_unlock($1)", [key])
      assert {:ok, :ran} = SubmitLock.run(@relayer, fn -> {:ok, :ran} end)
    after
      if previous,
        do: Application.put_env(:sovra, :submit_lock_wait_timeout_ms, previous),
        else: Application.delete_env(:sovra, :submit_lock_wait_timeout_ms)

      GenServer.stop(other)
    end
  end

  test "is held for the submission" do
    assert {:ok, true} =
             SubmitLock.run(@relayer, fn ->
               %{rows: [[held?]]} =
                 Repo.query!(
                   "SELECT count(*) > 0 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()"
                 )

               {:ok, held?}
             end)
  end
end
