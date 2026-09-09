defmodule Sovra.Signer.HealthTest do
  # async: false — swaps global config and uses a named singleton.
  use ExUnit.Case, async: false

  alias Sovra.Signer.{Health, Relayer}

  setup do
    prev = Application.get_env(:sovra, :signer_service)
    on_exit(fn -> Application.put_env(:sovra, :signer_service, prev) end)
    :ok
  end

  test "reports :unavailable when the monitor is not running" do
    assert Health.status() == :unavailable
    assert Health.snapshot() == :unavailable
  end

  test "reports :ok once KMS answers for the relayer key" do
    start_monitor()

    assert Health.check_now() == :ok
    assert %{status: :ok, checked_at: %DateTime{}} = Health.snapshot()
  end

  test "reports :error when KMS does not know the relayer key" do
    put_relayer_key("no-such-relayer-key")
    start_monitor()

    assert Health.check_now() == :error
    assert %{status: :error} = Health.snapshot()
  end

  test "reports :error when no relayer key is configured" do
    put_relayer_key(nil)
    start_monitor()

    assert Health.check_now() == :error
  end

  # The whole reason this probe exists: the relayer public key is memoized in
  # `:persistent_term` on this box, so a cache hit keeps answering long after
  # the IAM role is revoked. Only a real KMS call can fail.
  test "bypasses the relayer memo, so a cached key cannot mask an unreachable KMS" do
    key_id = "unreachable-relayer-key"
    :persistent_term.put({Relayer, key_id}, :crypto.strong_rand_bytes(64))
    on_exit(fn -> :persistent_term.erase({Relayer, key_id}) end)

    # The memo alone answers, which is exactly the state that must not read as ok.
    assert {:ok, _address} = Relayer.address()

    put_relayer_key(key_id)
    start_monitor()

    assert Health.check_now() == :error
  end

  test "the snapshot carries when the verdict was taken, for /ready" do
    start_monitor()
    before = DateTime.utc_now()

    assert Health.check_now() == :ok
    assert %{checked_at: checked_at} = Health.snapshot()
    assert DateTime.compare(checked_at, before) in [:gt, :eq]
  end

  defp start_monitor, do: start_supervised!({Health, enabled: true, interval_ms: 60_000})

  defp put_relayer_key(key_id) do
    config = Application.get_env(:sovra, :signer_service, [])
    Application.put_env(:sovra, :signer_service, Keyword.put(config, :relayer_kms_key_id, key_id))
  end
end
