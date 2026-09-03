defmodule Sovra.GuardianEventsTest do
  @moduledoc """
  Guardian is the flow that moves control of a citizen's account, and it had
  zero log statements. The two things these tests pin down:

    * `message_hash` is recorded on every recovery co-signature. The backend
      does not enforce the timelock — `Guardian.Policy.evaluate/1` is a stub and
      the timelock lives in the wallet contract — so the hash we signed is the
      only link between our signature and the on-chain operation it authorized,
      and the only part of the audit trail that survives outside our database.

    * OAuth subjects are fingerprinted, never logged. A Google `sub` is a
      stable person identifier.
  """

  use Sovra.DataCase, async: false

  import Sovra.GuardianHelpers
  import Sovra.LogHelpers

  alias Sovra.Auth.MockAuthProvider
  alias Sovra.Guardian
  alias Sovra.Guardian.HolderRecord
  alias Sovra.Log

  setup do
    Application.put_env(:sovra, :log_fingerprint_key, "test-fingerprint-key")
    on_exit(fn -> Application.delete_env(:sovra, :log_fingerprint_key) end)
    :ok
  end

  describe "onboarding" do
    test "guardian.onboarded records the address, key and subject fingerprint" do
      address = test_address("evt-onboard-#{System.unique_integer([:positive])}")

      {{:ok, _}, events} =
        capture_events(fn -> Guardian.onboard(address, MockAuthProvider.valid_token()) end)

      event = assert_event(events, "guardian.onboarded", sovra_address: address)
      assert event.metadata[:recovery_key_id]
      assert event.metadata[:oauth_subject_fp] == Log.fingerprint(MockAuthProvider.test_sub())
      # The raw Google subject must never appear.
      refute inspect(event.metadata) =~ MockAuthProvider.test_sub()
    end

    test "a bad ID token is rejected with its reason" do
      address = test_address("evt-badtoken-#{System.unique_integer([:positive])}")

      {{:error, :invalid_id_token}, events} =
        capture_events(fn -> Guardian.onboard(address, "bad-token") end)

      assert_event(events, "guardian.onboard.rejected",
        sovra_address: address,
        reason: :invalid_id_token
      )
    end

    test "an already-onboarded address is rejected" do
      address = test_address("evt-dupe-#{System.unique_integer([:positive])}")
      {:ok, _} = Guardian.onboard(address, MockAuthProvider.valid_token())

      {{:error, :already_onboarded}, events} =
        capture_events(fn -> Guardian.onboard(address, MockAuthProvider.valid_token_2()) end)

      assert_event(events, "guardian.onboard.rejected", reason: :already_onboarded)
    end

    test "the same Google account on a second device logs in, and the address gap shows" do
      first = test_address("evt-dev-a-#{System.unique_integer([:positive])}")
      second = test_address("evt-dev-b-#{System.unique_integer([:positive])}")
      {:ok, _} = Guardian.onboard(first, MockAuthProvider.valid_token())

      {{:ok, _}, events} =
        capture_events(fn -> Guardian.onboard(second, MockAuthProvider.valid_token()) end)

      # This branch mints the session for the *requested* address while
      # returning the *existing* one, so the requested address is recorded
      # whenever the two differ.
      event =
        assert_event(events, "guardian.authenticated",
          via: :onboard,
          sovra_address: first,
          requested_sovra_address: second
        )

      assert event.level == :info
    end
  end

  describe "authentication" do
    test "guardian.authenticated on the ID-token path" do
      address = test_address("evt-auth-#{System.unique_integer([:positive])}")
      {:ok, _} = Guardian.onboard(address, MockAuthProvider.valid_token())

      {{:ok, _}, events} =
        capture_events(fn ->
          Guardian.authenticate_with_token(MockAuthProvider.valid_token())
        end)

      assert_event(events, "guardian.authenticated", via: :id_token, sovra_address: address)
    end

    test "an unknown holder is a rejection, not a silent error" do
      {{:error, :holder_not_found}, events} =
        capture_events(fn ->
          Guardian.authenticate_with_token(MockAuthProvider.valid_token_2())
        end)

      assert_event(events, "guardian.auth.rejected", reason: :holder_not_found)
    end
  end

  describe "OAuth callback" do
    test "an invalid state is rejected before any address is known" do
      {{:error, :invalid_state}, events} =
        capture_events(fn -> Guardian.handle_auth_callback("code", "not-a-valid-state") end)

      assert_event(events, "guardian.oauth.rejected", reason: :invalid_state)
    end

    test "a binding mismatch is an error carrying both subject fingerprints" do
      # Onboard with one Google account, then complete a callback that
      # authenticated as a different one: an attempted account takeover.
      address = test_address("evt-mismatch-#{System.unique_integer([:positive])}")
      {:ok, _} = Guardian.onboard(address, MockAuthProvider.valid_token_2())

      {:ok, url} = Guardian.get_auth_url(address)
      state = url |> String.split("state=") |> List.last()

      {{:error, :oauth_mismatch}, events} =
        capture_events(fn ->
          Guardian.handle_auth_callback(MockAuthProvider.valid_code(), state)
        end)

      event =
        assert_event(events, "guardian.oauth_binding.mismatch", sovra_address: address)

      assert event.level == :error

      assert event.metadata[:expected_oauth_subject_fp] ==
               Log.fingerprint(MockAuthProvider.test_sub_2())

      assert event.metadata[:presented_oauth_subject_fp] ==
               Log.fingerprint(MockAuthProvider.test_sub())

      refute inspect(event.metadata) =~ MockAuthProvider.test_sub()
    end

    test "a matching binding authenticates" do
      address = test_address("evt-cb-ok-#{System.unique_integer([:positive])}")
      {:ok, _} = Guardian.onboard(address, MockAuthProvider.valid_token())

      {:ok, url} = Guardian.get_auth_url(address)
      state = url |> String.split("state=") |> List.last()

      {{:ok, _token}, events} =
        capture_events(fn ->
          Guardian.handle_auth_callback(MockAuthProvider.valid_code(), state)
        end)

      assert_event(events, "guardian.oauth.authenticated", sovra_address: address)
      refute_event(events, "guardian.oauth_binding.mismatch")
    end
  end

  describe "recovery key rotation" do
    setup do
      address = test_address("evt-rotate-#{System.unique_integer([:positive])}")
      {:ok, _} = Guardian.onboard(address, MockAuthProvider.valid_token())
      holder = Sovra.Repo.get_by!(HolderRecord, sovra_address: address)
      %{address: address, holder: holder}
    end

    test "rotation_started names both keys, since only one is destroyed later", %{
      address: address,
      holder: holder
    } do
      {{:ok, _}, events} =
        capture_events(fn -> Guardian.rotate_recovery_key(address) end)

      event =
        assert_event(events, "guardian.recovery_key.rotation_started",
          sovra_address: address,
          previous_recovery_key_id: holder.recovery_key_id
        )

      assert event.metadata[:recovery_key_id]
      refute event.metadata[:recovery_key_id] == holder.recovery_key_id
    end

    test "rotation_confirmed names the key that stopped existing", %{
      address: address,
      holder: holder
    } do
      {:ok, _} = Guardian.rotate_recovery_key(address)

      {:ok, events} = capture_events(fn -> Guardian.confirm_rotation(address) end)

      assert_event(events, "guardian.recovery_key.rotation_confirmed",
        sovra_address: address,
        destroyed_recovery_key_id: holder.recovery_key_id
      )
    end

    test "confirming with nothing pending stays quiet", %{address: address} do
      {{:error, :no_pending_rotation}, events} =
        capture_events(fn -> Guardian.confirm_rotation(address) end)

      refute_event(events, "guardian.recovery_key.rotation_confirmed")
    end
  end

  describe "recovery co-signing" do
    setup do
      address = test_address("evt-recovery-#{System.unique_integer([:positive])}")
      {:ok, _} = Guardian.onboard(address, MockAuthProvider.valid_token())
      %{address: address}
    end

    test "initiated records the hash we signed and which key is replaced", %{address: address} do
      params = %{
        new_key_x: Base.encode64(:crypto.strong_rand_bytes(32)),
        new_key_y: Base.encode64(:crypto.strong_rand_bytes(32)),
        key_to_replace: 1
      }

      {result, events} =
        capture_events(fn -> Guardian.initiate_recovery(address, params) end)

      case result do
        {:ok, %{message_hash: hash}} ->
          # The logged hash must be exactly what the caller was handed, or it
          # cannot be matched against the on-chain operation.
          assert_event(events, "guardian.recovery.initiated",
            sovra_address: address,
            message_hash: hash,
            key_to_replace: 1
          )

        {:error, _reason} ->
          # No chain configured in this environment: the hash build fails, and
          # that is our infrastructure, so it must be an error-level event.
          event = assert_event(events, "guardian.recovery.errored", stage: :initiate)
          assert event.level == :error
      end
    end

    test "malformed params are a warning, not an infrastructure error", %{address: address} do
      {{:error, :invalid_params}, events} =
        capture_events(fn -> Guardian.initiate_recovery(address, %{nonsense: true}) end)

      event =
        assert_event(events, "guardian.recovery.rejected",
          stage: :initiate,
          reason: :invalid_params
        )

      assert event.level == :warning
    end

    test "an unknown holder is a warning on finalize" do
      unknown = test_address("evt-nobody-#{System.unique_integer([:positive])}")

      {{:error, :holder_not_found}, events} =
        capture_events(fn -> Guardian.finalize_recovery(unknown) end)

      event =
        assert_event(events, "guardian.recovery.rejected",
          stage: :finalize,
          reason: :holder_not_found
        )

      assert event.level == :warning
    end
  end
end
