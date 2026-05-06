defmodule Sovra.Issuer.StatusListTest do
  use Sovra.DataCase, async: false

  alias Sovra.Issuer
  alias Sovra.Issuer.StatusList

  # Process-local HMAC stub.  Tests set a wildcard return value via
  # `Process.put({StubHmac, :wildcard}, bytes)` and every `hmac/2` call
  # returns those bytes. When unset, falls through to DatabaseHmacStore so
  # workspace creation (which generates real keys) keeps working.
  defmodule StubHmac do
    @behaviour Sovra.Crypto.HmacKeyStore

    @impl true
    def generate_hmac_key, do: Sovra.Crypto.DatabaseHmacStore.generate_hmac_key()

    @impl true
    def hmac(key_id, payload) do
      case Process.get({__MODULE__, :wildcard}) do
        nil -> Sovra.Crypto.DatabaseHmacStore.hmac(key_id, payload)
        bytes -> {:ok, bytes}
      end
    end

    @impl true
    def rotate(key_id), do: Sovra.Crypto.DatabaseHmacStore.rotate(key_id)

    @impl true
    def delete(key_id), do: Sovra.Crypto.DatabaseHmacStore.delete(key_id)

    def set_wildcard(bytes), do: Process.put({__MODULE__, :wildcard}, bytes)
    def clear_wildcard, do: Process.delete({__MODULE__, :wildcard})
  end

  setup do
    prev = Application.get_env(:sovra, :hmac_key_store)
    Application.put_env(:sovra, :hmac_key_store, StubHmac)
    on_exit(fn -> Application.put_env(:sovra, :hmac_key_store, prev) end)
    :ok
  end

  defp create_workspace do
    StubHmac.clear_wildcard()
    fixture_workspace().workspace
  end

  defp create_schema(workspace_id) do
    {:ok, schema} =
      Issuer.create_schema(workspace_id, %{
        schema_id: "schema-#{System.unique_integer([:positive])}",
        credential_type: "TestCred",
        name: "Test",
        claims: [
          %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
        ],
        validity_period: "1y"
      })

    schema
  end

  defp get_status_list(ws_id, purpose) do
    Repo.get_by!(StatusList, workspace_id: ws_id, status_purpose: purpose)
  end

  defp insert_sentinel_offer(ws_id, schema_id, index, purpose \\ "revocation") do
    now = DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second)

    {:ok, _} =
      Sovra.Issuer.CredentialOffer.create_changeset(%{
        id: Ecto.UUID.generate(),
        issuer_id: ws_id,
        schema_id: schema_id,
        pre_authorized_code_hash: "sentinel-#{System.unique_integer([:positive])}",
        claims: %{},
        status_purpose: purpose,
        status_list_index: index,
        expires_at: now
      })
      |> Repo.insert()
  end

  describe "seeded init on workspace creation" do
    test "both purposes get a row at width 17" do
      ws = create_workspace()

      assert get_status_list(ws.id, "revocation").width == StatusList.initial_width()
      assert get_status_list(ws.id, "suspension").width == StatusList.initial_width()
    end
  end

  describe "widen on exhaustion" do
    test "3 collisions at width 17 → row width becomes 18, allocation succeeds at high index" do
      ws = create_workspace()
      schema = create_schema(ws.id)

      insert_sentinel_offer(ws.id, schema.id, 0)

      # 17-bit prefix = 0 → collides with sentinel at index 0.
      # 18-bit prefix = 1 → fresh slot at index 1 (in width-18 range).
      collision_then_fresh = <<0::17, 1::1, 0::size(238)>>
      StubHmac.set_wildcard(collision_then_fresh)

      {:ok, result} =
        Issuer.create_credential_offer(ws.id, schema.schema_id, %{"name" => "x"})

      assert result.offer.status_list_index == 1
      assert get_status_list(ws.id, "revocation").width == StatusList.initial_width() + 1
    end
  end

  describe "cap at max width" do
    test "widen at max_width returns :bitmap_exhausted; row stays at max_width" do
      ws = create_workspace()
      schema = create_schema(ws.id)

      get_status_list(ws.id, "revocation")
      |> Ecto.Changeset.change(width: StatusList.max_width())
      |> Repo.update!()

      insert_sentinel_offer(ws.id, schema.id, 0)

      # Always-collide stub: HMAC = 0 → index 0 at every width.
      StubHmac.set_wildcard(<<0::256>>)

      assert {:error, :bitmap_exhausted} =
               Issuer.create_credential_offer(ws.id, schema.schema_id, %{"name" => "y"})

      assert get_status_list(ws.id, "revocation").width == StatusList.max_width()
    end
  end

  describe "widen_status_list/3 conflict resolution" do
    # Note: the SQL Sandbox in shared mode serializes all queries through a
    # single connection, so genuine concurrent transactions are impossible to
    # simulate inside `Sovra.DataCase`. Instead, this test calls
    # `widen_status_list/3` twice with the same `observed_width` and asserts
    # the second call observes the bumped row and does NOT double-increment —
    # which is the exact branch that protects against double-widen under
    # concurrency. The Postgres `SELECT … FOR UPDATE` lock semantics are a
    # platform invariant and out of scope for this assertion.

    test "second caller with stale observed_width sees the new width without re-bumping" do
      ws = create_workspace()
      initial = StatusList.initial_width()

      # First caller observes width=initial and bumps.
      assert {:ok, after_first} =
               Sovra.Issuer.widen_status_list(ws.id, "revocation", initial)

      assert after_first == initial + 1

      # Second caller observes the same stale width=initial and should
      # short-circuit because the row already moved past observed_width.
      assert {:ok, after_second} =
               Sovra.Issuer.widen_status_list(ws.id, "revocation", initial)

      assert after_second == initial + 1, "second call must not double-increment"
      assert get_status_list(ws.id, "revocation").width == initial + 1
    end

    test "successive widens with up-to-date observed_width keep stepping up" do
      ws = create_workspace()
      initial = StatusList.initial_width()

      assert {:ok, w1} = Sovra.Issuer.widen_status_list(ws.id, "revocation", initial)
      assert w1 == initial + 1

      assert {:ok, w2} = Sovra.Issuer.widen_status_list(ws.id, "revocation", w1)
      assert w2 == initial + 2
    end
  end
end
