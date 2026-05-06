defmodule Sovra.Workspaces.ApiKeysTest do
  use Sovra.DataCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces
  alias Sovra.Workspaces.ApiKey
  alias Sovra.Workspaces.ApiKeys

  defp setup_workspace(_context) do
    {:ok, user} =
      User.admin_changeset(%{
        email: "user-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Repo.insert()

    {:ok, %{workspace: ws}} =
      Workspaces.create_workspace(org.id, %{name: "Acme"}, user.id)

    %{workspace: ws, user: user}
  end

  setup :setup_workspace

  test "create_api_key returns plaintext once + record", %{workspace: ws} do
    {:ok, %{api_key: plaintext, record: %ApiKey{} = rec}} =
      ApiKeys.create_api_key(ws.id, "Prod")

    assert String.starts_with?(plaintext, "sovra_sk_")
    assert rec.name == "Prod"
    assert rec.workspace_id == ws.id
    assert is_binary(rec.api_key_hash)
    assert is_nil(rec.revoked_at)
  end

  test "find_active_by_plaintext hits active, misses unknown / revoked", %{workspace: ws} do
    {:ok, %{api_key: plaintext, record: rec}} = ApiKeys.create_api_key(ws.id, "Staging")

    {:ok, found} = ApiKeys.find_active_by_plaintext(plaintext)
    assert found.id == rec.id
    assert found.workspace.id == ws.id

    assert {:error, :invalid} = ApiKeys.find_active_by_plaintext("sovra_sk_nope")
    assert {:error, :invalid} = ApiKeys.find_active_by_plaintext(nil)

    {:ok, _} = ApiKeys.revoke_api_key(rec)
    assert {:error, :invalid} = ApiKeys.find_active_by_plaintext(plaintext)
  end

  test "list_api_keys includes revoked", %{workspace: ws} do
    {:ok, %{record: first}} = ApiKeys.create_api_key(ws.id, "First")
    {:ok, %{record: second}} = ApiKeys.create_api_key(ws.id, "Second")
    {:ok, _} = ApiKeys.revoke_api_key(first)

    listed = ApiKeys.list_api_keys(ws.id)
    ids = listed |> Enum.map(& &1.id) |> MapSet.new()
    assert MapSet.equal?(ids, MapSet.new([first.id, second.id]))

    revoked = Enum.find(listed, &(&1.id == first.id))
    assert revoked.revoked_at
  end

  test "get_api_key scopes by workspace_id", %{workspace: ws} do
    {:ok, %{record: rec}} = ApiKeys.create_api_key(ws.id, "Scoped")

    assert {:ok, _} = ApiKeys.get_api_key(ws.id, rec.id)
    assert {:error, :not_found} = ApiKeys.get_api_key(Ecto.UUID.generate(), rec.id)
  end
end
