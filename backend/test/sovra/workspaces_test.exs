defmodule Sovra.WorkspacesTest do
  use Sovra.DataCase, async: false

  alias Sovra.Workspaces
  alias Sovra.Workspaces.WorkspaceMember

  defp create_user, do: fixture_user()
  defp create_org, do: fixture_org()
  defp create_workspace, do: fixture_workspace()

  describe "create_workspace/3" do
    test "creates workspace + owner member + webhook secret" do
      user = create_user()
      org = create_org()

      {:ok, %{workspace: ws, webhook_secret: secret}} =
        Workspaces.create_workspace(org.id, %{name: "Acme"}, user.id)

      assert ws.name == "Acme"
      assert ws.organization_id == org.id
      assert ws.status == "active"
      assert is_binary(ws.webhook_secret_key_id)
      assert String.starts_with?(secret, "whsec_")

      assert {:ok, "admin"} = Workspaces.member_role(ws.id, user.id)

      assert is_binary(ws.status_index_secret_key_id)
      assert ws.status_index_secret_key_id != ws.webhook_secret_key_id
    end

    test "accepts optional webhook_url at creation" do
      user = create_user()
      org = create_org()

      {:ok, %{workspace: ws}} =
        Workspaces.create_workspace(
          org.id,
          %{name: "Acme", webhook_url: "https://example.com/hook"},
          user.id
        )

      assert ws.webhook_url == "https://example.com/hook"
    end

    test "rejects invalid webhook_url" do
      user = create_user()
      org = create_org()

      assert {:error, %Ecto.Changeset{}} =
               Workspaces.create_workspace(
                 org.id,
                 %{name: "Acme", webhook_url: "not-a-url"},
                 user.id
               )
    end
  end

  describe "update_workspace/2" do
    test "updates name and webhook URL" do
      %{workspace: ws} = create_workspace()

      {:ok, updated} =
        Workspaces.update_workspace(ws, %{
          name: "Renamed",
          webhook_url: "https://webhook.test"
        })

      assert updated.name == "Renamed"
      assert updated.webhook_url == "https://webhook.test"
    end

    test "refuses updates on deactivated workspaces" do
      %{workspace: ws} = create_workspace()

      {:ok, deactivated} =
        ws
        |> Sovra.Workspaces.Workspace.status_changeset("deactivated")
        |> Repo.update()

      assert {:error, %Ecto.Changeset{}} =
               Workspaces.update_workspace(deactivated, %{name: "Too late"})
    end
  end

  describe "regenerate_webhook_secret/1" do
    test "returns a new plaintext" do
      %{workspace: ws, webhook_secret: original} = create_workspace()

      {:ok, %{webhook_secret: new_plaintext}} = Workspaces.regenerate_webhook_secret(ws)

      assert is_binary(new_plaintext)
      assert new_plaintext != original
    end
  end

  describe "membership" do
    test "member_role returns role for members and :not_a_member otherwise" do
      %{workspace: ws, owner: owner} = create_workspace()
      other = create_user()

      assert {:ok, "admin"} = Workspaces.member_role(ws.id, owner.id)
      assert {:error, :not_a_member} = Workspaces.member_role(ws.id, other.id)

      {:ok, %WorkspaceMember{role: "member"}} =
        Workspaces.add_member(ws.id, other.id, "member")

      assert {:ok, "member"} = Workspaces.member_role(ws.id, other.id)
    end

    test "update_member_role enforces last-admin invariant" do
      %{workspace: ws, owner: owner} = create_workspace()

      # Demoting the only admin must be rejected.
      assert {:error, :last_admin} =
               Workspaces.update_member_role(ws.id, owner.id, "member")

      # Add a second admin — now demotion is allowed.
      other = create_user()
      {:ok, _} = Workspaces.add_member(ws.id, other.id, "admin")

      {:ok, _} = Workspaces.update_member_role(ws.id, owner.id, "member")
      assert {:ok, "member"} = Workspaces.member_role(ws.id, owner.id)
    end

    test "remove_member enforces last-admin invariant" do
      %{workspace: ws, owner: owner} = create_workspace()

      assert {:error, :last_admin} = Workspaces.remove_member(ws.id, owner.id)

      # Add a second admin — now the original admin can leave.
      other = create_user()
      {:ok, _} = Workspaces.add_member(ws.id, other.id, "admin")
      {:ok, _} = Workspaces.remove_member(ws.id, owner.id)
      assert {:error, :not_a_member} = Workspaces.member_role(ws.id, owner.id)
    end

    test "list_members returns members ordered by email" do
      %{workspace: ws, owner: owner} = create_workspace()
      {:ok, a} = owner |> Ecto.Changeset.change(email: "alice@example.com") |> Repo.update()

      bob = create_user()
      {:ok, b} = bob |> Ecto.Changeset.change(email: "bob@example.com") |> Repo.update()

      {:ok, _} = Workspaces.add_member(ws.id, b.id, "member")

      members = Workspaces.list_members(ws.id)

      assert Enum.map(members, & &1.email) == [a.email, b.email]
      assert Enum.all?(members, &(&1.status == "active"))
    end
  end

  describe "list_workspaces_for_user/1" do
    test "returns workspaces the user belongs to with their role" do
      %{workspace: ws, owner: owner} = create_workspace()

      [listed] = Workspaces.list_workspaces_for_user(owner.id)
      assert listed.id == ws.id
      assert listed.role == "admin"
      assert listed.organization_id == ws.organization_id
    end
  end
end
