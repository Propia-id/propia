defmodule Sovra.OrganizationsTest do
  use Sovra.DataCase, async: true

  alias Sovra.Accounts.User
  alias Sovra.Organizations
  alias Sovra.Organizations.{Organization, OrganizationMember}

  defp create_user(suffix \\ "#{System.unique_integer([:positive])}") do
    # Use admin_changeset (the only path that doesn't require a workspace),
    # since we're testing Organizations in isolation from Workspaces here.
    {:ok, account} =
      User.admin_changeset(%{
        email: "user-#{suffix}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Repo.insert()

    account
  end

  describe "create_organization/2" do
    test "creates org and owner membership atomically" do
      user = create_user()

      {:ok, %{organization: org, membership: mem}} =
        Organizations.create_organization(user.id, %{
          name: "Acme",
          logo_url: "https://acme.test/logo.png",
          website: "https://acme.test"
        })

      assert org.name == "Acme"
      assert org.status == "active"
      assert mem.role == "owner"
      assert mem.organization_id == org.id
      assert mem.user_id == user.id
    end

    test "requires a name" do
      user = create_user()
      assert {:error, %Ecto.Changeset{} = cs} = Organizations.create_organization(user.id, %{})
      assert %{name: ["can't be blank"]} = errors_on(cs)
    end

    test "rejects invalid URLs" do
      user = create_user()

      assert {:error, %Ecto.Changeset{} = cs} =
               Organizations.create_organization(user.id, %{
                 name: "Acme",
                 logo_url: "not-a-url",
                 website: "also-not"
               })

      errors = errors_on(cs)
      assert errors.logo_url
      assert errors.website
    end
  end

  describe "update_organization/2" do
    setup do
      user = create_user()

      {:ok, %{organization: org}} =
        Organizations.create_organization(user.id, %{name: "Acme"})

      %{user: user, org: org}
    end

    test "updates branding fields", %{org: org} do
      {:ok, updated} =
        Organizations.update_organization(org, %{
          name: "Acme Inc.",
          website: "https://acme.inc"
        })

      assert updated.name == "Acme Inc."
      assert updated.website == "https://acme.inc"
    end

    test "refuses updates on deactivated organizations", %{org: org} do
      {:ok, deactivated} = Organizations.deactivate_organization(org)

      assert {:error, %Ecto.Changeset{}} =
               Organizations.update_organization(deactivated, %{name: "Ignored"})
    end
  end

  describe "deactivate_organization/1" do
    test "sets status to deactivated" do
      user = create_user()

      {:ok, %{organization: org}} =
        Organizations.create_organization(user.id, %{name: "Acme"})

      {:ok, updated} = Organizations.deactivate_organization(org)
      assert updated.status == "deactivated"
    end
  end

  describe "member_role/2 and add_member/3" do
    test "returns role for members, :not_a_member otherwise" do
      owner = create_user("o")
      other = create_user("x")

      {:ok, %{organization: org}} =
        Organizations.create_organization(owner.id, %{name: "Acme"})

      assert {:ok, "owner"} = Organizations.member_role(org.id, owner.id)
      assert {:error, :not_a_member} = Organizations.member_role(org.id, other.id)

      {:ok, %OrganizationMember{role: "member"}} =
        Organizations.add_member(org.id, other.id, "member")

      assert {:ok, "member"} = Organizations.member_role(org.id, other.id)
    end
  end

  describe "list_members/1" do
    test "returns members ordered by email with placeholder status" do
      alice = create_user("alice")
      bob = create_user("bob")

      # Re-create accounts with deterministic emails to make ordering obvious.
      {:ok, alice} =
        alice
        |> Ecto.Changeset.change(email: "alice@example.com")
        |> Repo.update()

      {:ok, bob} =
        bob
        |> Ecto.Changeset.change(email: "bob@example.com")
        |> Repo.update()

      {:ok, %{organization: org}} =
        Organizations.create_organization(alice.id, %{name: "Acme"})

      {:ok, _} = Organizations.add_member(org.id, bob.id, "member")

      members = Organizations.list_members(org.id)

      assert Enum.map(members, & &1.email) == ["alice@example.com", "bob@example.com"]
      assert Enum.all?(members, &(&1.status == "active"))

      roles = Map.new(members, &{&1.email, &1.role})
      assert roles["alice@example.com"] == "owner"
      assert roles["bob@example.com"] == "member"
    end
  end

  describe "list_organizations_for_user/1" do
    test "returns only orgs the user belongs to with their role" do
      alice = create_user("a")
      bob = create_user("b")

      {:ok, %{organization: alices_org}} =
        Organizations.create_organization(alice.id, %{name: "Alice Org"})

      {:ok, _} = Organizations.create_organization(bob.id, %{name: "Bob Org"})

      alice_orgs = Organizations.list_organizations_for_user(alice.id)
      assert length(alice_orgs) == 1
      assert hd(alice_orgs).id == alices_org.id
      assert hd(alice_orgs).role == "owner"
    end
  end

  describe "composite primary key" do
    test "adding the same user twice to the same org is rejected" do
      user = create_user()

      {:ok, %{organization: org}} =
        Organizations.create_organization(user.id, %{name: "Acme"})

      # The create_organization call above already added user as owner.
      # Adding again (even as a different role) should be rejected by the PK.
      assert_raise Ecto.ConstraintError, fn ->
        Organizations.add_member(org.id, user.id, "member")
      end
    end

    test "Organization schema has expected associations" do
      user = create_user()

      {:ok, %{organization: org}} =
        Organizations.create_organization(user.id, %{name: "Acme"})

      preloaded = Repo.preload(org, :members)
      assert [%OrganizationMember{user_id: uid}] = preloaded.members
      assert uid == user.id

      assert %Organization{} = preloaded
    end
  end
end
