defmodule Sovra.Auth.IssuerInvitationsTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Auth.ArgsCrypto
  alias Sovra.Auth.IssuerInvitation
  alias Sovra.Auth.IssuerInvitations
  alias Sovra.Auth.MailerJob
  alias Sovra.Organizations
  alias Sovra.Workspaces

  @attrs %{
    full_name: "Test User",
    organization_name: "Test Organization",
    password: "a-very-strong-password-123"
  }

  defp unique_email, do: "inv-#{System.unique_integer([:positive])}@example.com"

  # Invite someone and recover the plaintext token the way the invitee would:
  # by reading the mail we just enqueued.
  defp invite(email \\ nil) do
    email = email || unique_email()
    {:ok, invitation} = IssuerInvitations.create(email, fixture_user().id)
    {invitation, latest_secret("issuer_invitation", "encrypted_token")}
  end

  defp request_code!(token) do
    {:ok, _} = IssuerInvitations.request_code(token)
    latest_secret("issuer_invitation_code", "encrypted_code")
  end

  defp latest_secret(kind, key) do
    %{args: args} =
      all_enqueued(worker: MailerJob)
      |> Enum.filter(&(&1.args["kind"] == kind))
      |> Enum.max_by(& &1.id)

    {:ok, plaintext} = ArgsCrypto.decrypt(args[key])
    plaintext
  end

  defp reload(%IssuerInvitation{id: id}), do: Repo.get!(IssuerInvitation, id)

  defp expire_invitation(%IssuerInvitation{id: id}) do
    Repo.update_all(from(i in IssuerInvitation, where: i.id == ^id),
      set: [
        expires_at: DateTime.utc_now() |> DateTime.add(-1, :second) |> DateTime.truncate(:second)
      ]
    )
  end

  defp expire_code(%IssuerInvitation{id: id}) do
    Repo.update_all(from(i in IssuerInvitation, where: i.id == ^id),
      set: [
        code_expires_at:
          DateTime.utc_now() |> DateTime.add(-1, :second) |> DateTime.truncate(:second)
      ]
    )
  end

  describe "create/2" do
    test "stores a pending invitation and enqueues the invitation email" do
      email = unique_email()
      admin = fixture_user()

      assert {:ok, invitation} = IssuerInvitations.create(email, admin.id)

      assert invitation.email == email
      assert invitation.invited_by_user_id == admin.id
      assert is_nil(invitation.used_at)
      assert is_nil(invitation.revoked_at)
      assert is_nil(invitation.code_hash)
      assert invitation.code_attempts == 0

      # 48 h, give or take the time the test took to get here.
      ttl = DateTime.diff(invitation.expires_at, DateTime.utc_now())
      assert ttl > 47 * 3600 and ttl <= 48 * 3600

      assert_enqueued(worker: MailerJob, args: %{"kind" => "issuer_invitation", "email" => email})
    end

    test "the plaintext token is never stored, only its hash" do
      {invitation, token} = invite()

      assert invitation.token_hash != token
      assert invitation.token_hash == :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
    end

    test "downcases the address" do
      assert {:ok, invitation} = IssuerInvitations.create("Pat@EXAMPLE.COM", fixture_user().id)
      assert invitation.email == "pat@example.com"
    end

    test "rejects an email that already has an account" do
      existing = fixture_user()

      assert {:error, :already_registered} =
               IssuerInvitations.create(existing.email, fixture_user().id)
    end

    test "rejects a second pending invitation for the same address" do
      email = unique_email()
      {:ok, _} = IssuerInvitations.create(email, fixture_user().id)

      assert {:error, :already_invited} = IssuerInvitations.create(email, fixture_user().id)
    end

    test "allows re-inviting once the first invitation expired" do
      email = unique_email()
      {:ok, first} = IssuerInvitations.create(email, fixture_user().id)
      expire_invitation(first)

      assert {:ok, _second} = IssuerInvitations.create(email, fixture_user().id)
    end
  end

  describe "lookup/1" do
    test "returns the invited address" do
      email = unique_email()
      {_invitation, token} = invite(email)

      assert {:ok, %{email: ^email}} = IssuerInvitations.lookup(token)
    end

    test "unknown, expired, revoked and used tokens are indistinguishable" do
      assert {:error, :invalid_invitation} = IssuerInvitations.lookup("not-a-real-token")
      assert {:error, :invalid_invitation} = IssuerInvitations.lookup(nil)

      {expired, expired_token} = invite()
      expire_invitation(expired)
      assert {:error, :invalid_invitation} = IssuerInvitations.lookup(expired_token)

      {revoked, revoked_token} = invite()
      {:ok, _} = IssuerInvitations.revoke(revoked.id)
      assert {:error, :invalid_invitation} = IssuerInvitations.lookup(revoked_token)

      {_used, used_token} = invite()
      code = request_code!(used_token)
      {:ok, _} = IssuerInvitations.accept(used_token, code, @attrs)
      assert {:error, :invalid_invitation} = IssuerInvitations.lookup(used_token)
    end
  end

  describe "request_code/1" do
    test "stores the code hashed and enqueues it to the invited address" do
      email = unique_email()
      {invitation, token} = invite(email)

      code = request_code!(token)
      reloaded = reload(invitation)

      assert code =~ ~r/^\d{6}$/
      assert reloaded.code_hash != code
      assert reloaded.code_attempts == 0
      assert DateTime.compare(reloaded.code_expires_at, DateTime.utc_now()) == :gt

      ttl = DateTime.diff(reloaded.code_expires_at, DateTime.utc_now())
      assert ttl > 14 * 60 and ttl <= 15 * 60

      assert_enqueued(
        worker: MailerJob,
        args: %{"kind" => "issuer_invitation_code", "email" => email}
      )
    end

    test "resending supersedes the previous code and clears spent attempts" do
      {invitation, token} = invite()
      first_code = request_code!(token)

      assert {:error, :invalid_code} = IssuerInvitations.accept(token, "000000", @attrs)
      assert reload(invitation).code_attempts == 1

      second_code = request_code!(token)
      assert second_code != first_code
      assert reload(invitation).code_attempts == 0

      assert {:error, :invalid_code} = IssuerInvitations.accept(token, first_code, @attrs)
      assert {:ok, _} = IssuerInvitations.accept(token, second_code, @attrs)
    end

    test "rejects an invitation that is no longer pending" do
      {invitation, token} = invite()
      expire_invitation(invitation)

      assert {:error, :invalid_invitation} = IssuerInvitations.request_code(token)
    end
  end

  describe "accept/3" do
    test "creates the user, their organization, an owner membership and a workspace" do
      email = unique_email()
      {invitation, token} = invite(email)
      code = request_code!(token)

      assert {:ok, %{user: user, organization: organization, workspace: workspace}} =
               IssuerInvitations.accept(token, code, @attrs)

      assert user.email == email
      assert user.full_name == "Test User"
      refute user.is_admin
      assert organization.name == "Test Organization"
      assert {:ok, "owner"} = Organizations.member_role(organization.id, user.id)

      # The password went through the normal hashing path.
      assert {:ok, _} = Sovra.Accounts.authenticate(email, @attrs.password)

      # Redeeming goes through register_user/1, so the invitee lands on a ready
      # workspace: named from the form, owned by them, keys and DID pending.
      assert workspace.name == "Test Organization"
      assert workspace.organization_id == organization.id
      assert workspace.provisioning_status == "pending"
      assert [%{id: workspace_id}] = Workspaces.list_workspaces_for_user(user.id)
      assert workspace_id == workspace.id
      assert {:ok, "admin"} = Workspaces.member_role(workspace.id, user.id)

      assert reload(invitation).used_at
    end

    test "the account address comes from the invitation, not from the caller" do
      email = unique_email()
      {_invitation, token} = invite(email)
      code = request_code!(token)

      attrs = Map.put(@attrs, :email, "attacker@example.com")

      assert {:ok, %{user: user}} = IssuerInvitations.accept(token, code, attrs)
      assert user.email == email
      refute Sovra.Accounts.get_user_by_email("attacker@example.com")
    end

    test "a wrong code spends an attempt without consuming the invitation" do
      {invitation, token} = invite()
      code = request_code!(token)

      assert {:error, :invalid_code} = IssuerInvitations.accept(token, "000000", @attrs)

      reloaded = reload(invitation)
      assert reloaded.code_attempts == 1
      assert is_nil(reloaded.used_at)

      # The real code still works afterwards.
      assert {:ok, _} = IssuerInvitations.accept(token, code, @attrs)
    end

    test "burns the code after five wrong attempts" do
      {_invitation, token} = invite()
      code = request_code!(token)

      for _ <- 1..5 do
        assert {:error, :invalid_code} = IssuerInvitations.accept(token, "000000", @attrs)
      end

      assert {:error, :too_many_attempts} = IssuerInvitations.accept(token, code, @attrs)
    end

    # Five typos must not lock the invitee out for good.
    test "a fresh code recovers from a burnt one" do
      {_invitation, token} = invite()
      code = request_code!(token)

      for _ <- 1..5 do
        assert {:error, :invalid_code} = IssuerInvitations.accept(token, "000000", @attrs)
      end

      assert {:error, :too_many_attempts} = IssuerInvitations.accept(token, code, @attrs)

      new_code = request_code!(token)
      assert {:ok, _} = IssuerInvitations.accept(token, new_code, @attrs)
    end

    test "rejects an expired code" do
      {invitation, token} = invite()
      code = request_code!(token)
      expire_code(invitation)

      assert {:error, :code_expired} = IssuerInvitations.accept(token, code, @attrs)
      assert is_nil(reload(invitation).used_at)
    end

    test "rejects a code that was never requested" do
      {_invitation, token} = invite()

      assert {:error, :code_not_requested} = IssuerInvitations.accept(token, "000000", @attrs)
    end

    test "is single use" do
      {_invitation, token} = invite()
      code = request_code!(token)

      assert {:ok, _} = IssuerInvitations.accept(token, code, @attrs)
      assert {:error, :invalid_invitation} = IssuerInvitations.accept(token, code, @attrs)
    end

    test "rejects an expired invitation even with the right code" do
      {invitation, token} = invite()
      code = request_code!(token)
      expire_invitation(invitation)

      assert {:error, :invalid_invitation} = IssuerInvitations.accept(token, code, @attrs)
    end

    test "a weak password fails without consuming the invitation" do
      {invitation, token} = invite()
      code = request_code!(token)

      assert {:error, %Ecto.Changeset{}} =
               IssuerInvitations.accept(token, code, %{@attrs | password: "short"})

      assert is_nil(reload(invitation).used_at)
      assert {:ok, _} = IssuerInvitations.accept(token, code, @attrs)
    end
  end

  describe "list_pending/0 and revoke/1" do
    test "lists only redeemable invitations" do
      {_pending, _} = invite("pending-#{System.unique_integer([:positive])}@example.com")
      {expired, _} = invite()
      expire_invitation(expired)
      {revoked, _} = invite()
      {:ok, _} = IssuerInvitations.revoke(revoked.id)

      ids = IssuerInvitations.list_pending() |> Enum.map(& &1.id)

      refute expired.id in ids
      refute revoked.id in ids
      assert length(ids) == 1
    end

    test "a revoked invitation cannot be redeemed" do
      {invitation, token} = invite()
      code = request_code!(token)

      assert {:ok, _} = IssuerInvitations.revoke(invitation.id)
      assert {:error, :invalid_invitation} = IssuerInvitations.accept(token, code, @attrs)
    end

    test "an already-redeemed invitation cannot be revoked" do
      {invitation, token} = invite()
      code = request_code!(token)
      {:ok, _} = IssuerInvitations.accept(token, code, @attrs)

      assert {:error, :already_used} = IssuerInvitations.revoke(invitation.id)
    end

    test "revoking something that does not exist" do
      assert {:error, :not_found} = IssuerInvitations.revoke(Ecto.UUID.generate())
    end

    # The id comes off the URL, so a non-UUID must not reach Repo.get/2.
    test "revoking a malformed id" do
      assert {:error, :not_found} = IssuerInvitations.revoke("not-a-uuid")
    end
  end
end
