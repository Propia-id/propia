defmodule Sovra.Auth.PasswordResetTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Accounts
  alias Sovra.Accounts.User
  alias Sovra.Auth.MailerJob
  alias Sovra.Auth.PasswordResetToken
  alias Sovra.Auth.RefreshToken
  alias Sovra.Auth.RefreshTokens
  alias Sovra.Auth.PasswordReset

  defp user do
    {:ok, account} =
      User.registration_changeset(%{
        email: "pr-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123",
        full_name: "Pat Reset"
      })
      |> Repo.insert()

    account
  end

  describe "request/1" do
    test "creates a token and enqueues a mailer job for known email" do
      u = user()
      :ok = PasswordReset.request(u.email)

      assert [token] = Repo.all(PasswordResetToken)
      assert token.user_id == u.id
      assert is_nil(token.used_at)
      assert DateTime.compare(token.expires_at, DateTime.utc_now()) == :gt

      assert_enqueued(worker: MailerJob, args: %{"kind" => "password_reset", "user_id" => u.id})
    end

    test "is a no-op for unknown email (no enumeration)" do
      :ok = PasswordReset.request("nobody-#{System.unique_integer([:positive])}@example.com")
      assert Repo.all(PasswordResetToken) == []
      refute_enqueued(worker: MailerJob)
    end
  end

  describe "confirm/2" do
    test "updates password, marks token used, revokes refresh tokens, sends email" do
      u = user()

      # Capture the plaintext token by decrypting what's in the enqueued job.
      :ok = PasswordReset.request(u.email)
      [%{args: %{"encrypted_token" => encrypted}}] = all_enqueued(worker: MailerJob)
      {:ok, plaintext} = Sovra.Auth.ArgsCrypto.decrypt(encrypted)

      {:ok, _refresh, _} = RefreshTokens.create(u.id)

      assert {:ok, %User{} = updated} =
               PasswordReset.confirm(plaintext, "a-new-strong-password-456")

      # Old password no longer works
      assert {:error, :invalid_credentials} =
               Accounts.authenticate(u.email, "a-very-strong-password-123")

      # New password works
      assert {:ok, _} = Accounts.authenticate(u.email, "a-new-strong-password-456")
      assert updated.id == u.id

      # Token is single-use
      assert {:error, :invalid_or_expired} =
               PasswordReset.confirm(plaintext, "a-new-strong-password-789")

      # All refresh tokens for the user revoked
      assert Repo.all(RefreshToken) |> Enum.all?(&(&1.revoked_at != nil))

      # A password-changed notification is enqueued
      assert_enqueued(worker: MailerJob, args: %{"kind" => "password_changed"})
    end

    test "rejects unknown token" do
      assert {:error, :invalid_or_expired} =
               PasswordReset.confirm("nope", "a-strong-password-456")
    end
  end
end
