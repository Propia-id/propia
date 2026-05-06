defmodule Sovra.Auth.RefreshTokensTest do
  use Sovra.DataCase, async: false

  import Ecto.Query

  alias Sovra.Accounts.User
  alias Sovra.Auth.RefreshToken
  alias Sovra.Auth.RefreshTokens

  defp user do
    {:ok, account} =
      User.admin_changeset(%{
        email: "rt-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Repo.insert()

    account
  end

  describe "create/1" do
    test "returns plaintext + persisted hashed record" do
      u = user()
      {:ok, plaintext, record} = RefreshTokens.create(u.id)

      assert is_binary(plaintext) and byte_size(plaintext) >= 40
      assert record.user_id == u.id
      refute record.token_hash == plaintext
      assert record.token_hash =~ ~r/^[0-9a-f]{64}$/
      assert DateTime.compare(record.expires_at, DateTime.utc_now()) == :gt
    end
  end

  describe "rotate/1" do
    test "revokes presented token and mints a new one" do
      u = user()
      {:ok, plaintext, original} = RefreshTokens.create(u.id)

      assert {:ok, user_id, new_plaintext, new_record} = RefreshTokens.rotate(plaintext)

      assert user_id == u.id
      assert new_plaintext != plaintext
      refute new_record.id == original.id

      reloaded = Repo.get!(RefreshToken, original.id)
      assert reloaded.revoked_at != nil
    end

    test "rejects unknown plaintext" do
      assert {:error, :invalid} = RefreshTokens.rotate("not-a-real-token")
    end

    test "rejects revoked plaintext as reuse and revokes the entire user family" do
      u = user()
      {:ok, plaintext, _} = RefreshTokens.create(u.id)
      {:ok, _other_plaintext, other} = RefreshTokens.create(u.id)
      :ok = RefreshTokens.revoke(plaintext)

      assert {:error, :reuse_detected} = RefreshTokens.rotate(plaintext)

      # Other active tokens for the same user are revoked as a theft response.
      assert Repo.get!(RefreshToken, other.id).revoked_at != nil
    end

    test "rejects expired plaintext" do
      u = user()
      {:ok, plaintext, record} = RefreshTokens.create(u.id)

      # Force-expire the record.
      Repo.update_all(
        from(rt in RefreshToken, where: rt.id == ^record.id),
        set: [expires_at: ~U[2000-01-01 00:00:00Z]]
      )

      assert {:error, :invalid} = RefreshTokens.rotate(plaintext)
    end

    test "concurrent rotates of the same plaintext: exactly one wins" do
      # Two parallel rotates of the same token must not both succeed —
      # the conditional UPDATE inside rotate/1 guarantees atomic claim.
      # The second caller either sees :invalid (its UPDATE matched 0 rows
      # because the row was already revoked) or :reuse_detected (the row
      # existed but had revoked_at set).
      u = user()
      {:ok, plaintext, _} = RefreshTokens.create(u.id)

      parent = self()

      tasks =
        for _ <- 1..2 do
          Task.async(fn ->
            Ecto.Adapters.SQL.Sandbox.allow(Sovra.Repo, parent, self())
            RefreshTokens.rotate(plaintext)
          end)
        end

      results = Task.await_many(tasks, 2_000)

      successes = Enum.count(results, &match?({:ok, _, _, _}, &1))
      failures = Enum.count(results, &match?({:error, _}, &1))

      assert successes == 1
      assert failures == 1
    end
  end

  describe "revoke_all_for_user/1" do
    test "marks every active token revoked" do
      u = user()
      {:ok, _, a} = RefreshTokens.create(u.id)
      {:ok, _, b} = RefreshTokens.create(u.id)

      :ok = RefreshTokens.revoke_all_for_user(u.id)

      assert Repo.get!(RefreshToken, a.id).revoked_at != nil
      assert Repo.get!(RefreshToken, b.id).revoked_at != nil
    end
  end
end
