defmodule Sovra.Auth.PasswordReset do
  @moduledoc """
  Time-limited single-use password reset tokens. The plaintext token is
  emailed to the user; only its SHA-256 hash is stored.
  """

  import Ecto.Query

  require Logger

  alias Sovra.Accounts
  alias Sovra.Auth.ArgsCrypto
  alias Sovra.Auth.MailerJob
  alias Sovra.Auth.PasswordResetToken
  alias Sovra.Auth.RefreshTokens
  alias Sovra.Repo

  @ttl_seconds 3600

  @doc """
  Issue a reset token for the given email and enqueue the mailer job.

  Always returns `:ok` regardless of whether the email matches a user, to
  avoid account enumeration. The mailer job is only enqueued when the
  email matches.
  """
  def request(email) when is_binary(email) do
    case Accounts.get_user_by_email(email) do
      nil ->
        :ok

      user ->
        plaintext = generate_plaintext()

        expires_at =
          DateTime.utc_now()
          |> DateTime.add(@ttl_seconds, :second)
          |> DateTime.truncate(:second)

        {:ok, _} =
          %PasswordResetToken{}
          |> Ecto.Changeset.change(%{
            user_id: user.id,
            token_hash: hash(plaintext),
            expires_at: expires_at
          })
          |> Repo.insert()

        # The plaintext token is encrypted before going into oban_jobs.args
        # so a DB-backup leak doesn't expose a usable reset link. The worker
        # decrypts it just-in-time when sending the email.
        enqueue_email(%{
          kind: "password_reset",
          user_id: user.id,
          encrypted_token: ArgsCrypto.encrypt(plaintext)
        })

        :ok
    end
  end

  @doc """
  Consume a reset token and update the user's password. On success,
  marks the token used, updates the password, and revokes every active
  refresh token for the user.
  """
  def confirm(plaintext, new_password) when is_binary(plaintext) and is_binary(new_password) do
    hashed = hash(plaintext)
    now = now()

    record =
      Repo.one(
        from(t in PasswordResetToken,
          where: t.token_hash == ^hashed and is_nil(t.used_at) and t.expires_at > ^now,
          limit: 1
        )
      )

    case record do
      nil ->
        {:error, :invalid_or_expired}

      token ->
        case Accounts.get_user(token.user_id) do
          nil ->
            {:error, :invalid_or_expired}

          user ->
            result =
              Repo.transaction(fn ->
                # Atomic single-use claim: a conditional UPDATE that only
                # affects the row if `used_at` is still NULL. Two concurrent
                # confirms with the same token cannot both win — exactly one
                # sees count == 1, the other sees 0 and rolls back.
                claim =
                  Repo.update_all(
                    from(t in PasswordResetToken,
                      where: t.id == ^token.id and is_nil(t.used_at)
                    ),
                    set: [used_at: now]
                  )

                case claim do
                  {1, _} ->
                    case Accounts.update_password(user, new_password) do
                      {:ok, updated_user} ->
                        :ok = RefreshTokens.revoke_all_for_user(user.id)
                        updated_user

                      {:error, reason} ->
                        Repo.rollback(reason)
                    end

                  {0, _} ->
                    Repo.rollback(:already_used)
                end
              end)

            case result do
              {:ok, updated_user} ->
                enqueue_email(%{kind: "password_changed", user_id: updated_user.id})
                {:ok, updated_user}

              {:error, :already_used} ->
                {:error, :invalid_or_expired}

              {:error, _} = error ->
                error
            end
        end
    end
  end

  defp enqueue_email(args) do
    case args |> MailerJob.new() |> Oban.insert() do
      {:ok, _job} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "Failed to enqueue auth email (kind=#{args[:kind] || args["kind"]}): #{inspect(reason)}"
        )

        :ok
    end
  end

  defp generate_plaintext do
    Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
  end

  defp hash(plaintext) do
    :crypto.hash(:sha256, plaintext) |> Base.encode16(case: :lower)
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)
end
