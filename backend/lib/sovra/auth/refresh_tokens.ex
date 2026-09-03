defmodule Sovra.Auth.RefreshTokens do
  @moduledoc """
  Opaque refresh tokens with rotation. The plaintext token is returned to
  the caller exactly once and stored only as a SHA-256 hash. Each refresh
  rotates the token: the presented one is revoked atomically (via a
  conditional UPDATE) and a new one issued.

  If a token presented for rotation is found in the table but already
  revoked, that's a reuse signal — every active refresh token for the
  user is revoked (theft response).
  """

  use Sovra.Log

  import Ecto.Query

  alias Sovra.Auth.RefreshToken
  alias Sovra.Repo

  @ttl_seconds 14 * 24 * 3600

  @doc "Mint a new refresh token for `user_id`. Returns `{:ok, plaintext, %RefreshToken{}}`."
  def create(user_id) do
    plaintext = generate_plaintext()

    expires_at =
      DateTime.utc_now()
      |> DateTime.add(@ttl_seconds, :second)
      |> DateTime.truncate(:second)

    %RefreshToken{}
    |> Ecto.Changeset.change(%{
      user_id: user_id,
      token_hash: hash(plaintext),
      expires_at: expires_at
    })
    |> Repo.insert()
    |> case do
      {:ok, record} -> {:ok, plaintext, record}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @doc """
  Verify a presented refresh token, revoke it atomically, and mint a new
  one for the same user. Returns `{:ok, user_id, new_plaintext, new_record}`
  on success.

  Concurrency: the revoke step is a conditional `UPDATE … WHERE
  revoked_at IS NULL`, so two simultaneous rotates of the same plaintext
  cannot both succeed — exactly one will see `count == 1`, the other
  `count == 0` and fall through to the reuse-detection branch.

  Reuse detection: if a token is found by hash but already revoked,
  `revoke_all_for_user/1` is called. The caller gets `{:error, :reuse_detected}`
  and should treat the active session as compromised.
  """
  def rotate(plaintext) when is_binary(plaintext) do
    hashed = hash(plaintext)
    now = now()

    # Atomic claim: revoke the row only if it's still active. RETURNING
    # gives us the row's user_id without a separate SELECT.
    query =
      from(rt in RefreshToken,
        where: rt.token_hash == ^hashed and is_nil(rt.revoked_at) and rt.expires_at > ^now,
        select: rt
      )

    case Repo.update_all(query, set: [revoked_at: now, last_used_at: now]) do
      {1, [revoked]} ->
        case create(revoked.user_id) do
          {:ok, plaintext, new_record} ->
            {:ok, revoked.user_id, plaintext, new_record}

          {:error, _} = error ->
            error
        end

      {0, _} ->
        # Either unknown, expired, or already revoked. Distinguish:
        case Repo.one(from(rt in RefreshToken, where: rt.token_hash == ^hashed, limit: 1)) do
          %RefreshToken{revoked_at: revoked_at, user_id: user_id} when not is_nil(revoked_at) ->
            # A revoked token being presented again means either a stolen
            # cookie or a broken client. Either way the whole family is
            # revoked, which logs the user out everywhere — worth an alert.
            Log.event(:warning, "refresh token reuse detected",
              event: "auth.refresh_token.reuse_detected",
              user_id: user_id
            )

            :ok = revoke_all_for_user(user_id)
            {:error, :reuse_detected}

          _ ->
            {:error, :invalid}
        end
    end
  end

  @doc "Revoke a refresh token by plaintext (no-op if already revoked or unknown)."
  def revoke(plaintext) when is_binary(plaintext) do
    hashed = hash(plaintext)

    from(rt in RefreshToken,
      where: rt.token_hash == ^hashed and is_nil(rt.revoked_at)
    )
    |> Repo.update_all(set: [revoked_at: now()])

    :ok
  end

  @doc "Revoke every active refresh token for a user (used after password reset or theft)."
  def revoke_all_for_user(user_id) do
    from(rt in RefreshToken,
      where: rt.user_id == ^user_id and is_nil(rt.revoked_at)
    )
    |> Repo.update_all(set: [revoked_at: now()])

    :ok
  end

  defp generate_plaintext do
    Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
  end

  defp hash(plaintext) do
    :crypto.hash(:sha256, plaintext) |> Base.encode16(case: :lower)
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)
end
