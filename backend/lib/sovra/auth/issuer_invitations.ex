defmodule Sovra.Auth.IssuerInvitations do
  @moduledoc """
  Invitations to the issuer console, the only way an account gets created while
  self-service registration is closed.

  A super-admin authorizes an email; the invitee follows the emailed link and
  submits the form, which sends a short code to that same address. Both secrets
  are stored as SHA-256 only and neither is ever returned to the caller: the
  email is the channel, as in `Sovra.Auth.PasswordReset`.
  """

  import Ecto.Query

  alias Sovra.Accounts
  alias Sovra.Auth.ArgsCrypto
  alias Sovra.Auth.IssuerInvitation
  alias Sovra.Auth.MailerJob
  alias Sovra.Repo

  @invitation_ttl_seconds 48 * 3600
  @code_ttl_seconds 15 * 60
  @max_code_attempts 5

  @doc """
  Authorize `email` to create an issuer account. Inserts the invitation and
  its mailer job in one transaction, so an invitation never exists without
  the email that makes it usable.
  """
  def create(email, invited_by_user_id) when is_binary(email) do
    email = String.downcase(email)
    token = generate_token()

    with :ok <- ensure_invitable(email) do
      Ecto.Multi.new()
      |> Ecto.Multi.insert(
        :invitation,
        IssuerInvitation.create_changeset(%{
          email: email,
          token_hash: hash(token),
          expires_at: seconds_from_now(@invitation_ttl_seconds),
          invited_by_user_id: invited_by_user_id
        })
      )
      |> Oban.insert(:email, fn %{invitation: invitation} ->
        MailerJob.new(%{
          kind: "issuer_invitation",
          email: invitation.email,
          encrypted_token: ArgsCrypto.encrypt(token)
        })
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{invitation: invitation}} -> {:ok, invitation}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  @doc "The address an invitation is for, so the form can show who is signing up."
  def lookup(token) do
    with {:ok, invitation} <- fetch_pending(token) do
      {:ok, %{email: invitation.email}}
    end
  end

  @doc """
  Issue a fresh code to the invited address. Callable again to resend, which
  supersedes the previous code and clears the attempts spent on it.
  """
  def request_code(token) do
    with {:ok, invitation} <- fetch_pending(token) do
      code = generate_code()

      Ecto.Multi.new()
      |> Ecto.Multi.update(
        :invitation,
        IssuerInvitation.code_changeset(
          invitation,
          hash(code),
          seconds_from_now(@code_ttl_seconds)
        )
      )
      |> Oban.insert(:email, fn %{invitation: invitation} ->
        MailerJob.new(%{
          kind: "issuer_invitation_code",
          email: invitation.email,
          encrypted_code: ArgsCrypto.encrypt(code)
        })
      end)
      |> Repo.transaction()
      |> case do
        {:ok, _changes} -> {:ok, %{email: invitation.email}}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  @doc """
  Redeem an invitation: verify the code, then create the account through the
  ordinary registration path, which builds the user, an organization and a
  first workspace with its DID and signing keys.

  The account's email comes from the invitation, never from `attrs`. That is
  what makes the code meaningful. `attrs` requires `:full_name`,
  `:organization_name` and `:password`.
  """
  def accept(token, code, %{full_name: _, organization_name: _, password: _} = attrs) do
    with {:ok, invitation} <- fetch_pending(token),
         :ok <- verify_code(invitation, code) do
      claim_and_register(invitation, attrs)
    end
  end

  @doc "Invitations still redeemable, newest first."
  def list_pending do
    now = now()

    from(i in IssuerInvitation,
      where: is_nil(i.used_at) and is_nil(i.revoked_at) and i.expires_at > ^now,
      order_by: [desc: i.inserted_at],
      select: %{
        id: i.id,
        email: i.email,
        expires_at: i.expires_at,
        invited_by_user_id: i.invited_by_user_id,
        inserted_at: i.inserted_at
      }
    )
    |> Repo.all()
  end

  @doc "Cancel a pending invitation. An already-redeemed one cannot be revoked."
  def revoke(id) do
    # Repo.get/2 raises on anything that isn't a UUID, and the id comes off the URL.
    with {:ok, uuid} <- Ecto.UUID.cast(id),
         %IssuerInvitation{} = invitation <- Repo.get(IssuerInvitation, uuid) do
      if invitation.used_at do
        {:error, :already_used}
      else
        invitation
        |> IssuerInvitation.revoke_changeset(now())
        |> Repo.update()
      end
    else
      _ -> {:error, :not_found}
    end
  end

  # ── Internals ──────────────────────────────────────────

  defp ensure_invitable(email) do
    cond do
      Accounts.get_user_by_email(email) -> {:error, :already_registered}
      pending_for_email?(email) -> {:error, :already_invited}
      true -> :ok
    end
  end

  # A concurrent invite can slip a duplicate past this check. Harmless: the
  # first accept wins and the second hits the unique constraint on users.email.
  defp pending_for_email?(email) do
    now = now()

    Repo.exists?(
      from(i in IssuerInvitation,
        where:
          i.email == ^email and is_nil(i.used_at) and is_nil(i.revoked_at) and
            i.expires_at > ^now
      )
    )
  end

  # One error for unknown, expired, used and revoked alike. Distinguishing them
  # would tell a caller which tokens are real.
  defp fetch_pending(token) when is_binary(token) do
    invitation = Repo.one(from(i in IssuerInvitation, where: i.token_hash == ^hash(token)))

    if invitation && IssuerInvitation.pending?(invitation, now()) do
      {:ok, invitation}
    else
      {:error, :invalid_invitation}
    end
  end

  defp fetch_pending(_token), do: {:error, :invalid_invitation}

  defp verify_code(%IssuerInvitation{code_hash: nil}, _code), do: {:error, :code_not_requested}

  defp verify_code(%IssuerInvitation{} = invitation, code) do
    cond do
      invitation.code_attempts >= @max_code_attempts ->
        {:error, :too_many_attempts}

      DateTime.compare(invitation.code_expires_at, now()) != :gt ->
        {:error, :code_expired}

      matching_code?(invitation, code) ->
        :ok

      true ->
        spend_attempt(invitation)
        {:error, :invalid_code}
    end
  end

  defp matching_code?(%IssuerInvitation{code_hash: stored}, code) when is_binary(code),
    do: Plug.Crypto.secure_compare(hash(code), stored)

  defp matching_code?(_invitation, _code), do: false

  defp spend_attempt(%IssuerInvitation{id: id}) do
    Repo.update_all(from(i in IssuerInvitation, where: i.id == ^id), inc: [code_attempts: 1])
    :ok
  end

  # One transaction for the claim and the account, so a burnt invitation can
  # never end up without an account behind it.
  defp claim_and_register(%IssuerInvitation{} = invitation, attrs) do
    Repo.transaction(fn ->
      with {:ok, _claimed_at} <- claim(Repo, invitation),
           {:ok, result} <-
             Accounts.register_user(%{
               email: invitation.email,
               password: attrs.password,
               full_name: attrs.full_name,
               workspace_name: attrs.organization_name
             }) do
        result
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  # Single-use claim: the UPDATE only matches while used_at is NULL, so two
  # concurrent accepts cannot both win.
  defp claim(repo, %IssuerInvitation{id: id}) do
    now = now()

    case repo.update_all(
           from(i in IssuerInvitation, where: i.id == ^id and is_nil(i.used_at)),
           set: [used_at: now, updated_at: now]
         ) do
      {1, _} -> {:ok, now}
      {0, _} -> {:error, :invalid_invitation}
    end
  end

  defp generate_token, do: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

  defp generate_code do
    :crypto.strong_rand_bytes(4)
    |> :binary.decode_unsigned()
    |> rem(1_000_000)
    |> Integer.to_string()
    |> String.pad_leading(6, "0")
  end

  defp hash(plaintext), do: :crypto.hash(:sha256, plaintext) |> Base.encode16(case: :lower)

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp seconds_from_now(seconds), do: now() |> DateTime.add(seconds, :second)
end
