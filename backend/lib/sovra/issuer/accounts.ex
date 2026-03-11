defmodule Sovra.Issuer.Accounts do
  @moduledoc """
  Account management for issuer dashboard users.
  """

  alias Sovra.Issuer.{IssuerAccount, IssuerRecord}
  alias Sovra.Auth.IssuerSession
  alias Sovra.Repo

  import Ecto.Query

  def register(email, password, issuer_name) do
    Repo.transaction(fn ->
      case Sovra.Issuer.create_issuer(issuer_name) do
        {:ok, issuer} ->
          changeset =
            IssuerAccount.registration_changeset(%{
              email: email,
              password: password,
              issuer_id: issuer.id
            })

          case Repo.insert(changeset) do
            {:ok, account} ->
              {:ok, token} = IssuerSession.create(account.id, issuer.id)
              %{token: token, account: account, issuer: issuer}

            {:error, changeset} ->
              Repo.rollback(changeset)
          end

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  def authenticate(email, password) do
    account = Repo.one(from(a in IssuerAccount, where: a.email == ^email))

    cond do
      account && Bcrypt.verify_pass(password, account.password_hash) ->
        {:ok, token} = IssuerSession.create(account.id, account.issuer_id)
        issuer = Repo.get!(IssuerRecord, account.issuer_id)
        {:ok, %{token: token, account: account, issuer: issuer}}

      account ->
        {:error, :invalid_credentials}

      true ->
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}
    end
  end
end
