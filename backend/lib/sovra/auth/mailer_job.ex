defmodule Sovra.Auth.MailerJob do
  @moduledoc "Oban worker that delivers transactional auth emails with retry semantics."

  use Oban.Worker, queue: :mailers, max_attempts: 5

  alias Sovra.Accounts
  alias Sovra.Auth.ArgsCrypto
  alias Sovra.Auth.Emails
  alias Sovra.Mailer

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"kind" => kind} = args}) do
    case Accounts.get_user(args["user_id"]) do
      nil ->
        :ok

      user ->
        with {:ok, email} <- build_email(kind, user, args),
             {:ok, _} <- Mailer.deliver(email) do
          :ok
        else
          {:error, reason} -> {:error, reason}
          :error -> {:error, :decrypt_failed}
        end
    end
  end

  defp build_email("password_reset", user, args) do
    case ArgsCrypto.decrypt(args["encrypted_token"] || "") do
      {:ok, token} ->
        {:ok, Emails.password_reset(user.email, user.full_name, build_reset_link(token))}

      :error ->
        :error
    end
  end

  defp build_email("welcome", user, args) do
    {:ok, Emails.welcome(user.email, user.full_name, args["workspace_name"])}
  end

  defp build_email("password_changed", user, _args) do
    {:ok, Emails.password_changed(user.email, user.full_name)}
  end

  defp build_reset_link(token) do
    base = Application.get_env(:sovra, :issuer_frontend_url, "http://localhost:5173")
    "#{base}/reset-password?token=#{token}"
  end
end
