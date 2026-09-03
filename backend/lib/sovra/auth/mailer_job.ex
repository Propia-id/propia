defmodule Sovra.Auth.MailerJob do
  @moduledoc "Oban worker that delivers transactional auth emails with retry semantics."

  use Oban.Worker, queue: :mailers, max_attempts: 5
  use Sovra.Log

  alias Sovra.Accounts
  alias Sovra.Auth.ArgsCrypto
  alias Sovra.Auth.Emails
  alias Sovra.Mailer

  @impl Oban.Worker
  def perform(%Oban.Job{args: args} = job) do
    Log.adopt_job_context(job)

    Log.put_context(
      kind: args["kind"],
      user_id: args["user_id"],
      email: args["email"]
    )

    case deliver_for(job) do
      :ok ->
        # accounts.ex logged only the enqueue failure, so a mail that was
        # accepted and then never sent produced nothing at all.
        Log.event(:info, "auth email sent", event: "email.sent", kind: args["kind"])
        :ok

      {:error, reason} ->
        Log.event(:error, "auth email delivery failed",
          event: "email.failed",
          kind: args["kind"],
          reason: Log.reason(reason)
        )

        {:error, reason}

      other ->
        other
    end
  end

  # Invitation mail goes out before the account exists, so these two resolve
  # the recipient from the job args instead of looking up a user.
  defp deliver_for(%Oban.Job{args: %{"kind" => "issuer_invitation", "email" => email} = args}) do
    case ArgsCrypto.decrypt(args["encrypted_token"] || "") do
      {:ok, token} -> deliver(Emails.issuer_invitation(email, build_invitation_link(token)))
      :error -> {:error, :decrypt_failed}
    end
  end

  defp deliver_for(%Oban.Job{
         args: %{"kind" => "issuer_invitation_code", "email" => email} = args
       }) do
    case ArgsCrypto.decrypt(args["encrypted_code"] || "") do
      {:ok, code} -> deliver(Emails.issuer_invitation_code(email, code))
      :error -> {:error, :decrypt_failed}
    end
  end

  defp deliver_for(%Oban.Job{args: %{"kind" => kind} = args}) do
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

  defp build_invitation_link(token) do
    base = Application.get_env(:sovra, :issuer_frontend_url, "http://localhost:5173")
    "#{base}/accept-invitation?token=#{token}"
  end

  defp deliver(email) do
    case Mailer.deliver(email) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end
end
