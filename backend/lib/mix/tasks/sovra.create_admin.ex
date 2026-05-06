defmodule Mix.Tasks.Sovra.CreateAdmin do
  @moduledoc """
  Creates an admin account for the issuer dashboard.

  ## Usage

      mix sovra.create_admin EMAIL PASSWORD

  The admin account can create and manage issuer accounts.
  Password must be at least 12 characters.
  """

  use Mix.Task

  @shortdoc "Create an admin account for the issuer dashboard"

  @impl Mix.Task
  def run([email, password]) do
    Mix.Task.run("app.start")

    case Sovra.Accounts.create_admin(%{email: email, password: password}) do
      {:ok, account} ->
        Mix.shell().info("Admin account created: #{account.email} (id: #{account.id})")

      {:error, changeset} ->
        errors =
          Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
            Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
              opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
            end)
          end)

        Mix.shell().error("Failed to create admin account: #{inspect(errors)}")
        exit({:shutdown, 1})
    end
  end

  def run(_) do
    Mix.shell().error("Usage: mix sovra.create_admin EMAIL PASSWORD")
    exit({:shutdown, 1})
  end
end
