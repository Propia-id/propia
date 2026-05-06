# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs

alias Sovra.Accounts

# Create a default admin account for development
case Accounts.create_admin(%{email: "admin@sovra.dev", password: "password1234"}) do
  {:ok, account} ->
    IO.puts("Admin account created: #{account.email}")

  {:error, changeset} ->
    if Keyword.has_key?(changeset.errors, :email) do
      IO.puts("Admin account already exists: admin@sovra.dev")
    else
      IO.puts("Failed to create admin: #{inspect(changeset.errors)}")
    end
end
