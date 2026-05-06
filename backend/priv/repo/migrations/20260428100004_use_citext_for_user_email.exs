defmodule Sovra.Repo.Migrations.UseCitextForUserEmail do
  @moduledoc """
  Move case-insensitive email uniqueness from app-code discipline
  (`String.downcase/1` in every changeset and query) to a property of
  the column itself, via the `citext` Postgres extension.

  After this migration, `Foo@x.com` and `foo@x.com` are equal under both
  the unique constraint and equality comparisons, regardless of how
  rows were inserted. The existing unique index is rebuilt automatically
  when the column type changes.

  We keep `update_change(:email, &String.downcase/1)` on the registration
  changesets so stored values remain canonical lowercase (cosmetic /
  display); the downcase calls on query paths are no longer load-bearing
  and have been removed from `Sovra.Accounts`.
  """
  use Ecto.Migration

  def up do
    execute "CREATE EXTENSION IF NOT EXISTS citext"

    alter table(:users) do
      modify :email, :citext, from: :string
    end
  end

  def down do
    alter table(:users) do
      modify :email, :string, from: :citext
    end

    # Don't DROP EXTENSION — other tables might depend on it.
  end
end
