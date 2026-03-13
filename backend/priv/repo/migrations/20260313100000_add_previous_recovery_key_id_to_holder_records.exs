defmodule Sovra.Repo.Migrations.AddPreviousRecoveryKeyIdToHolderRecords do
  use Ecto.Migration

  def change do
    alter table(:holder_records) do
      add :previous_recovery_key_id, :string
    end
  end
end
