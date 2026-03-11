defmodule Sovra.Repo.Migrations.RenameServerKeyToRecoveryKey do
  use Ecto.Migration

  def change do
    rename table(:holder_records), :server_key_id, to: :recovery_key_id
    rename table(:holder_records), :server_public_key_x, to: :recovery_public_key_x
    rename table(:holder_records), :server_public_key_y, to: :recovery_public_key_y

    drop index(:holder_records, [:server_key_id])
    create index(:holder_records, [:recovery_key_id])
  end
end
