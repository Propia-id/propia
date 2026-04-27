defmodule Sovra.Repo.Migrations.AddWebhookFieldsToWorkspaces do
  use Ecto.Migration

  def change do
    alter table(:workspaces) do
      add :webhook_url, :string
      add :webhook_secret_key_id, :string
    end
  end
end
