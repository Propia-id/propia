defmodule Sovra.Documents.DocumentLayout do
  @moduledoc """
  Where a document schema's fields sit on the page.

  An opaque map: the shape belongs to the editor. The renderer escapes every
  value and drops anything it does not recognise, so nothing here reaches a page
  unchecked.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "document_layouts" do
    field :layout, :map
    field :version, :integer, default: 1

    belongs_to :credential_schema, Sovra.Issuer.CredentialSchema

    timestamps(type: :utc_datetime)
  end

  def create_changeset(schema_id, layout) do
    %__MODULE__{}
    |> cast(%{credential_schema_id: schema_id, layout: layout}, [:credential_schema_id, :layout])
    |> validate_required([:credential_schema_id, :layout])
    |> unique_constraint(:credential_schema_id)
  end

  def update_changeset(record, layout) do
    record
    |> cast(%{layout: layout}, [:layout])
    |> validate_required([:layout])
    |> put_change(:version, (record.version || 1) + 1)
  end
end
