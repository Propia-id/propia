defmodule Sovra.Issuer.CredentialSchema do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @kinds ~w(credential document)

  schema "credential_schemas" do
    field :schema_id, :string
    field :credential_type, :string
    field :name, :string
    field :claims, {:array, :map}
    field :validity_period, :string
    field :version, :integer, default: 1

    # "credential" → issued to a wallet over OID4VCI, bound to a holder key.
    # "document"   → issued and signed directly by the issuer, no holder.
    field :kind, :string, default: "credential"

    belongs_to :issuer, Sovra.Workspaces.Workspace

    timestamps(type: :utc_datetime)
  end

  @required ~w(schema_id issuer_id credential_type name claims)a

  # Optional, but validated whenever the key is given: parse_validity_period/1
  # falls back to a year on anything it cannot read, so "1yr" would silently
  # become a real date. Zero is rejected too — "0d" puts `exp` at issuance, dead
  # on arrival.
  @validity_period ~r/^[1-9]\d*(y|m|d)$/

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ [:version, :kind])
    # Cast on its own with `empty_values: []` so a blank period reaches
    # validate_format/3. Ecto's default treats "" — and any whitespace-only
    # string — as empty and casts it to the field default, recording no change:
    # validate_format/3 would never run and the schema would read as an explicit
    # "no expiry", which is the one thing nil is not allowed to be guessed for.
    |> cast(attrs, [:validity_period], empty_values: [])
    |> validate_required(@required)
    |> validate_format(:validity_period, @validity_period)
    |> validate_inclusion(:kind, @kinds)
    |> unique_constraint([:issuer_id, :schema_id, :version])
  end

  def kinds, do: @kinds

  @doc """
  Asserts a schema is of the expected kind.

  A credential schema is issued to a wallet over OID4VCI; a document schema is
  signed directly by the issuer. Mixing the two flows is always a mistake, so
  both entry points assert rather than trusting the caller.
  """
  def assert_kind(%__MODULE__{kind: kind}, kind), do: :ok
  def assert_kind(%__MODULE__{kind: kind}, _expected), do: {:error, {:wrong_schema_kind, kind}}
end
