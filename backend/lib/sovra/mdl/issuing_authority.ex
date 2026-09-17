defmodule Sovra.Mdl.IssuingAuthority do
  @moduledoc """
  An admitted IACA root — the trust anchor our verifiers accept an mDL chain
  against.

  ## Existence is the admission

  There is no status column. A row here means a platform admin decided this
  root may be trusted, and our verifiers accept a chain exactly when it ends at
  one. A second flag would be a second decision that could disagree with the
  first, and the only question anyone actually asks is whether the root is
  admitted.

  That decision cannot be delegated to the certificate itself. Anyone can
  self-sign a root naming any country and authority they like — the result is
  structurally indistinguishable from a real one — so "the CA signed it" is
  circular when the issuer supplies the CA too. Every X.509 chain ends at a
  root somebody chose to trust out of band, and this table is where that choice
  is written down.

  In the wider ecosystem the same choice is made by AAMVA's Digital Trust
  Service or the EU trust list, after vetting that the applicant really is a
  driver-licensing authority. Those govern whether *third parties* accept our
  issuers, and are not ours to make. This table governs whether *we* do, which
  is what lets a pilot work end to end before any external body has looked at
  it. A future source that syncs an external list would add rows here.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "mdl_issuing_authorities" do
    field :certificate, :string

    # Denormalised from the certificate. The subject fields are read on every
    # document signer registered under this root, and a country column is what
    # makes "which authorities do we trust for Spain" a query rather than a
    # scan-and-parse.
    field :subject_country, :string
    field :subject_state, :string
    field :subject_common_name, :string
    field :not_before, :utc_datetime
    field :not_after, :utc_datetime

    # SHA-256 of the DER, so re-uploading a root is recognised as the same
    # anchor rather than creating a second one that would survive revoking the
    # first.
    field :fingerprint, :binary

    field :admitted_at, :utc_datetime

    belongs_to :admitted_by_user, Sovra.Accounts.User
    has_many :workspaces, Sovra.Workspaces.Workspace, foreign_key: :mdl_issuing_authority_id

    timestamps(type: :utc_datetime)
  end

  @required ~w(certificate subject_country subject_common_name not_before not_after fingerprint admitted_at)a
  @optional ~w(subject_state admitted_by_user_id)a

  def admit_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> validate_format(:subject_country, ~r/^[A-Z]{2}$/,
      message: "must be an ISO 3166-1 alpha-2 country code"
    )
    |> unique_constraint(:fingerprint,
      message: "this root is already admitted"
    )
  end
end
