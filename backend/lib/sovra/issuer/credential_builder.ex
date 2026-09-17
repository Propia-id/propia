defmodule Sovra.Issuer.CredentialBuilder do
  @moduledoc """
  Format-neutral facade over the two credential builders.

  Exists so `deliver_credential/3` does not have to know how either format is
  put together. In particular it makes expiry format-neutral: both clauses
  derive `expires_at` from the schema's `validity_period`, where the SD-JWT
  path used to recover it by splitting the finished credential string, decoding
  its payload, and reading `exp` back out — a roundabout re-derivation of a
  value we already had, and one that would have needed a CBOR equivalent.
  """

  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Issuer.CredentialSchema
  alias Sovra.Issuer.Mdoc
  alias Sovra.Issuer.SDJWT

  @type issued :: %{
          credential: String.t(),
          format: String.t(),
          expires_at: DateTime.t() | nil,
          doc_type: String.t() | nil
        }

  @doc """
  Build a credential in whichever format the schema declares.

  `holder_key` is the `{x, y}` P-256 point from the holder's OID4VCI proof.
  SD-JWT ignores it — it binds through the `cnf` DID reference — but mdoc
  cannot be issued without it, because `MSO.deviceKeyInfo` carries the key
  itself rather than a pointer to it.
  """
  @spec build(
          Sovra.Workspaces.Workspace.t(),
          CredentialSchema.t(),
          map(),
          String.t(),
          {binary(), binary()} | nil,
          keyword()
        ) :: {:ok, issued()} | {:error, term()}
  def build(workspace, schema, claims, holder_did, holder_key, opts \\ [])

  def build(
        workspace,
        %CredentialSchema{format: "vc+sd-jwt"} = schema,
        claims,
        holder_did,
        _key,
        opts
      ) do
    with {:ok, sd_jwt} <- SDJWT.build(workspace, schema, claims, holder_did, opts) do
      {:ok,
       %{
         credential: sd_jwt,
         format: "vc+sd-jwt",
         expires_at: expires_at(schema, opts),
         doc_type: nil
       }}
    end
  end

  def build(
        workspace,
        %CredentialSchema{format: "mso_mdoc"} = schema,
        claims,
        holder_did,
        {_x, _y} = holder_key,
        opts
      ) do
    with {:ok, %{credential: credential, doc_type: doc_type, valid_until: valid_until}} <-
           Mdoc.build(workspace, schema, claims, holder_did, holder_key, opts) do
      {:ok,
       %{
         credential: credential,
         format: "mso_mdoc",
         # Straight from the signed MSO, not re-derived: the row a verifier is
         # checked against has to be the instant `validUntil` actually carries.
         expires_at: valid_until,
         doc_type: doc_type
       }}
    end
  end

  def build(_workspace, %CredentialSchema{format: "mso_mdoc"}, _claims, _did, nil, _opts) do
    {:error, :holder_key_required}
  end

  @doc "The unsigned preview shown at offer-creation time, in the schema's format."
  @spec preview(Sovra.Workspaces.Workspace.t(), CredentialSchema.t(), map(), keyword()) :: map()
  def preview(workspace, %CredentialSchema{format: "mso_mdoc"} = schema, claims, opts),
    do: Mdoc.build_preview(workspace, schema, claims, opts)

  def preview(workspace, schema, claims, opts),
    do: SDJWT.build_preview(workspace, schema, claims, opts)

  # SD-JWT only. nil when the schema declares no validity period: the JWT omits
  # `exp` and the IssuedCredential row records no expiry. mdoc cannot express
  # that — `ValidityInfo.validUntil` is mandatory — so it reports the instant it
  # signed instead of deriving one here.
  defp expires_at(schema, opts) do
    case ClaimUtils.parse_validity_period(schema.validity_period) do
      nil ->
        nil

      seconds ->
        now = Keyword.get(opts, :now) || DateTime.utc_now() |> DateTime.truncate(:second)
        DateTime.add(now, seconds, :second)
    end
  end
end
