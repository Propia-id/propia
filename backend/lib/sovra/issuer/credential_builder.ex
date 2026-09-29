defmodule Sovra.Issuer.CredentialBuilder do
  @moduledoc """
  Format-neutral facade over the two credential builders.

  Exists so `deliver_credential/3` does not have to know how either format is
  put together. Expiry is the clearest case: every path here defers to
  `ClaimUtils.resolve_expiry/2`, which honours an issuer's custom
  `:valid_until` over the schema's `validity_period`.

  The SD-JWT path once recovered expiry by splitting the finished credential,
  decoding its payload and reading `exp` back out; the fix for that left three
  independent derivations (here, in `SDJWT`, in `Mdoc`) which agreed only
  because one caller threaded the same `now:` into each, and which the offer
  preview did not share at all. One resolver plus a `now:` pinned on the way in
  makes disagreement impossible rather than merely avoided.
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
    opts = pin_now(opts)

    with {:ok, sd_jwt} <- SDJWT.build(workspace, schema, claims, holder_did, opts) do
      {:ok,
       %{
         credential: sd_jwt,
         format: "vc+sd-jwt",
         # The same instant handed to the signer, not a second derivation of
         # it: the row a verifier is checked against has to be the one `exp`
         # actually carries.
         expires_at: ClaimUtils.resolve_expiry(schema, opts),
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
    opts = pin_now(opts)

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
    do: Mdoc.build_preview(workspace, schema, claims, pin_now(opts))

  def preview(workspace, schema, claims, opts),
    do: SDJWT.build_preview(workspace, schema, claims, pin_now(opts))

  # Pins the issuance instant up front so every downstream derivation — the
  # signed `exp`, the `issued_credentials` row, the preview — measures a
  # relative validity period from the same second rather than each reading the
  # clock for itself.
  defp pin_now(opts) do
    Keyword.put_new_lazy(opts, :now, fn -> DateTime.utc_now() |> DateTime.truncate(:second) end)
  end
end
