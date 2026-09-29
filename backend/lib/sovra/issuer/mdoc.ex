defmodule Sovra.Issuer.Mdoc do
  @moduledoc """
  Builds ISO/IEC 18013-5 `IssuerSigned` credentials — the mdoc sibling of
  `Sovra.Issuer.SDJWT`.

  Same shape as the SD-JWT builder, and the same signing seam: the MSO is a
  `COSE_Sign1` produced through `Sovra.Crypto.Key.sign/2`, so an mdoc issued in
  production is signed by KMS exactly like an SD-JWT, with no key material on
  the API node.

  ## What OID4VCI delivers

  The credential response carries `IssuerSigned` (namespaces plus `issuerAuth`),
  not a full `DeviceResponse` — the holder has nothing to sign yet, because
  device authentication is bound to a verifier's session and does not exist at
  issuance time.

  ## The digest detail that is easy to get wrong

  `valueDigests` are taken over `#6.24(bstr .cbor IssuerSignedItem)` — the
  encoded tag-24 wrapper — not over the bare item map. Getting this wrong
  produces a credential that looks right and fails every verification.

  Issuance hashes the wrapper it just built and puts that same value on the
  wire, both through this module's deterministic encoder, so the digest and the
  wire form cannot drift. Verification rebuilds the wrapper around the payload
  it received and lands on the same bytes, because 18013-5 permits only
  shortest-form heads — see `Sovra.Cbor`.
  """

  alias Sovra.Cbor
  alias Sovra.Cose
  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Issuer.MdocElement
  alias Sovra.Mdoc.DocType
  alias Sovra.Mdoc.IssuerTrust
  alias Sovra.Mdoc.MetaNamespace

  @mso_version "1.0"
  @digest_algorithm "SHA-256"

  # ISO 18013-5 makes `ValidityInfo.validUntil` mandatory, so an mdoc has no way
  # to say "never expires" — the one thing a schema with no `validity_period`
  # says. Rather than emit a malformed MSO, the mdoc path keeps the one-year
  # default that predates expiry being optional. Only SD-JWT can drop `exp`.
  @default_validity_seconds 365 * 86400

  @doc """
  Build a signed mdoc credential.

  `holder_key` is the `{x, y}` P-256 point from the holder's OID4VCI proof. An
  mdoc binds to the key itself rather than to a DID reference the way SD-JWT's
  `cnf` does, so it cannot be issued without one.

  Options:
    * `:status_list_index` — required; travels in the Sovra meta namespace
    * `:now` — issuance instant, defaulting to now
  """
  @spec build(
          Sovra.Workspaces.Workspace.t(),
          Sovra.Issuer.CredentialSchema.t(),
          map(),
          String.t(),
          {binary(), binary()},
          keyword()
        ) ::
          {:ok, %{credential: String.t(), doc_type: String.t(), valid_until: DateTime.t()}}
          | {:error, term()}
  def build(workspace, schema, claims, holder_did, {_x, _y} = holder_key, opts \\ []) do
    now = Keyword.get(opts, :now) || DateTime.utc_now() |> DateTime.truncate(:second)
    status_list_index = Keyword.fetch!(opts, :status_list_index)
    doc_type = DocType.build(workspace, schema)
    namespace = DocType.namespace(workspace, schema)

    with {:ok, doc_type} <- require_doc_type(doc_type),
         {:ok, namespace} <- require_doc_type(namespace),
         {:ok, claim_items} <- build_claim_items(schema, claims) do
      meta_items =
        holder_did
        |> MetaNamespace.build(
          status_list_index,
          %{namespace => mandatory_elements(schema, claim_items)},
          schema.credential_type,
          namespace,
          workspace.eoa_address
        )
        |> Map.to_list()

      # The data elements live in the namespace, which is the docType only for
      # a generated schema. ISO pairs `org.iso.18013.5.1.mDL` with
      # `org.iso.18013.5.1`, and conflating them puts every element somewhere
      # no conformant reader looks.
      namespaces = %{
        namespace => encode_items(claim_items),
        MetaNamespace.namespace() => encode_items(meta_items)
      }

      valid_until = valid_until(schema, now, opts)
      mso = build_mso(doc_type, namespaces, holder_key, schema, now, valid_until)

      case sign_mso(mso, workspace, doc_type) do
        {:ok, issuer_auth} ->
          issuer_signed = %{
            "nameSpaces" =>
              Map.new(namespaces, fn {ns, items} -> {ns, Enum.map(items, & &1.tagged)} end),
            "issuerAuth" => issuer_auth
          }

          {:ok,
           %{
             credential: Base.url_encode64(Cbor.encode(issuer_signed), padding: false),
             doc_type: doc_type,
             valid_until: valid_until
           }}

        {:error, _} = error ->
          error
      end
    end
  end

  @doc """
  The unsigned preview returned at offer-creation time.

  Deliberately plain JSON rather than CBOR: this is a rendering aid for the
  dashboard and Sovra Gov, shown to a citizen before the wallet has scanned
  anything. Handing every existing preview consumer a CBOR blob to decode would
  buy consistency nobody asked for.
  """
  @spec build_preview(
          Sovra.Workspaces.Workspace.t(),
          Sovra.Issuer.CredentialSchema.t(),
          map(),
          keyword()
        ) :: map()
  def build_preview(workspace, schema, claims, opts \\ []) do
    now = Keyword.get(opts, :now) || DateTime.utc_now() |> DateTime.truncate(:second)
    doc_type = DocType.build(workspace, schema)
    iat = DateTime.to_unix(now)

    %{
      "doc_type" => doc_type,
      "namespace" => DocType.namespace(workspace, schema),
      "iat" => iat,
      "exp" => DateTime.to_unix(valid_until(schema, now, opts))
    }
    |> Map.merge(ClaimUtils.take_declared_claims(schema, claims))
    |> maybe_add_status(workspace, opts)
  end

  # ── Items ───────────────────────────────────────────────

  defp build_claim_items(schema, claims) do
    schema.claims
    |> ClaimUtils.parse_claim_defs()
    |> Enum.reduce_while({:ok, []}, fn claim_def, {:ok, acc} ->
      case Map.fetch(claims, claim_def["key"]) do
        # A claim the schema declares but the issuer did not supply is simply
        # absent, exactly as in the SD-JWT path. `validate_required_claims/2`
        # has already rejected any *required* omission upstream.
        :error ->
          {:cont, {:ok, acc}}

        {:ok, value} ->
          case MdocElement.encode(claim_def, value) do
            {:ok, encoded} -> {:cont, {:ok, [{claim_def["key"], encoded} | acc]}}
            {:error, _} = error -> {:halt, error}
          end
      end
    end)
    |> case do
      {:ok, items} -> {:ok, Enum.reverse(items)}
      error -> error
    end
  end

  # Each item becomes `#6.24(bstr .cbor IssuerSignedItem)`. The encoded wrapper
  # is kept because both the digest and the wire form must use those exact
  # bytes.
  defp encode_items(items) do
    digest_ids = digest_ids(length(items))

    items
    |> Enum.zip(digest_ids)
    |> Enum.map(fn {{key, value}, digest_id} ->
      tagged =
        Cbor.embed(%{
          "digestID" => digest_id,
          "random" => Cbor.bstr(:crypto.strong_rand_bytes(16)),
          "elementIdentifier" => key,
          "elementValue" => value
        })

      %{
        digest_id: digest_id,
        element_identifier: key,
        tagged: tagged,
        digest: :crypto.hash(:sha256, Cbor.encode(tagged))
      }
    end)
  end

  # 18013-5 requires digestIDs to be unique within a namespace and to convey no
  # information, so they are random rather than sequential.
  defp digest_ids(count) do
    Stream.repeatedly(fn -> :crypto.strong_rand_bytes(4) |> :binary.decode_unsigned() end)
    |> Stream.uniq()
    |> Enum.take(count)
  end

  # ── MSO ─────────────────────────────────────────────────

  defp build_mso(doc_type, namespaces, {x, y}, _schema, now, valid_until) do
    %{
      "version" => @mso_version,
      "digestAlgorithm" => @digest_algorithm,
      "valueDigests" =>
        Map.new(namespaces, fn {ns, items} ->
          {ns, Map.new(items, fn item -> {item.digest_id, Cbor.bstr(item.digest)} end)}
        end),
      "deviceKeyInfo" => %{"deviceKey" => Cose.Key.p256(x, y)},
      "docType" => doc_type,
      "validityInfo" => %{
        "signed" => Cbor.tdate(now),
        "validFrom" => Cbor.tdate(now),
        "validUntil" => Cbor.tdate(valid_until)
      }
    }
  end

  # Defers to the resolver every issuance path shares, so a custom
  # `:valid_until` lands in `ValidityInfo` exactly as it lands in the SD-JWT's
  # `exp` and the `issued_credentials` row.
  #
  # The fallback is the mdoc-specific part: the resolver returns nil for a
  # schema that declares no validity period, which SD-JWT renders as "no `exp`"
  # and mdoc cannot render at all.
  defp valid_until(schema, now, opts) do
    ClaimUtils.resolve_expiry(schema, opts) ||
      DateTime.add(now, @default_validity_seconds, :second)
  end

  # Which key signs, and what travels beside the signature, are both decided by
  # the docType — see `Sovra.Mdoc.IssuerTrust`. A generated docType is signed by
  # the workspace's general key, an ISO one by the key its Document Signer
  # Certificate names, and that certificate rides along in `x5chain`. The
  # verifier reads the same signal, so neither side can choose alone.
  defp sign_mso(mso, workspace, doc_type) do
    with {:ok, key_id, unprotected} <- IssuerTrust.issuer_auth_material(workspace, doc_type) do
      Cose.Sign1.sign(
        key_id,
        %{1 => Cose.Sign1.alg_es256()},
        unprotected,
        Cbor.encode(Cbor.embed(mso))
      )
    end
  end

  # ── Helpers ─────────────────────────────────────────────

  # Derived from the items actually issued, not from the schema alone.
  #
  # A claim that is `disclosable: false` but not `required` may simply not have
  # been supplied — `build_claim_items/2` omits it, exactly as the SD-JWT path
  # does. Listing it as mandatory anyway would produce a credential that issues
  # cleanly and then fails every verification, because the verifier requires
  # each mandatory element to be present and this one does not exist.
  defp mandatory_elements(schema, claim_items) do
    issued = MapSet.new(claim_items, fn {key, _value} -> key end)

    schema.claims
    |> ClaimUtils.parse_claim_defs()
    |> Enum.reject(&(&1["disclosable"] || &1["sd"]))
    |> Enum.map(& &1["key"])
    |> Enum.filter(&MapSet.member?(issued, &1))
  end

  # A docType only comes back nil for an unprovisioned workspace, which
  # `create_credential_offer/3` already gates. Guarding anyway so the failure is
  # named rather than a match error deep inside CBOR encoding.
  defp require_doc_type(nil), do: {:error, :doc_type_unavailable}
  defp require_doc_type(doc_type), do: {:ok, doc_type}

  defp maybe_add_status(preview, workspace, opts) do
    case Keyword.get(opts, :status_list_index) do
      nil ->
        preview

      index ->
        Map.put(
          preview,
          "credentialStatus",
          ClaimUtils.credential_status_entries(workspace, index)
        )
    end
  end
end
