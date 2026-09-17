defmodule Sovra.Issuer.OID4VCI do
  @moduledoc """
  OpenID for Verifiable Credential Issuance (OID4VCI) protocol helpers.
  Builds metadata and offer responses matching the wallet's expected formats.
  """

  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Mdoc.DocType
  alias Sovra.Repo

  # Every display string we publish is authored in one language today, so the
  # locale is fixed rather than plumbed through. Wallets resolve exact tag,
  # then language, then first entry.
  @locale "en-US"

  def build_metadata(workspace, schemas, designs \\ []) do
    base_url = ClaimUtils.base_url()
    workspace = Repo.preload(workspace, :organization)
    credential_issuer = "#{base_url}/#{workspace.did}"
    designs_by_schema_id = Map.new(designs, fn d -> {d.credential_schema_id, d} end)

    configs =
      Map.new(latest_per_schema_id(schemas), fn schema ->
        {schema.credential_type,
         config_for(schema, workspace, Map.get(designs_by_schema_id, schema.id))}
      end)

    %{
      "credential_issuer" => credential_issuer,
      "authorization_servers" => [credential_issuer],
      "credential_endpoint" => "#{base_url}/wallet/issuer/credential",
      "credential_configurations_supported" => configs,
      "display" => [display_entry(workspace)]
    }
  end

  # One configuration per schema either way, still keyed by `credential_type`.
  # Keeping that key is what lets `ensure_configuration_matches/2` and
  # `build_offer_uri/4` stay untouched — the docType identifies the wire format,
  # not the configuration.
  defp config_for(%{format: "mso_mdoc"} = schema, workspace, design) do
    doc_type = DocType.build(workspace, schema)

    %{
      "format" => "mso_mdoc",
      "doctype" => doc_type,
      # The holder proves possession with a plain OID4VCI `jwt` proof, exactly as
      # for SD-JWT; `cose_key` describes how the key is *carried* in the issued
      # credential (MSO.deviceKeyInfo), not how the proof is signed.
      "cryptographic_binding_methods_supported" => ["cose_key"],
      "credential_signing_alg_values_supported" => [-7],
      "proof_types_supported" => %{
        "jwt" => %{"proof_signing_alg_values_supported" => ["ES256"]}
      },
      "credential_metadata" =>
        credential_metadata(schema, workspace, design, mdoc_claims(schema, doc_type))
    }
  end

  defp config_for(schema, workspace, design) do
    %{
      "format" => "vc+sd-jwt",
      "credential_definition" => %{
        "type" => ["VerifiableCredential", schema.credential_type]
      },
      "credential_metadata" => credential_metadata(schema, workspace, design, claims_for(schema))
    }
  end

  # OpenID4VP 1.0 path form: `[namespace, element_identifier]`. The namespace is
  # the docType, since we emit exactly one.
  #
  # Only operator-defined claims appear here. The `io.sovra.meta.1` namespace an
  # issued mdoc also carries is Sovra plumbing — a wallet has nothing to render
  # for it and no reason to request it.
  defp mdoc_claims(schema, doc_type) do
    schema.claims
    |> ClaimUtils.parse_claim_defs()
    |> Enum.map(fn claim ->
      %{
        "path" => [doc_type, claim["key"]],
        # `disclosable: false` means the holder cannot withhold it, which is what
        # OID4VCI calls a mandatory claim.
        "mandatory" => not disclosable?(claim)
      }
    end)
    |> case do
      [] -> nil
      claims -> claims
    end
  end

  defp disclosable?(claim), do: !!(claim["disclosable"] || claim["sd"])

  defp latest_per_schema_id(schemas) do
    schemas
    |> Enum.group_by(& &1.schema_id)
    |> Enum.map(fn {_, versions} -> Enum.max_by(versions, &(&1.version || 1)) end)
  end

  defp display_entry(%{organization: %{name: name} = org}) when is_binary(name) do
    %{"name" => name}
    |> maybe_put("logo", logo_entry(org.logo_url))
    |> maybe_put("url", org.website)
  end

  defp display_entry(workspace), do: %{"name" => workspace.name}

  # OID4VCI 1.0 §12.2.4: a configuration's presentation data — the card face
  # (`display`) and the per-claim labels (`claims`) — is nested under
  # `credential_metadata`. Both sat at the top of the configuration object in
  # draft 13; wallets read the 1.0 position only.
  # `claims` comes from the caller because the two formats point at claims
  # differently: an mdoc element is addressed `[namespace, identifier]`, an
  # SD-JWT claim by its flat key.
  defp credential_metadata(schema, workspace, design, claims) do
    %{"display" => display_for(schema, workspace, design)}
    |> maybe_put("claims", claims)
  end

  # OID4VCI 1.0 Appendix B.2 — one claims description object per schema claim.
  # `path` is a claims path pointer; our claims are flat, so every pointer is a
  # single segment. Claims the issuer never labelled are still described (the
  # wallet wants `mandatory`), just without a `display` for the wallet to
  # override its own derived label with.
  defp claims_for(schema) do
    case schema.claims |> ClaimUtils.parse_claim_defs() |> Enum.flat_map(&claim_description/1) do
      [] -> nil
      descriptions -> descriptions
    end
  end

  defp claim_description(%{"key" => key} = claim) when is_binary(key) and key != "" do
    [
      %{"path" => [key]}
      |> maybe_put("mandatory", if(claim["required"] == true, do: true))
      |> maybe_put("display", claim_display(claim["label"]))
    ]
  end

  defp claim_description(_), do: []

  defp claim_display(label) when is_binary(label) do
    case String.trim(label) do
      "" -> nil
      trimmed -> [%{"name" => trimmed, "locale" => @locale}]
    end
  end

  defp claim_display(_), do: nil

  defp display_for(schema, workspace, nil) do
    [credential_display(schema, workspace)]
  end

  defp display_for(schema, _workspace, design) do
    title_text = mapping_text(design.display && design.display.title)

    [
      %{
        "name" => title_text || design.name || schema.name,
        "locale" => @locale,
        "description" => design.description,
        "logo" => image_ref(design.styles && design.styles.thumbnail),
        "background_color" => color(design.styles && design.styles.background),
        "text_color" => color(design.styles && design.styles.text),
        "background_image" => image_ref(design.styles && design.styles.hero)
      }
      |> drop_nil_values()
    ]
  end

  defp credential_display(schema, %{organization: %{} = org}) do
    %{"name" => schema.name}
    |> maybe_put("logo", logo_entry(org.logo_url))
    |> maybe_put("url", org.website)
  end

  defp credential_display(schema, _workspace), do: %{"name" => schema.name}

  defp mapping_text(nil), do: nil
  defp mapping_text(%{text: text}) when is_binary(text) and text != "", do: text
  defp mapping_text(%{fallback: fb}) when is_binary(fb) and fb != "", do: fb
  defp mapping_text(_), do: nil

  defp image_ref(nil), do: nil

  defp image_ref(%{uri: uri} = ref) when is_binary(uri) do
    %{"uri" => uri, "alt_text" => Map.get(ref, :alt)} |> drop_nil_values()
  end

  defp image_ref(_), do: nil

  defp color(nil), do: nil
  defp color(%{color: c}) when is_binary(c), do: c
  defp color(_), do: nil

  defp logo_entry(nil), do: nil
  defp logo_entry(""), do: nil
  defp logo_entry(uri) when is_binary(uri), do: %{"uri" => uri}

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp drop_nil_values(map) do
    Enum.reject(map, fn {_k, v} -> is_nil(v) end) |> Map.new()
  end
end
