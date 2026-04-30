defmodule Sovra.Issuer.OID4VCI do
  @moduledoc """
  OpenID for Verifiable Credential Issuance (OID4VCI) protocol helpers.
  Builds metadata and offer responses matching the wallet's expected formats.
  """

  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Repo

  def build_metadata(workspace, schemas, designs \\ []) do
    base_url = ClaimUtils.base_url()
    workspace = Repo.preload(workspace, :organization)
    designs_by_schema_id = Map.new(designs, fn d -> {d.credential_schema_id, d} end)

    configs =
      Map.new(schemas, fn schema ->
        {schema.credential_type,
         %{
           "format" => "vc+sd-jwt",
           "credential_definition" => %{
             "type" => ["VerifiableCredential", schema.credential_type]
           },
           "display" => display_for(schema, workspace, Map.get(designs_by_schema_id, schema.id))
         }}
      end)

    %{
      "credential_issuer" => base_url,
      "credential_endpoint" => "#{base_url}/api/v1/issuer/credential",
      "token_endpoint" => "#{base_url}/api/v1/issuer/token",
      "credential_configurations_supported" => configs,
      "display" => [display_entry(workspace)]
    }
  end

  defp display_entry(%{organization: %{name: name} = org}) when is_binary(name) do
    %{"name" => name}
    |> maybe_put("logo", logo_entry(org.logo_url))
    |> maybe_put("url", org.website)
  end

  defp display_entry(workspace), do: %{"name" => workspace.name}

  defp display_for(schema, workspace, nil) do
    [credential_display(schema, workspace)]
  end

  defp display_for(schema, _workspace, design) do
    title_text = mapping_text(design.display && design.display.title)

    [
      %{
        "name" => title_text || design.name || schema.name,
        "locale" => "en-US",
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
