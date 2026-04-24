defmodule Sovra.Issuer.OID4VCI do
  @moduledoc """
  OpenID for Verifiable Credential Issuance (OID4VCI) protocol helpers.
  Builds metadata and offer responses matching the wallet's expected formats.
  """

  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Repo

  def build_metadata(workspace, schemas) do
    base_url = ClaimUtils.base_url()
    workspace = Repo.preload(workspace, :organization)

    configs =
      Map.new(schemas, fn schema ->
        {schema.credential_type,
         %{
           "format" => "vc+sd-jwt",
           "credential_definition" => %{
             "type" => ["VerifiableCredential", schema.credential_type]
           },
           "display" => [credential_display(schema, workspace)]
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

  defp credential_display(schema, %{organization: %{} = org}) do
    %{"name" => schema.name}
    |> maybe_put("logo", logo_entry(org.logo_url))
    |> maybe_put("url", org.website)
  end

  defp credential_display(schema, _workspace), do: %{"name" => schema.name}

  defp logo_entry(nil), do: nil
  defp logo_entry(""), do: nil
  defp logo_entry(uri) when is_binary(uri), do: %{"uri" => uri}

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
