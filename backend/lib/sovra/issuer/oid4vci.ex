defmodule Sovra.Issuer.OID4VCI do
  @moduledoc """
  OpenID for Verifiable Credential Issuance (OID4VCI) protocol helpers.
  Builds metadata and offer responses matching the wallet's expected formats.
  """

  alias Sovra.Issuer.ClaimUtils

  def build_metadata(issuer, schemas) do
    base_url = ClaimUtils.base_url()

    configs =
      Map.new(schemas, fn schema ->
        {schema.credential_type,
         %{
           "format" => "vc+sd-jwt",
           "credential_definition" => %{
             "type" => ["VerifiableCredential", schema.credential_type]
           },
           "display" => [%{"name" => schema.name}]
         }}
      end)

    %{
      "credential_issuer" => base_url,
      "credential_endpoint" => "#{base_url}/api/v1/issuer/credential",
      "token_endpoint" => "#{base_url}/api/v1/issuer/token",
      "credential_configurations_supported" => configs,
      "display" => [%{"name" => issuer.name}]
    }
  end
end
