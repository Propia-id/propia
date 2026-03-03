defmodule Sovra.Issuer.OID4VCI do
  @moduledoc """
  OpenID for Verifiable Credential Issuance (OID4VCI) protocol flows.
  Handles credential offers, authorization, token exchange, and credential issuance.
  """

  @doc """
  Creates a credential offer for the given credential type.
  """
  def create_offer(_credential_type, _issuer_did) do
    {:error, :not_implemented}
  end
end
