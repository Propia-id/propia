defmodule Sovra.Credentials.SDJWT do
  @moduledoc """
  SD-JWT issuance and selective disclosure handling.
  """

  @doc """
  Issues an SD-JWT credential with the given claims and disclosures.
  """
  def issue(_claims, _disclosures, _signing_key) do
    {:error, :not_implemented}
  end

  @doc """
  Verifies an SD-JWT presentation.
  """
  def verify(_sd_jwt) do
    {:error, :not_implemented}
  end
end
