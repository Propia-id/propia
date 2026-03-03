defmodule Sovra.Cosigner do
  @moduledoc """
  Co-signing logic — KB-JWT co-signature, holder authentication, policy enforcement.
  """

  @doc """
  Co-signs a KB-JWT for the given holder after policy validation.
  """
  def cosign(_kb_jwt, _holder_did) do
    {:error, :not_implemented}
  end
end
