defmodule Sovra.Cosigner.Policy do
  @moduledoc """
  Policy enforcement for co-signing requests.
  Evaluates whether a co-signing request should be approved.
  """

  @doc """
  Evaluates whether a co-signing request meets policy requirements.
  """
  def evaluate(_request) do
    {:error, :not_implemented}
  end
end
