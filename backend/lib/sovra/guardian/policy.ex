defmodule Sovra.Guardian.Policy do
  @moduledoc """
  Policy enforcement for guardian signing requests.
  Evaluates whether a signing request should be approved.
  """

  @doc """
  Evaluates whether a signing request meets policy requirements.
  """
  def evaluate(_request) do
    {:error, :not_implemented}
  end
end
