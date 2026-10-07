defmodule Sovra.Ethereum.ChainError do
  @moduledoc """
  Why a chain write failed, as one bounded line, for storing on the row it
  failed for (`registration_error`, `status_change_error`). The full reason is
  in the logs; this is what a dashboard or an API caller reads.
  """

  use Sovra.Log

  @max_length 200

  @spec message(term()) :: String.t()
  def message(%{"message" => message}) when is_binary(message), do: truncate(message)
  def message(reason) when is_binary(reason), do: truncate(reason)
  def message(reason), do: reason |> Log.reason() |> to_string() |> truncate()

  defp truncate(string) do
    string
    |> String.replace(~r/\s+/, " ")
    |> String.slice(0, @max_length)
  end
end
