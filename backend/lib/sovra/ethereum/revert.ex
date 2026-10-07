defmodule Sovra.Ethereum.Revert do
  @moduledoc """
  Recognizes a contract's custom error in a failed write.

  A write that would revert fails at gas estimation, before any transaction
  exists, and the node answers with the custom error's 4-byte selector — in
  `data`, or folded into `message` by nodes that return no `data`. The selector
  is what tells "already in the end state this write wanted" apart from a real
  failure, and that is what lets a retried write converge instead of wedging.
  """

  @doc """
  The 4-byte selector of a custom error signature, e.g. `"AlreadyRegistered()"`,
  as a `0x`-prefixed lowercase hex string. Pure; call it at compile time.
  """
  @spec selector(String.t()) :: String.t()
  def selector(signature) when is_binary(signature) do
    "0x" <>
      (signature
       |> ExKeccak.hash_256()
       |> binary_part(0, 4)
       |> Base.encode16(case: :lower))
  end

  @doc "Whether the JSON-RPC error `reason` carries the revert `selector`."
  @spec matches?(term(), String.t()) :: boolean()
  def matches?(reason, selector) when is_map(reason) do
    [Map.get(reason, "data"), Map.get(reason, "message")]
    |> Enum.filter(&is_binary/1)
    |> Enum.any?(&String.contains?(&1, selector))
  end

  def matches?(reason, selector) when is_binary(reason), do: String.contains?(reason, selector)

  def matches?(_reason, _selector), do: false
end
