defmodule Sovra.Crypto.SoftwareKeyStore do
  @moduledoc """
  In-memory P256 key store for development. Keys are stored in ETS.
  Not for production — use HSM/KMS-backed implementation instead.
  """

  use GenServer

  @behaviour Sovra.Crypto.KeyStore

  @table :sovra_software_key_store

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl Sovra.Crypto.KeyStore
  def generate_key(holder_id) do
    GenServer.call(__MODULE__, {:generate_key, holder_id})
  end

  @impl Sovra.Crypto.KeyStore
  def sign(key_id, hash) do
    case :ets.lookup(@table, key_id) do
      [{^key_id, private_key}] -> Sovra.Crypto.P256.sign(hash, private_key)
      [] -> {:error, :key_not_found}
    end
  end

  @impl Sovra.Crypto.KeyStore
  def delete_key(key_id) do
    GenServer.call(__MODULE__, {:delete_key, key_id})
  end

  # Server callbacks

  @impl GenServer
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :set, :protected, read_concurrency: true])
    {:ok, %{table: table}}
  end

  @impl GenServer
  def handle_call({:generate_key, _holder_id}, _from, state) do
    case Sovra.Crypto.P256.generate_key_pair() do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} ->
        key_id = generate_key_id()
        :ets.insert(@table, {key_id, priv})
        {:reply, {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}}, state}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:delete_key, key_id}, _from, state) do
    :ets.delete(@table, key_id)
    {:reply, :ok, state}
  end

  defp generate_key_id do
    <<u0::48, _::4, u1::12, _::2, u2::62>> = :crypto.strong_rand_bytes(16)

    <<u0::48, 4::4, u1::12, 2::2, u2::62>>
    |> Base.encode16(case: :lower)
    |> then(fn hex ->
      <<a::binary-size(8), b::binary-size(4), c::binary-size(4), d::binary-size(4),
        e::binary-size(12)>> = hex

      "#{a}-#{b}-#{c}-#{d}-#{e}"
    end)
  end
end
