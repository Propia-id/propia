defmodule Sovra.Relay.SessionStore do
  @moduledoc """
  In-memory session store for the OpenID4VP relay.

  Sessions are stored in an ETS table and auto-expire after 5 minutes.
  A periodic cleanup sweep runs every 60 seconds.
  """

  use GenServer

  @table :relay_sessions
  @ttl_seconds 300
  @cleanup_interval_ms 60_000

  # --- Public API ---

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc "Create a new session. Returns the session ID."
  def create do
    id = Ecto.UUID.generate()
    now = System.system_time(:second)
    :ets.insert(@table, {id, nil, nil, now})
    id
  end

  @doc "Store the request object for a session. Returns :ok or :not_found."
  def put_request(id, request) do
    case :ets.lookup(@table, id) do
      [{^id, _req, resp, created_at}] ->
        :ets.insert(@table, {id, request, resp, created_at})
        :ok

      [] ->
        :not_found
    end
  end

  @doc "Get the request object for a session."
  def get_request(id) do
    case :ets.lookup(@table, id) do
      [{^id, request, _resp, _created_at}] -> {:ok, request}
      [] -> :not_found
    end
  end

  @doc "Store the VP response for a session. Returns :ok or :not_found."
  def put_response(id, response) do
    case :ets.lookup(@table, id) do
      [{^id, req, _resp, created_at}] ->
        :ets.insert(@table, {id, req, response, created_at})
        :ok

      [] ->
        :not_found
    end
  end

  @doc "Get the VP response for a session."
  def get_response(id) do
    case :ets.lookup(@table, id) do
      [{^id, _req, response, _created_at}] -> {:ok, response}
      [] -> :not_found
    end
  end

  @doc "Delete a session."
  def delete(id) do
    :ets.delete(@table, id)
    :ok
  end

  # --- GenServer callbacks ---

  @impl true
  def init(_) do
    table = :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
    schedule_cleanup()
    {:ok, %{table: table}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cutoff = System.system_time(:second) - @ttl_seconds

    :ets.select_delete(@table, [
      {{:_, :_, :_, :"$1"}, [{:<, :"$1", cutoff}], [true]}
    ])

    schedule_cleanup()
    {:noreply, state}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end
end
