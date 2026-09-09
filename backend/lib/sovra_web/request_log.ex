defmodule SovraWeb.RequestLog do
  @moduledoc """
  One `http.request` event per request, replacing Phoenix's two metadata-free
  prose lines (the endpoint passes them `log: false`).

  On `[:phoenix, :endpoint, :stop]`, which fires from `register_before_send/2`
  and so runs after the auth plugs, carrying the context they resolved.

  `route` is the router's pattern, and `method` and the requested path are in
  the message: ids in a path make it unfacetable, and the ceiling in
  `Sovra.Log` is per line. Never `conn.query_string`, which carries tokens.
  """
  use Sovra.Log

  require Logger

  @event [:phoenix, :endpoint, :stop]

  # Polled every few seconds by the tunnel and the deploy gate.
  @quiet_paths ~w(/health /ready)

  @doc "Attaches the handler. Idempotent."
  @spec attach() :: :ok
  def attach do
    case :telemetry.attach(__MODULE__, @event, &__MODULE__.handle_event/4, nil) do
      :ok -> :ok
      {:error, :already_exists} -> :ok
    end
  end

  # `:telemetry` detaches a handler that raises, for the life of the node.
  @doc false
  def handle_event(@event, measurements, metadata, _config) do
    log(measurements, metadata)
  rescue
    error -> Logger.error("Request log handler failed: #{inspect(error)}")
  end

  defp log(%{duration: duration}, %{conn: conn}) do
    if loggable?(conn) do
      Log.event(level(conn.status), "#{conn.method} #{conn.request_path}",
        event: "http.request",
        route: route(conn),
        status: conn.status,
        duration_ms: duration_ms(duration)
      )
    end
  end

  # No router when an endpoint plug halts ahead of it; `:error` when nothing
  # matched. One value either way, never the requested path.
  defp route(%{private: %{phoenix_router: router}} = conn) do
    case Phoenix.Router.route_info(router, conn.method, conn.path_info, conn.host) do
      %{route: route} -> route
      :error -> "unmatched"
    end
  end

  defp route(_conn), do: "unmatched"

  # Fractional, not truncated: most requests finish inside a millisecond.
  defp duration_ms(duration) do
    duration
    |> System.convert_time_unit(:native, :microsecond)
    |> Kernel./(1000)
    |> Float.round(3)
  end

  defp loggable?(%{request_path: path, status: status}),
    do: path not in @quiet_paths or not is_integer(status) or status >= 400

  defp level(status) when is_integer(status) and status >= 500, do: :error
  defp level(status) when is_integer(status) and status >= 400, do: :warning
  defp level(_status), do: :info
end
