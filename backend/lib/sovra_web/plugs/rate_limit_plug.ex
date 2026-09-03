defmodule SovraWeb.Plugs.RateLimitPlug do
  @moduledoc """
  Per-IP rate limiting plug using Hammer.
  """

  use Sovra.Log

  import Plug.Conn

  @behaviour Plug

  @impl true
  def init(opts) do
    %{
      max_requests: Keyword.get(opts, :max_requests, 10),
      window_ms: Keyword.get(opts, :window_ms, 60_000)
    }
  end

  @impl true
  def call(conn, %{max_requests: max, window_ms: window}) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    bucket = "rate_limit:#{conn.request_path}:#{ip}"

    case Hammer.check_rate(bucket, window, max) do
      {:allow, _count} ->
        conn

      {:deny, _limit} ->
        # The raw address stays out of New Relic (it lives in the Cloudflare and
        # HAProxy logs, which is where a block would be applied anyway); the
        # fingerprint is enough to see one caller hitting many paths.
        Log.event(:warning, "rate limit denied",
          event: "auth.rate_limit.denied",
          path: conn.request_path,
          ip: ip,
          max_requests: max,
          window_ms: window
        )

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(429, Jason.encode!(%{error: "too_many_requests"}))
        |> halt()
    end
  end
end
