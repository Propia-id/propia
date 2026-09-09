defmodule SovraWeb.HealthController do
  @moduledoc """
  Two probes with deliberately different jobs.

  `index/2` (`GET /health`) is **liveness**: it confirms this node's endpoint is
  accepting requests, and nothing else. The Cloudflare tunnel and the deploy
  gate point at it, so it must stay free of I/O and must never fail for a reason
  outside this node. It also carries the build identity from `Sovra.BuildInfo` —
  compile-time constants, so the no-I/O contract holds. The deploy asserts on it
  per node.

  `ready/2` (`GET /ready`) is **readiness**: it renders the snapshot
  `Sovra.Health` keeps in ETS — 200 only when every dependency is up, 503
  otherwise, including before the first poll lands. It performs no I/O of its
  own, so it cannot be used to hammer a dependency.

  Both routes are unauthenticated and externally reachable, so dependency detail
  stays inside the closed set of labels from `Sovra.Health.label/1` — never a
  raw reason, a URL, or a key id.
  """

  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.BuildInfo
  alias Sovra.Health

  tags(["Health"])

  # A module attribute rather than a helper: `operation/2` expands at compile
  # time, so it cannot call a function defined in this module.
  @ready_schema %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      status: %OpenApiSpex.Schema{
        type: :string,
        description: "ok | error | starting | unavailable",
        example: "ok"
      },
      checked_at: %OpenApiSpex.Schema{type: :string, nullable: true},
      checks: %OpenApiSpex.Schema{
        type: :object,
        description:
          "One entry per dependency (database, signer, signer_kms), plus `rpc` keyed " <>
            "by chain id. Errors carry a closed-set label, never a raw reason."
      }
    }
  }

  operation(:index,
    summary: "Liveness check",
    description:
      "Confirms the endpoint is accepting requests, and reports the commit this " <>
        "release was built from. Performs no I/O and never fails for a dependency.",
    responses: %{
      200 =>
        {"Liveness status", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             status: %OpenApiSpex.Schema{type: :string, example: "ok"},
             revision: %OpenApiSpex.Schema{type: :string, example: "30436195114f"},
             ref: %OpenApiSpex.Schema{type: :string, example: "main"},
             version: %OpenApiSpex.Schema{type: :string, example: "0.1.0"},
             built_at: %OpenApiSpex.Schema{type: :string, nullable: true}
           }
         }}
    }
  )

  def index(conn, _params), do: json(conn, Map.put(BuildInfo.all(), :status, "ok"))

  operation(:ready,
    summary: "Readiness check",
    description:
      "200 only when every dependency passed the last poll, 503 otherwise. Reads a " <>
        "cached snapshot, so a request never reaches a dependency.",
    responses: %{
      200 => {"Every dependency up", "application/json", @ready_schema},
      503 =>
        {"A dependency is down, or no cycle has completed", "application/json", @ready_schema}
    }
  )

  def ready(conn, _params) do
    body = payload(Health.snapshot())

    conn
    |> put_status(if body.status == "ok", do: :ok, else: :service_unavailable)
    |> json(body)
  end

  # The monitor is not running: disabled by config, or dead between restarts
  # (the ETS table dies with its owner). Not ready either way.
  defp payload(:unavailable), do: %{status: "unavailable", checked_at: nil, checks: %{}}

  defp payload(%{status: status, checked_at: checked_at, checks: checks}) do
    %{
      status: to_string(status),
      checked_at: checked_at && DateTime.to_iso8601(checked_at),
      checks: render_checks(checks)
    }
  end

  defp render_checks(checks) do
    Map.new(checks, fn
      {:rpc, by_chain} ->
        {:rpc, Map.new(by_chain, fn {chain_id, e} -> {to_string(chain_id), render_entry(e)} end)}

      {key, entry} ->
        {key, render_entry(entry)}
    end)
  end

  defp render_entry(entry) do
    Map.new(entry, fn
      {:status, value} -> {:status, to_string(value)}
      {:error, value} -> {:error, to_string(value)}
      pair -> pair
    end)
  end
end
