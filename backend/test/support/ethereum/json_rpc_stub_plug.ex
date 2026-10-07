defmodule Sovra.Ethereum.JsonRpcStubPlug do
  @moduledoc """
  Minimal JSON-RPC endpoint for tests. `ethereumex` calls through its own named
  Finch instance, so `Req.Test` cannot intercept it — the request has to hit a
  real socket.

  Canned results come from the `:sovra, :stub_json_rpc` app env map, keyed by
  method, for single requests and batches alike. A `{:error, map}` value is returned as a JSON-RPC error. Each received
  request is also forwarded to the test process as `{:json_rpc, method, params}`
  so calls can be asserted on.

      Application.put_env(:sovra, :stub_json_rpc, %{
        "eth_getBalance" => "0x1bc16d674ec80000",
        "test_pid" => self()
      })
  """

  use Plug.Router

  plug :match
  plug Plug.Parsers, parsers: [:json], pass: ["application/json"], json_decoder: Jason
  plug :dispatch

  post "/" do
    stubs = Application.get_env(:sovra, :stub_json_rpc, %{})

    # A batch arrives as a JSON array, which Plug.Parsers puts under "_json";
    # each request in it is answered as if it came alone.
    body =
      case conn.body_params do
        %{"_json" => requests} when is_list(requests) -> Enum.map(requests, &answer(&1, stubs))
        request -> answer(request, stubs)
      end

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, Jason.encode!(body))
  end

  defp answer(%{"method" => method, "id" => id} = request, stubs) do
    params = Map.get(request, "params", [])

    if pid = stubs["test_pid"], do: send(pid, {:json_rpc, method, params})

    case Map.fetch(stubs, method) do
      {:ok, {:error, error}} -> %{jsonrpc: "2.0", id: id, error: error}
      {:ok, result} -> %{jsonrpc: "2.0", id: id, result: result}
      :error -> %{jsonrpc: "2.0", id: id, error: %{code: -32_601, message: "not stubbed"}}
    end
  end

  match _ do
    send_resp(conn, 404, "")
  end
end
