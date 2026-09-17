defmodule Sovra.Ethereum.ClientBalanceTest do
  # async: false — mutates the global :ethereum config and the JSON-RPC stub env.
  use ExUnit.Case, async: false

  alias Sovra.Ethereum.{Client, JsonRpcStubPlug}

  @port 4601
  @chain_id 999_701
  @other_chain_id 999_702
  @address <<0xAB::8, 0::152>>

  # One listener for the whole module, not one per test. Starting and stopping
  # it around every test raced with itself two ways: the next bind could land
  # before the last listener released the port (`:eaddrinuse`), and the HTTP
  # client's pooled keep-alive connection to the previous listener could be
  # checked out after that listener died (`TransportError{reason: :closed}`).
  # The stub is stateless — its answers come from the application env each test
  # sets below — so there is nothing to reset between tests.
  setup_all do
    start_supervised!({Bandit, plug: JsonRpcStubPlug, scheme: :http, port: @port})
    :ok
  end

  setup do
    original = Application.get_env(:sovra, :ethereum, [])

    Application.put_env(
      :sovra,
      :ethereum,
      Keyword.merge(original,
        chain_id: @chain_id,
        chain_name: "stub-chain",
        rpc_url: "http://127.0.0.1:#{@port}/"
      )
    )

    on_exit(fn ->
      Application.put_env(:sovra, :ethereum, original)
      Application.delete_env(:sovra, :stub_json_rpc)
    end)

    :ok
  end

  defp stub(result), do: stub_map(%{"eth_getBalance" => result})

  defp stub_map(map) do
    Application.put_env(:sovra, :stub_json_rpc, Map.put(map, "test_pid", self()))
  end

  defp put_rpc_url(url) do
    Application.put_env(
      :sovra,
      :ethereum,
      Keyword.put(Application.get_env(:sovra, :ethereum, []), :rpc_url, url)
    )
  end

  describe "get_balance/2" do
    test "decodes a balance and calls eth_getBalance at the latest block" do
      stub("0x1bc16d674ec80000")

      assert {:ok, 2_000_000_000_000_000_000} = Client.get_balance(@chain_id, @address)

      expected = "0x" <> Base.encode16(@address, case: :lower)
      assert_receive {:json_rpc, "eth_getBalance", [^expected, "latest"]}
    end

    test "a drained relayer decodes as zero" do
      stub("0x0")
      assert {:ok, 0} = Client.get_balance(@chain_id, @address)
    end

    test "an empty hex body decodes as zero" do
      stub("0x")
      assert {:ok, 0} = Client.get_balance(@chain_id, @address)
    end

    # The strict decoder is what keeps a drained key distinguishable from a
    # broken proxy response.
    for {label, value} <- [
          {"non-hex digits", "0xZZ"},
          {"partially hex digits", "0x1f2g"},
          {"a null result", nil},
          {"an unprefixed number", "12345"}
        ] do
      test "rejects #{label} rather than reading it as zero" do
        stub(unquote(Macro.escape(value)))
        assert {:error, :invalid_uint_response} = Client.get_balance(@chain_id, @address)
      end
    end

    test "surfaces a JSON-RPC error from the node" do
      stub_map(%{"eth_getBalance" => {:error, %{code: -32_000, message: "boom"}}})
      assert {:error, _} = Client.get_balance(@chain_id, @address)
    end

    test "reads the chain whether or not the registry contracts are configured" do
      stub("0x2a")

      original = Application.get_env(:sovra, :ethereum, [])
      Application.put_env(:sovra, :ethereum, Keyword.put(original, :did_registry_address, nil))
      on_exit(fn -> Application.put_env(:sovra, :ethereum, original) end)

      refute Client.configured?()
      assert {:ok, 42} = Client.get_balance(@chain_id, @address)
    end

    test "reports a chain configured without an RPC URL as unconfigured" do
      put_rpc_url(nil)
      assert {:error, :chain_rpc_not_configured} = Client.get_balance(@chain_id, @address)

      put_rpc_url("")
      assert {:error, :chain_rpc_not_configured} = Client.get_balance(@chain_id, @address)
    end

    test "reports a chain that is not the configured one as unknown" do
      assert {:error, :unknown_chain} = Client.get_balance(@other_chain_id, @address)
    end
  end
end
