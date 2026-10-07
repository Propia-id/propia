defmodule Sovra.Ethereum.SignatureRegistryTest do
  # async: false — mutates the global :ethereum config and the JSON-RPC stub env.
  use ExUnit.Case, async: false

  alias Sovra.Ethereum.{JsonRpcStubPlug, SignatureRegistry}

  # Not ClientBalanceTest's port: each module binds its own listener, and a
  # shared port could be bound before the other module's listener let it go.
  @port 4602
  @registry "0x00000000000000000000000000000000000000aa"
  @signer "0x00000000000000000000000000000000000000bb"
  @digest :crypto.hash(:sha256, "document")
  @event_topic "0x" <>
                 (ExKeccak.hash_256("SignatureRecorded(address,bytes32,uint64)")
                  |> Base.encode16(case: :lower))

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
        rpc_url: "http://127.0.0.1:#{@port}/",
        signature_registry_address: @registry
      )
    )

    on_exit(fn ->
      Application.put_env(:sovra, :ethereum, original)
      Application.delete_env(:sovra, :stub_json_rpc)
    end)

    :ok
  end

  defp stub_logs(logs) do
    Application.put_env(:sovra, :stub_json_rpc, %{"eth_getLogs" => logs, "test_pid" => self()})
  end

  defp word(hex_body), do: "0x" <> String.pad_leading(hex_body, 64, "0")

  describe "find_record/2" do
    test "returns the transaction and timestamp from the SignatureRecorded event" do
      recorded_at = ~U[2026-09-30 12:00:00Z]

      stub_logs([
        %{
          "address" => @registry,
          "blockHash" => word("01"),
          "blockNumber" => "0x10",
          "data" => word(Integer.to_string(DateTime.to_unix(recorded_at), 16)),
          "logIndex" => "0x0",
          "removed" => false,
          "topics" => [
            @event_topic,
            word(String.trim_leading(@signer, "0x")),
            "0x" <> Base.encode16(@digest, case: :lower)
          ],
          "transactionHash" => word("abc"),
          "transactionIndex" => "0x0"
        }
      ])

      assert {:ok, %{tx_hash: tx_hash, recorded_at: ^recorded_at}} =
               SignatureRegistry.find_record(@signer, @digest)

      assert tx_hash == word("abc")

      # Filtered to this registry, this signer and this digest, over the whole
      # chain: without fromBlock the node would only search the latest block.
      assert_received {:json_rpc, "eth_getLogs", [filter]}
      assert filter["address"] == @registry
      assert filter["fromBlock"] == "earliest"

      assert [@event_topic, signer_topic, digest_topic] = filter["topics"]
      assert signer_topic == word(String.trim_leading(@signer, "0x"))
      assert digest_topic == "0x" <> Base.encode16(@digest, case: :lower)
    end

    test "is :record_not_found when no event matches" do
      stub_logs([])

      assert {:error, :record_not_found} = SignatureRegistry.find_record(@signer, @digest)
    end
  end
end
