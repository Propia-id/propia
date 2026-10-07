defmodule Sovra.Ethereum.ClientSendTest do
  # async: false — mutates the global :ethereum config and the JSON-RPC stub env.
  use Sovra.DataCase, async: false

  alias Sovra.Ethereum.{Client, JsonRpcStubPlug}
  alias Sovra.Ethereum.Contracts.RevocationRegistryContract

  # Its own port: see Sovra.Ethereum.SignatureRegistryTest.
  @port 4603
  @registry "0x00000000000000000000000000000000000000aa"
  @issuer "0x00000000000000000000000000000000000000bb"

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
        receipt_poll_attempts: 0
      )
    )

    Application.put_env(:sovra, :stub_json_rpc, %{
      "test_pid" => self(),
      "eth_chainId" => "0x1",
      "eth_estimateGas" => "0x5208",
      "eth_gasPrice" => "0x1",
      "eth_maxPriorityFeePerGas" => "0x1",
      # Seven already mined, two more submitted and still pending.
      "eth_getTransactionCount" => "0x9",
      "eth_sendRawTransaction" => "0x" <> String.duplicate("ab", 32),
      "eth_getTransactionReceipt" => %{"status" => "0x1", "blockNumber" => "0x10"}
    })

    on_exit(fn ->
      Application.put_env(:sovra, :ethereum, original)
      Application.delete_env(:sovra, :stub_json_rpc)
    end)

    :ok
  end

  test "signs with the pending nonce, so in-flight transactions are not reused" do
    tx_hash = "0x" <> String.duplicate("ab", 32)

    assert {:ok, ^tx_hash} =
             RevocationRegistryContract.set_status(@issuer, 0, 1)
             |> Client.send_transaction(to: @registry, op: :credential_revoke)

    assert_received {:json_rpc, "eth_getTransactionCount", [_relayer, "pending"]}
    refute_received {:json_rpc, "eth_getTransactionCount", [_relayer, "latest"]}

    assert_received {:json_rpc, "eth_sendRawTransaction", [raw]}
    assert {:ok, %{payload: %{nonce: 9}}} = Ethers.Transaction.decode(raw)
  end

  # The registries treat "already done" reverts as success by finding the
  # custom error's selector in the failure. That only works if the node's error
  # reaches them intact, through gas estimation and the submit lock.
  test "a revert at gas estimation comes back with its selector, and nothing is sent" do
    selector = Sovra.Ethereum.Revert.selector("AlreadyRegistered()")

    Application.put_env(
      :sovra,
      :stub_json_rpc,
      Map.put(
        Application.get_env(:sovra, :stub_json_rpc),
        "eth_estimateGas",
        {:error, %{code: 3, message: "execution reverted", data: selector}}
      )
    )

    assert {:error, reason} =
             RevocationRegistryContract.set_status(@issuer, 0, 1)
             |> Client.send_transaction(to: @registry, op: :credential_revoke)

    assert Sovra.Ethereum.Revert.matches?(reason, selector)
    refute_received {:json_rpc, "eth_sendRawTransaction", _}
  end
end
