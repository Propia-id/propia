defmodule Sovra.Ethereum.KmsSignerTest do
  use ExUnit.Case, async: true

  alias Sovra.Ethereum.KmsSigner

  # The signer service is stubbed (config/test.exs points :sovra, :signer at a
  # Req.Test plug). The stub signs with a known key, so KmsSigner must produce
  # output byte-identical to Ethers.Signer.Local for that same key.
  @priv String.duplicate(<<0x11>>, 32)

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, Jason.encode!(body))
  end

  setup do
    Req.Test.stub(:sovra_signer, fn conn ->
      case conn.request_path do
        "/v1/relayer/address" ->
          {:ok, pub} = ExSecp256k1.create_public_key(@priv)
          json(conn, 200, %{address: Ethers.Utils.public_key_to_address(pub)})

        "/v1/relayer/sign" ->
          {:ok, body, _conn} = Plug.Conn.read_body(conn)
          %{"digest" => digest_hex} = Jason.decode!(body)
          digest = Base.decode16!(digest_hex, case: :mixed)
          {:ok, {r, s, recovery_id}} = ExSecp256k1.sign(digest, @priv)

          json(conn, 200, %{
            r: Base.encode16(r, case: :lower),
            s: Base.encode16(s, case: :lower),
            recovery_id: recovery_id
          })
      end
    end)

    :ok
  end

  test "accounts returns the same relayer address as the local signer" do
    assert KmsSigner.accounts([]) == Ethers.Signer.Local.accounts(private_key: @priv)
  end

  test "caches the relayer address: a second lookup works with the signer down" do
    assert {:ok, [address]} = KmsSigner.accounts([])

    Req.Test.stub(:sovra_signer, fn conn -> json(conn, 500, %{error: "down"}) end)

    assert {:ok, [^address]} = KmsSigner.accounts([])
  end

  test "sign_transaction is byte-identical to the local signer for the same key" do
    {:ok, tx} =
      Ethers.Transaction.Eip1559.new(%{
        chain_id: 84_532,
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 2_000_000_000,
        gas: 21_000,
        to: "0x0000000000000000000000000000000000000001",
        value: 0,
        input: "0x",
        access_list: []
      })

    assert Ethers.Signer.Local.sign_transaction(tx, private_key: @priv) ==
             KmsSigner.sign_transaction(tx, [])
  end
end
