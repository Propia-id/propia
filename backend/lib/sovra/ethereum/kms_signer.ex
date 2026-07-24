defmodule Sovra.Ethereum.KmsSigner do
  @moduledoc """
  `Ethers.Signer` backed by the KMS signer service. Mirrors `Ethers.Signer.Local`
  — same encode → keccak → `Signed` assembly — but the secp256k1 signature and
  the relayer address come from the signer service (`/v1/relayer/*`, which signs
  via AWS KMS). No key material or AWS credentials on this node.

  HTTP transport and config (`config :sovra, :signer`) live in
  `Sovra.Signer.Client`. The relayer address derives from the immutable KMS
  relayer key, so it is fetched once and cached in `:persistent_term` for the
  node's lifetime (mirroring the signer service's own pubkey cache in
  `Sovra.Signer.Relayer`).
  """

  @behaviour Ethers.Signer

  alias Ethers.Transaction
  alias Ethers.Transaction.Signed
  alias Ethers.Utils
  alias Sovra.Signer.Client

  @impl true
  def sign_transaction(transaction, _opts) do
    encoded = Transaction.encode(transaction)
    sign_hash = ExKeccak.hash_256(encoded)

    with {:ok, {r, s, recovery_id}} <- remote_sign(sign_hash) do
      signed = %Signed{
        payload: transaction,
        signature_r: r,
        signature_s: s,
        signature_y_parity_or_v: Signed.calculate_y_parity_or_v(transaction, recovery_id)
      }

      {:ok, Utils.hex_encode(Transaction.encode(signed))}
    end
  end

  @impl true
  def accounts(_opts) do
    case relayer_address() do
      {:ok, address} -> {:ok, [address]}
      {:error, _} = err -> err
    end
  end

  # --- internals -------------------------------------------------------------

  defp remote_sign(<<_::binary-size(32)>> = hash) do
    with {:ok, %{status: 200, body: %{"r" => r_hex, "s" => s_hex, "recovery_id" => v}}} <-
           Client.post("/v1/relayer/sign", %{digest: Base.encode16(hash, case: :lower)}),
         {:ok, r} <- Client.decode_hex(r_hex),
         {:ok, s} <- Client.decode_hex(s_hex),
         true <- v in [0, 1] do
      {:ok, {r, s, v}}
    else
      {:ok, %{status: status, body: body}} -> {:error, {:signer_error, status, body}}
      false -> {:error, :bad_recovery_id}
      {:error, _} = err -> err
    end
  end

  defp relayer_address do
    case :persistent_term.get({__MODULE__, :relayer_address}, nil) do
      nil ->
        with {:ok, address} <- fetch_relayer_address() do
          :persistent_term.put({__MODULE__, :relayer_address}, address)
          {:ok, address}
        end

      address ->
        {:ok, address}
    end
  end

  defp fetch_relayer_address do
    case Client.get("/v1/relayer/address") do
      {:ok, %{status: 200, body: %{"address" => address}}} -> {:ok, address}
      {:ok, resp} -> {:error, {:signer_error, resp.status, resp.body}}
      {:error, _} = err -> err
    end
  end
end
