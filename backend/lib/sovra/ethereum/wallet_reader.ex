defmodule Sovra.Ethereum.WalletReader do
  @moduledoc """
  Reads wallet contract state and computes EIP-712 hashes for recovery operations.
  This allows the server to construct the exact message hash that the contract expects,
  rather than blindly signing client-supplied hashes.
  """

  alias Sovra.Ethereum.Client

  # EIP-712 constants matching SovraWalletV1.sol
  @domain_typehash ExKeccak.hash_256(
                     "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                   )
  @name_hash ExKeccak.hash_256("SovraWallet")
  @version_hash ExKeccak.hash_256("1")

  @doc "Read the current nonce from a wallet contract."
  @spec read_nonce(String.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def read_nonce(wallet_address) do
    # nonce() selector = keccak256("nonce()")[0:4] = 0xaffed0e0
    selector = ExKeccak.hash_256("nonce()") |> binary_part(0, 4)

    case Client.call(%{data: selector}, to: wallet_address) do
      {:ok, "0x" <> hex} ->
        {nonce, _} = Integer.parse(hex, 16)
        {:ok, nonce}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Read the holder's current passkey (P-256 public key) from a wallet
  contract. The passkey is the live signing key that gets updated by the
  recovery flow, so the returned value reflects the *current* authorized
  key — not whatever was set at issuance time.

  Returns `{:error, :uninitialized_passkey}` when both coordinates are
  zero (wallet not yet initialized) so callers can fail closed without
  treating an unset wallet as a valid identity.
  """
  @spec read_passkey(String.t()) :: {:ok, {binary, binary}} | {:error, term()}
  def read_passkey(wallet_address) do
    with {:ok, x} <- read_bytes32(wallet_address, "passkeyX()"),
         {:ok, y} <- read_bytes32(wallet_address, "passkeyY()") do
      if x == <<0::256>> and y == <<0::256>> do
        {:error, :uninitialized_passkey}
      else
        {:ok, {x, y}}
      end
    end
  end

  @doc """
  Returns true if the wallet's DID has been deactivated (a permanent,
  one-way action set via `deactivate()` on the contract).
  """
  @spec did_deactivated?(String.t()) :: {:ok, boolean()} | {:error, term()}
  def did_deactivated?(wallet_address) do
    case read_bytes32(wallet_address, "didDeactivated()") do
      {:ok, <<0::256>>} -> {:ok, false}
      {:ok, _} -> {:ok, true}
      {:error, _} = err -> err
    end
  end

  defp read_bytes32(wallet_address, signature) do
    selector = ExKeccak.hash_256(signature) |> binary_part(0, 4)

    case Client.call(%{data: selector}, to: wallet_address) do
      {:ok, "0x" <> hex} ->
        case Base.decode16(hex, case: :mixed) do
          {:ok, <<bytes::binary-32>>} -> {:ok, bytes}
          _ -> {:error, :malformed_response}
        end

      {:error, _} = err ->
        err
    end
  end

  @doc "Compute the EIP-712 domain separator for a wallet."
  @spec domain_separator(String.t(), non_neg_integer()) :: binary()
  def domain_separator(wallet_address, chain_id) do
    address_bytes = decode_address(wallet_address)

    ExKeccak.hash_256(
      ABI.TypeEncoder.encode(
        [@domain_typehash, @name_hash, @version_hash, chain_id, address_bytes],
        %ABI.FunctionSelector{
          types: [{:bytes, 32}, {:bytes, 32}, {:bytes, 32}, {:uint, 256}, :address]
        }
      )
    )
  end

  @doc "Build the full EIP-712 message hash for initiateRecovery."
  @spec build_initiate_recovery_hash(String.t(), binary(), binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, term()}
  def build_initiate_recovery_hash(wallet_address, new_key_x, new_key_y, key_to_replace)
      when key_to_replace in [0, 1] do
    config = Application.get_env(:sovra, :ethereum, [])
    chain_id = get_chain_id(config)

    with {:ok, nonce} <- read_nonce(wallet_address) do
      op_selector = ExKeccak.hash_256("initiateRecovery") |> binary_part(0, 4)

      op_hash =
        ExKeccak.hash_256(
          ABI.TypeEncoder.encode(
            [op_selector, new_key_x, new_key_y, key_to_replace],
            %ABI.FunctionSelector{types: [{:bytes, 4}, {:bytes, 32}, {:bytes, 32}, {:uint, 8}]}
          )
        )

      dom_sep = domain_separator(wallet_address, chain_id)

      struct_hash =
        ExKeccak.hash_256(
          ABI.TypeEncoder.encode(
            [op_hash, nonce],
            %ABI.FunctionSelector{types: [{:bytes, 32}, {:uint, 256}]}
          )
        )

      msg_hash = ExKeccak.hash_256(<<0x19, 0x01>> <> dom_sep <> struct_hash)
      {:ok, msg_hash}
    end
  end

  @doc "Build the full EIP-712 message hash for finalizeRecovery."
  @spec build_finalize_recovery_hash(String.t()) :: {:ok, binary()} | {:error, term()}
  def build_finalize_recovery_hash(wallet_address) do
    config = Application.get_env(:sovra, :ethereum, [])
    chain_id = get_chain_id(config)

    with {:ok, nonce} <- read_nonce(wallet_address) do
      op_hash =
        ExKeccak.hash_256(
          ABI.TypeEncoder.encode(
            [ExKeccak.hash_256("finalizeRecovery") |> binary_part(0, 4)],
            %ABI.FunctionSelector{types: [{:bytes, 4}]}
          )
        )

      dom_sep = domain_separator(wallet_address, chain_id)

      struct_hash =
        ExKeccak.hash_256(
          ABI.TypeEncoder.encode(
            [op_hash, nonce],
            %ABI.FunctionSelector{types: [{:bytes, 32}, {:uint, 256}]}
          )
        )

      msg_hash = ExKeccak.hash_256(<<0x19, 0x01>> <> dom_sep <> struct_hash)
      {:ok, msg_hash}
    end
  end

  defp decode_address("0x" <> hex) do
    {:ok, bytes} = Base.decode16(hex, case: :mixed)
    bytes
  end

  defp get_chain_id(config) do
    Keyword.get(config, :chain_id, 65_536_999)
  end
end
