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

    case call_raw(wallet_address, selector) do
      {:ok, raw} -> {:ok, :binary.decode_unsigned(raw)}
      {:error, _} = err -> err
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

  # AlignedAccount.KeyType enum: 0 = ECDSA, 1 = P256, 2 = WebAuthnP256.
  @webauthn_p256 2

  @doc """
  Read the holder's currently-authorized WebAuthn P-256 keys from an
  `AlignedAccount` contract (the Aligned-backed replacement for
  `read_passkey/1`).

  Enumerates the account's user keys (`getUserKeysCount` → `getKeyHashAt` →
  `getUserKeyByHash`) and keeps only `WebAuthnP256` keys whose `validAt`
  timelock has elapsed — so a pending guardian-recovery key that isn't yet
  signable on-chain is never returned as a valid identity. Returns the raw
  32-byte `{x, y}` coordinates of each.
  """
  @spec read_aligned_keys(String.t()) :: {:ok, [{binary, binary}]} | {:error, term()}
  def read_aligned_keys(wallet_address) do
    with {:ok, count} <- read_user_keys_count(wallet_address) do
      now = System.os_time(:second)

      keys =
        0..(count - 1)//1
        |> Enum.reduce([], fn i, acc ->
          with {:ok, key_hash} <- read_key_hash_at(wallet_address, i),
               {:ok, {@webauthn_p256, valid_at, {x, y}}} <-
                 read_user_key_by_hash(wallet_address, key_hash),
               true <- valid_at <= now do
            [{x, y} | acc]
          else
            _ -> acc
          end
        end)
        |> Enum.reverse()

      if keys == [], do: {:error, :no_active_keys}, else: {:ok, keys}
    end
  end

  @doc """
  Decode the ABI return of `AlignedAccount.getUserKeyByHash(bytes32)` — a
  `Key { uint8 keyType; uint48 validAt; bytes publicKey }` struct where
  `publicKey = abi.encode(bytes32 x, bytes32 y)` (64 bytes for P-256). Pure;
  exposed for testing.
  """
  @spec decode_aligned_key(binary) ::
          {:ok, {non_neg_integer, non_neg_integer, {binary, binary}}} | {:error, :malformed_key}
  def decode_aligned_key(raw) when is_binary(raw) do
    case raw do
      <<_offset::256, key_type::256, valid_at::256, _pk_off::256, 64::256, x::binary-32,
        y::binary-32, _::binary>> ->
        {:ok, {key_type, valid_at, {x, y}}}

      _ ->
        {:error, :malformed_key}
    end
  end

  defp read_user_keys_count(wallet_address) do
    case call_raw(wallet_address, selector("getUserKeysCount()")) do
      {:ok, raw} -> {:ok, :binary.decode_unsigned(raw)}
      {:error, _} = err -> err
    end
  end

  defp read_key_hash_at(wallet_address, index) do
    data = selector("getKeyHashAt(uint256)") <> <<index::256>>

    case call_raw(wallet_address, data) do
      {:ok, <<key_hash::binary-32>>} -> {:ok, key_hash}
      {:ok, _} -> {:error, :malformed_response}
      {:error, _} = err -> err
    end
  end

  defp read_user_key_by_hash(wallet_address, <<key_hash::binary-32>>) do
    data = selector("getUserKeyByHash(bytes32)") <> key_hash

    case call_raw(wallet_address, data) do
      {:ok, raw} -> decode_aligned_key(raw)
      {:error, _} = err -> err
    end
  end

  defp selector(signature), do: ExKeccak.hash_256(signature) |> binary_part(0, 4)

  defp read_bytes32(wallet_address, signature) do
    case call_raw(wallet_address, selector(signature)) do
      {:ok, <<bytes::binary-32>>} -> {:ok, bytes}
      {:ok, _} -> {:error, :malformed_response}
      {:error, _} = err -> err
    end
  end

  @doc """
  Decode an `eth_call` result body. Pure; exposed for testing.

  An `eth_call` naming a function the account does not implement does not
  revert — it returns empty, which some nodes report as "0x" and others as a
  bare null. That is what a holder DID pointed at the wrong kind of account
  looks like (an EIP-7702 AlignedAccount read with the legacy SovraWalletV1
  selectors, say), and the caller records `holder_did_unresolvable` for it.
  """
  @spec decode_call_body(term) :: {:ok, binary} | {:error, atom}
  def decode_call_body("0x" <> hex) do
    case Base.decode16(hex, case: :mixed) do
      # Zero bytes is not a value. `read_nonce` read it as nonce 0 and signed
      # an EIP-712 hash over it.
      {:ok, ""} -> {:error, :empty_response}
      {:ok, raw} -> {:ok, raw}
      :error -> {:error, :malformed_response}
    end
  end

  def decode_call_body(_), do: {:error, :malformed_response}

  # Every read goes through this, so an undecodable call is an error the caller
  # can record rather than a crash inside the request.
  defp call_raw(wallet_address, data) do
    case Client.call(%{data: data}, to: wallet_address) do
      {:ok, body} -> decode_call_body(body)
      {:error, _} = err -> err
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
