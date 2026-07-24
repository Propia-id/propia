defmodule Sovra.Signer.Relayer do
  @moduledoc """
  Signer-service relayer signing. Signs a 32-byte Ethereum digest with the
  secp256k1 relayer key held in AWS KMS and returns `{r, s, recovery_id}`
  (low-s normalized, Ethereum recovery id) for `Ethers` transaction assembly,
  plus the relayer's address.

  The relayer key id is signer-side config (`RELAYER_KMS_KEY_ID`) — API nodes
  never see it; they call `/v1/relayer/*` on the signer over Tailscale. The
  immutable public key is cached after the first `GetPublicKey`.
  """

  alias Sovra.Crypto.Secp256k1
  alias Sovra.Crypto.Spki

  @spec sign(<<_::256>>) ::
          {:ok, %{r: binary(), s: binary(), recovery_id: 0 | 1}} | {:error, term()}
  def sign(<<digest::binary-size(32)>>) do
    with {:ok, key_id} <- key_id(),
         {:ok, der} <- backend().sign(key_id, digest),
         {:ok, {r, s}} <- Secp256k1.parse_der(der),
         {:ok, pub} <- public_key(key_id),
         {:ok, v} <- Secp256k1.recovery_id(digest, r, s, pub) do
      {:ok, %{r: r, s: s, recovery_id: v}}
    end
  end

  def sign(_), do: {:error, :invalid_hash_size}

  @spec address() :: {:ok, String.t()} | {:error, term()}
  def address do
    with {:ok, key_id} <- key_id(),
         {:ok, pub} <- public_key(key_id) do
      {:ok, Secp256k1.address(pub)}
    end
  end

  # --- internals -------------------------------------------------------------

  defp public_key(key_id) do
    case :persistent_term.get({__MODULE__, key_id}, nil) do
      nil ->
        with {:ok, der} <- backend().get_public_key(key_id),
             {:ok, pub} <- Spki.uncompressed_point(der) do
          :persistent_term.put({__MODULE__, key_id}, pub)
          {:ok, pub}
        end

      pub ->
        {:ok, pub}
    end
  end

  defp key_id do
    case Application.get_env(:sovra, :signer_service, [])[:relayer_kms_key_id] do
      id when is_binary(id) and id != "" -> {:ok, id}
      _ -> {:error, :relayer_key_not_configured}
    end
  end

  defp backend, do: Application.get_env(:sovra, :kms_backend, Sovra.AWS.KMS)
end
