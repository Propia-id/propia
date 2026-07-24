defmodule Sovra.Crypto.DatabaseKeyStore do
  @moduledoc """
  P256 key store backed by PostgreSQL. Keys are stored as plaintext.
  For development only — production uses `Sovra.Crypto.KmsKeyStore`
  (AWS KMS via the signer service).
  """

  @behaviour Sovra.Crypto.KeyStore

  alias Sovra.Crypto.{P256, StoredKey}
  alias Sovra.Repo

  @impl Sovra.Crypto.KeyStore
  def generate_key(_holder_id) do
    case P256.generate_key_pair() do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} ->
        key_id = generate_key_id()

        case %StoredKey{}
             |> StoredKey.changeset(%{key_id: key_id, private_key: priv})
             |> Repo.insert() do
          {:ok, _} ->
            {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}}

          {:error, changeset} ->
            {:error, {:db_error, changeset}}
        end

      error ->
        error
    end
  end

  @impl Sovra.Crypto.KeyStore
  def sign(key_id, hash) do
    case Repo.get_by(StoredKey, key_id: key_id) do
      nil -> {:error, :key_not_found}
      %StoredKey{private_key: private_key} -> P256.sign(hash, private_key)
    end
  end

  @impl Sovra.Crypto.KeyStore
  def delete_key(key_id) do
    case Repo.get_by(StoredKey, key_id: key_id) do
      nil ->
        :ok

      stored ->
        case Repo.delete(stored) do
          {:ok, _} -> :ok
          {:error, changeset} -> {:error, {:db_error, changeset}}
        end
    end
  end

  defp generate_key_id do
    <<u0::48, _::4, u1::12, _::2, u2::62>> = :crypto.strong_rand_bytes(16)

    <<u0::48, 4::4, u1::12, 2::2, u2::62>>
    |> Base.encode16(case: :lower)
    |> then(fn hex ->
      <<a::binary-size(8), b::binary-size(4), c::binary-size(4), d::binary-size(4),
        e::binary-size(12)>> = hex

      "#{a}-#{b}-#{c}-#{d}-#{e}"
    end)
  end
end
