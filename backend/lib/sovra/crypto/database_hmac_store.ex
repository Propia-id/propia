defmodule Sovra.Crypto.DatabaseHmacStore do
  @moduledoc """
  Development/test HMAC store that keeps the plaintext in the existing
  `stored_keys` table. Signing happens locally with `:crypto.mac/3`.

  Not for production use. Production should configure `VaultHmacStore`.
  """

  @behaviour Sovra.Crypto.HmacKeyStore

  alias Sovra.Crypto.StoredKey
  alias Sovra.Repo

  @impl true
  def generate_hmac_key do
    plaintext = random_plaintext()
    key_id = "webhook-" <> (:crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower))

    changeset =
      StoredKey.changeset(%{
        key_id: key_id,
        private_key: plaintext,
        holder_id: "workspace_webhook"
      })

    case Repo.insert(changeset) do
      {:ok, _} -> {:ok, %{key_id: key_id, plaintext: plaintext}}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def hmac(key_id, payload) do
    case Repo.get_by(StoredKey, key_id: key_id) do
      nil ->
        {:error, :not_found}

      %StoredKey{private_key: secret} ->
        {:ok, :crypto.mac(:hmac, :sha256, secret, IO.iodata_to_binary(payload))}
    end
  end

  @impl true
  def rotate(key_id) do
    case Repo.get_by(StoredKey, key_id: key_id) do
      nil ->
        {:error, :not_found}

      %StoredKey{} = stored ->
        plaintext = random_plaintext()

        stored
        |> Ecto.Changeset.change(private_key: plaintext)
        |> Repo.update()
        |> case do
          {:ok, _} -> {:ok, %{plaintext: plaintext}}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  @impl true
  def delete(key_id) do
    case Repo.get_by(StoredKey, key_id: key_id) do
      nil ->
        :ok

      %StoredKey{} = stored ->
        Repo.delete(stored)
        |> case do
          {:ok, _} -> :ok
          err -> err
        end
    end
  end

  # The plaintext is what a customer pastes into their webhook receiver, so
  # it should be URL-safe and copy-friendly. 32 random bytes → 43 base64url
  # chars, prefixed for identification.
  defp random_plaintext do
    "whsec_" <> Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
  end
end
