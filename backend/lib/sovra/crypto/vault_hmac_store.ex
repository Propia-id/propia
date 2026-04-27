defmodule Sovra.Crypto.VaultHmacStore do
  @moduledoc """
  HMAC-SHA256 store backed by OpenBao/Vault Transit.

  The plaintext is `exportable: true` so it can be revealed to the user
  once at creation/rotation (they need it to verify our signatures on their
  side). After that, all signing happens server-side in Vault.
  """

  @behaviour Sovra.Crypto.HmacKeyStore

  @impl true
  def generate_hmac_key do
    name = generate_key_name()

    with :ok <- create_transit_key(name),
         {:ok, plaintext} <- export_key(name, 1) do
      {:ok, %{key_id: name, plaintext: plaintext}}
    end
  end

  @impl true
  def hmac(key_id, payload) do
    %{url: url, token: token, transit_mount: mount} = vault_config()

    body = %{
      "input" => Base.encode64(IO.iodata_to_binary(payload)),
      "algorithm" => "sha2-256"
    }

    case Req.post("#{url}/v1/#{mount}/hmac/#{key_id}",
           json: body,
           headers: auth_headers(token)
         ) do
      {:ok, %{status: 200, body: %{"data" => %{"hmac" => "vault:v1:" <> b64}}}} ->
        case Base.decode64(b64) do
          {:ok, sig} -> {:ok, sig}
          :error -> {:error, :invalid_signature}
        end

      {:ok, %{status: status, body: body}} ->
        {:error, {:vault_hmac_error, status, body}}

      {:error, reason} ->
        {:error, {:vault_hmac_error, reason}}
    end
  end

  @impl true
  def rotate(key_id) do
    %{url: url, token: token, transit_mount: mount} = vault_config()

    with {:ok, %{status: status}} when status in [200, 204] <-
           Req.post("#{url}/v1/#{mount}/keys/#{key_id}/rotate",
             json: %{},
             headers: auth_headers(token)
           ),
         {:ok, latest_version} <- fetch_latest_version(key_id),
         {:ok, plaintext} <- export_key(key_id, latest_version) do
      {:ok, %{plaintext: plaintext}}
    else
      {:ok, %{status: status, body: body}} -> {:error, {:vault_rotate_error, status, body}}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def delete(key_id) do
    %{url: url, token: token, transit_mount: mount} = vault_config()
    headers = auth_headers(token)

    with {:ok, %{status: 200}} <-
           Req.post("#{url}/v1/#{mount}/keys/#{key_id}/config",
             json: %{"deletion_allowed" => true},
             headers: headers
           ),
         {:ok, %{status: 204}} <-
           Req.delete("#{url}/v1/#{mount}/keys/#{key_id}", headers: headers) do
      :ok
    else
      {:ok, %{status: status, body: body}} -> {:error, {:vault_delete_error, status, body}}
      {:error, reason} -> {:error, {:vault_delete_error, reason}}
    end
  end

  # --- Private ---

  defp create_transit_key(name) do
    %{url: url, token: token, transit_mount: mount} = vault_config()

    body = %{
      "type" => "hmac",
      "algorithm" => "sha2-256",
      "exportable" => true
    }

    case Req.post("#{url}/v1/#{mount}/keys/#{name}", json: body, headers: auth_headers(token)) do
      {:ok, %{status: status}} when status in [200, 204] -> :ok
      {:ok, %{status: status, body: body}} -> {:error, {:vault_create_error, status, body}}
      {:error, reason} -> {:error, {:vault_create_error, reason}}
    end
  end

  defp export_key(name, version) do
    %{url: url, token: token, transit_mount: mount} = vault_config()

    case Req.get("#{url}/v1/#{mount}/export/hmac-key/#{name}/#{version}",
           headers: auth_headers(token)
         ) do
      {:ok, %{status: 200, body: %{"data" => %{"keys" => keys}}}} ->
        case Map.get(keys, to_string(version)) do
          nil -> {:error, :export_missing}
          plaintext when is_binary(plaintext) -> {:ok, plaintext}
        end

      {:ok, %{status: status, body: body}} ->
        {:error, {:vault_export_error, status, body}}

      {:error, reason} ->
        {:error, {:vault_export_error, reason}}
    end
  end

  defp fetch_latest_version(name) do
    %{url: url, token: token, transit_mount: mount} = vault_config()

    case Req.get("#{url}/v1/#{mount}/keys/#{name}", headers: auth_headers(token)) do
      {:ok, %{status: 200, body: %{"data" => %{"latest_version" => v}}}} ->
        {:ok, v}

      {:ok, %{status: status, body: body}} ->
        {:error, {:vault_get_key_error, status, body}}

      {:error, reason} ->
        {:error, {:vault_get_key_error, reason}}
    end
  end

  defp vault_config do
    config = Application.fetch_env!(:sovra, :vault)

    %{
      url: Keyword.fetch!(config, :url),
      token: Keyword.fetch!(config, :token),
      transit_mount: Keyword.get(config, :transit_mount, "transit")
    }
  end

  defp auth_headers(token), do: [{"x-vault-token", token}]

  defp generate_key_name do
    "webhook-" <> (:crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower))
  end
end
