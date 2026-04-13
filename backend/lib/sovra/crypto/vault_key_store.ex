defmodule Sovra.Crypto.VaultKeyStore do
  @moduledoc """
  P256 key store backed by OpenBao/Vault Transit engine.
  Keys never leave the Transit engine — signing happens server-side.
  For production use.
  """

  @behaviour Sovra.Crypto.KeyStore

  alias Sovra.Crypto.P256

  @coord_size 32

  @impl Sovra.Crypto.KeyStore
  def generate_key(_holder_id) do
    name = generate_key_name()

    with :ok <- create_transit_key(name),
         {:ok, {x, y}} <- fetch_public_key(name) do
      {:ok, %{key_id: name, public_key_x: x, public_key_y: y}}
    end
  end

  @impl Sovra.Crypto.KeyStore
  def sign(key_id, <<hash::binary-size(32)>>) do
    %{url: url, token: token, transit_mount: mount} = vault_config()

    body = %{
      "input" => Base.encode64(hash),
      "prehashed" => true,
      "hash_algorithm" => "sha2-256",
      "marshaling_algorithm" => "asn1"
    }

    case Req.post("#{url}/v1/#{mount}/sign/#{key_id}", json: body, headers: auth_headers(token)) do
      {:ok, %{status: 200, body: %{"data" => %{"signature" => signature}}}} ->
        parse_vault_signature(signature)

      {:ok, %{status: status, body: body}} ->
        {:error, {:vault_sign_error, status, body}}

      {:error, reason} ->
        {:error, {:vault_sign_error, reason}}
    end
  end

  def sign(_key_id, _hash), do: {:error, :invalid_hash_size}

  @impl Sovra.Crypto.KeyStore
  def delete_key(key_id) do
    %{url: url, token: token, transit_mount: mount} = vault_config()
    headers = auth_headers(token)

    # Enable deletion, then delete
    with {:ok, %{status: 200}} <-
           Req.post("#{url}/v1/#{mount}/keys/#{key_id}/config",
             json: %{"deletion_allowed" => true},
             headers: headers
           ),
         {:ok, %{status: 204}} <-
           Req.delete("#{url}/v1/#{mount}/keys/#{key_id}", headers: headers) do
      :ok
    else
      {:ok, %{status: status, body: body}} ->
        {:error, {:vault_delete_error, status, body}}

      {:error, reason} ->
        {:error, {:vault_delete_error, reason}}
    end
  end

  # --- Private ---

  defp create_transit_key(name) do
    %{url: url, token: token, transit_mount: mount} = vault_config()

    case Req.post("#{url}/v1/#{mount}/keys/#{name}",
           json: %{"type" => "ecdsa-p256"},
           headers: auth_headers(token)
         ) do
      {:ok, %{status: status}} when status in [200, 204] -> :ok
      {:ok, %{status: status, body: body}} -> {:error, {:vault_create_error, status, body}}
      {:error, reason} -> {:error, {:vault_create_error, reason}}
    end
  end

  defp fetch_public_key(name) do
    %{url: url, token: token, transit_mount: mount} = vault_config()

    case Req.get("#{url}/v1/#{mount}/keys/#{name}", headers: auth_headers(token)) do
      {:ok, %{status: 200, body: %{"data" => %{"keys" => keys}}}} ->
        # Latest version's public key (keys are version-numbered string maps)
        latest_version = keys |> Map.keys() |> Enum.max()
        %{"public_key" => pem} = keys[latest_version]
        parse_pem_public_key(pem)

      {:ok, %{status: status, body: body}} ->
        {:error, {:vault_get_key_error, status, body}}

      {:error, reason} ->
        {:error, {:vault_get_key_error, reason}}
    end
  end

  defp parse_vault_signature("vault:v1:" <> b64_signature) do
    b64_signature
    |> Base.decode64!()
    |> P256.parse_der_signature()
  end

  defp parse_pem_public_key(pem) do
    [{:SubjectPublicKeyInfo, der, :not_encrypted}] = :public_key.pem_decode(pem)

    {:SubjectPublicKeyInfo, _algo, key_bits} =
      :public_key.der_decode(:SubjectPublicKeyInfo, der)

    case key_bits do
      <<4, x::binary-size(@coord_size), y::binary-size(@coord_size)>> ->
        {:ok, {x, y}}

      _ ->
        {:error, :invalid_public_key_format}
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
