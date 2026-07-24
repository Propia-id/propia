defmodule Sovra.Crypto.KmsKeyStore do
  @moduledoc """
  Production P-256 key store. Delegates to the dedicated signer service over
  HTTP (reached across Tailscale), which signs via AWS KMS. The API node holds
  no key material and no AWS credentials — it just makes an authenticated RPC.

  The private key never leaves KMS; this is the OpenBao/Transit replacement, so
  it returns the same shapes as the other `Sovra.Crypto.KeyStore` backends
  (`{key_id, public_key_x, public_key_y}` on create, `%{r, s}` on sign).

  HTTP transport and config (`config :sovra, :signer`) live in
  `Sovra.Signer.Client`.
  """

  @behaviour Sovra.Crypto.KeyStore

  alias Sovra.Signer.Client

  @coord_size 32

  @impl Sovra.Crypto.KeyStore
  def generate_key(holder_id) do
    with {:ok, %{status: 201, body: body}} <-
           Client.post("/v1/keys", %{holder_id: to_string(holder_id)}),
         %{"key_id" => key_id, "public_key_x" => x_hex, "public_key_y" => y_hex} <- body,
         {:ok, <<_::binary-size(@coord_size)>> = x} <- Client.decode_hex(x_hex),
         {:ok, <<_::binary-size(@coord_size)>> = y} <- Client.decode_hex(y_hex) do
      {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}}
    else
      # Match only HTTP responses here — a bare `{:ok, resp}` would also
      # swallow `{:ok, wrong_size_binary}` from decode_hex and crash on
      # `resp.status`.
      {:ok, %{status: status, body: body}} -> {:error, {:signer_error, status, body}}
      {:error, _} = err -> err
      other -> {:error, {:unexpected_signer_response, other}}
    end
  end

  @impl Sovra.Crypto.KeyStore
  def sign(key_id, <<hash::binary-size(32)>>) when is_binary(key_id) do
    with {:ok, %{status: 200, body: body}} <-
           Client.post("/v1/sign", %{key: key_id, digest: Base.encode16(hash, case: :lower)}),
         %{"r" => r_hex, "s" => s_hex} <- body,
         {:ok, <<_::binary-size(@coord_size)>> = r} <- Client.decode_hex(r_hex),
         {:ok, <<_::binary-size(@coord_size)>> = s} <- Client.decode_hex(s_hex) do
      {:ok, %{r: r, s: s}}
    else
      {:ok, %{status: status, body: body}} -> {:error, {:signer_error, status, body}}
      {:error, _} = err -> err
      other -> {:error, {:unexpected_signer_response, other}}
    end
  end

  def sign(_key_id, _hash), do: {:error, :invalid_hash_size}

  @impl Sovra.Crypto.KeyStore
  def delete_key(key_id) when is_binary(key_id) do
    case Client.post("/v1/keys/#{key_id}/deletion", %{}) do
      {:ok, %{status: 200}} -> :ok
      {:ok, resp} -> {:error, {:signer_error, resp.status, resp.body}}
      {:error, _} = err -> err
    end
  end
end
