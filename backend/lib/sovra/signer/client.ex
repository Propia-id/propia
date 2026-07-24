defmodule Sovra.Signer.Client do
  @moduledoc """
  HTTP client for the signer service, shared by everything on the API node
  that talks to it (`Sovra.Crypto.KmsKeyStore` for P-256 workspace keys,
  `Sovra.Ethereum.KmsSigner` for the secp256k1 relayer).

  Reads `config :sovra, :signer`:
    * `url`   — signer base URL, e.g. `http://sovra-signer:4001`
    * `token` — shared bearer token (`SIGNER_TOKEN`)
    * `receive_timeout` — optional, defaults to 15s
    * `req_options` — extra `Req` options (tests inject `plug:`/`base_url`)

  Requests carry bearer auth and never retry; transport errors map to
  `{:error, {:signer_unreachable, reason}}`. Also owns `decode_hex/1` for the
  hex (`0x` optional) binaries the signer speaks.
  """

  @spec post(String.t(), map()) :: {:ok, Req.Response.t()} | {:error, term()}
  def post(path, body), do: request(:post, path, json: body)

  @spec get(String.t()) :: {:ok, Req.Response.t()} | {:error, term()}
  def get(path), do: request(:get, path, [])

  defp request(method, path, extra) do
    config = Application.get_env(:sovra, :signer, [])

    with {:ok, base} <- fetch(config, :url, :signer_url_missing),
         {:ok, token} <- fetch(config, :token, :signer_token_missing) do
      options =
        [
          method: method,
          url: base <> path,
          auth: {:bearer, token},
          retry: false,
          receive_timeout: config[:receive_timeout] || 15_000
        ] ++ extra ++ (config[:req_options] || [])

      case Req.request(options) do
        {:ok, resp} -> {:ok, resp}
        {:error, reason} -> {:error, {:signer_unreachable, reason}}
      end
    end
  end

  defp fetch(config, key, error) do
    case config[key] do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end

  @spec decode_hex(term()) :: {:ok, binary()} | {:error, :bad_hex}
  def decode_hex("0x" <> hex), do: decode_hex(hex)

  def decode_hex(hex) when is_binary(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, :bad_hex}
    end
  end

  def decode_hex(_), do: {:error, :bad_hex}
end
