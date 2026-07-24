defmodule Sovra.AWS.ReqHTTPClient do
  @moduledoc """
  `AWS.HTTPClient` implementation backed by `Req` (which owns its own Finch
  pool), so aws-elixir needs neither hackney nor a separately supervised Finch.
  Used by `Sovra.AWS.KMS`.

  aws-elixir signs the request (SigV4) *before* calling this: `headers` already
  carries `Authorization` + the `x-amz-*` headers and `body` is the exact signed
  payload. We therefore forward both verbatim and disable Req's
  request-mutating conveniences (retry, redirect, body decoding) so nothing that
  the signature was computed over is altered. Response decompression is left on
  so the caller receives decompressed JSON to parse.

  `config :sovra, :aws_req_options` is appended to every request — the test
  seam (tests inject `plug: {Req.Test, :aws_kms}`), mirroring the `:signer`
  config's `req_options`. Unset in prod.
  """

  @behaviour AWS.HTTPClient

  @impl AWS.HTTPClient
  def request(method, url, body, headers, options) do
    req_opts =
      [
        method: method,
        url: IO.iodata_to_binary(url),
        headers: headers,
        body: IO.iodata_to_binary(body),
        decode_body: false,
        retry: false,
        redirect: false
      ] ++
        Keyword.take(options, [:receive_timeout, :connect_options, :pool_timeout]) ++
        Application.get_env(:sovra, :aws_req_options, [])

    case Req.request(req_opts) do
      {:ok, %Req.Response{status: status, headers: resp_headers, body: resp_body}} ->
        {:ok, %{status_code: status, headers: flatten_headers(resp_headers), body: resp_body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Req returns headers as %{"name" => ["value", ...]}; aws-elixir expects a
  # flat list of {name, value} tuples.
  defp flatten_headers(headers) when is_map(headers) do
    Enum.flat_map(headers, fn {k, values} -> Enum.map(values, &{k, &1}) end)
  end

  defp flatten_headers(headers) when is_list(headers), do: headers
end
