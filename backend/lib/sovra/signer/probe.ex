defmodule Sovra.Signer.Probe do
  @moduledoc """
  The API node's read-only view of the signer, for `Sovra.Health`.

  Deliberately not `Sovra.Signer.Client`, for two reasons:

    * `Client` logs `signer.request.failed` at `:error` on every non-2xx. A
      dependency that stays down would then emit an error line per node per
      minute, forever, from a *monitor* rather than from a real request.
    * The readiness probe must be able to answer when the shared bearer token is
      the thing that is wrong, so `health/0` sends no token at all — the
      signer's probe routes are unauthenticated by design.

  Two calls with different jobs. `relayer_address/0` exercises the
  **authenticated** path, so a rotated `SIGNER_TOKEN` is caught. `health/0`
  reads the signer's own KMS verdict, which the authenticated call cannot see:
  the relayer public key is memoized in `:persistent_term` on the signer, so it
  stops reaching AWS after the first call and a revoked IAM role would stay
  invisible until a real signature.
  """

  @typedoc """
  The signer's KMS verdict. `:starting` means it has not completed its first
  probe; `:skipped` means there is nothing to reach — no signer is configured,
  or the one deployed does not serve the route yet.
  """
  @type verdict :: %{kms: :ok | :error | :starting | :skipped}

  @doc """
  Whether this node talks to a signer service at all. Local dev and the test
  suite run the software key store and an in-process relayer key, so there is
  no signer to be down.
  """
  @spec configured?() :: boolean()
  def configured? do
    case Application.get_env(:sovra, :signer, [])[:url] do
      url when is_binary(url) and url != "" -> true
      _ -> false
    end
  end

  @doc "The authenticated path: does the signer answer, and does it accept our token?"
  @spec relayer_address() :: :ok | :skipped | {:error, term()}
  def relayer_address do
    if configured?() do
      case request(method: :get, path: "/v1/relayer/address", auth: true) do
        {:ok, %{status: 200, body: %{"address" => address}}} when is_binary(address) -> :ok
        {:ok, %{status: 200, body: body}} -> {:error, {:unexpected_signer_response, body}}
        {:ok, resp} -> {:error, {:signer_error, resp.status, resp.body}}
        {:error, _} = err -> err
      end
    else
      :skipped
    end
  end

  @doc "The signer's own KMS verdict, from its unauthenticated `GET /ready`."
  @spec health() :: {:ok, verdict()} | {:error, term()}
  def health do
    if configured?() do
      with {:ok, resp} <- request(method: :get, path: "/ready", auth: false),
           do: interpret(resp)
    else
      {:ok, %{kms: :skipped}}
    end
  end

  # --- internals -------------------------------------------------------------

  defp interpret(%{status: status} = resp) when status in [200, 503], do: kms_verdict(resp)

  # A signer that has no /ready route yet. `deploy.services` deploys the API
  # before the signer, so this is the normal state of a rollout window, not a
  # fault: reporting it as an error would 503 every API node, and page, until
  # the signer catches up.
  defp interpret(%{status: 404}), do: {:ok, %{kms: :skipped}}

  # 401 means the signer authenticated before it dispatched, which a router that
  # does not know this route does — the unauthenticated probe never reached a
  # route at all, so this is not a KMS verdict either. Ask again WITH the token
  # rather than assume: such a signer answers 404 from its catch-all, while one
  # that rejects the token too is a genuine auth failure worth reporting.
  defp interpret(%{status: 401}), do: retry_authenticated()

  defp interpret(resp), do: {:error, {:signer_error, resp.status, resp.body}}

  # Deliberately not a recursive call back into `interpret/1`: a token the signer
  # also rejects would answer 401 again and loop, one HTTP request per turn.
  # Exactly one retry, then a verdict either way.
  defp retry_authenticated do
    case request(method: :get, path: "/ready", auth: true) do
      {:ok, %{status: 404}} -> {:ok, %{kms: :skipped}}
      {:ok, %{status: status} = resp} when status in [200, 503] -> kms_verdict(resp)
      {:ok, resp} -> {:error, {:signer_error, resp.status, resp.body}}
      {:error, _} = err -> err
    end
  end

  defp kms_verdict(%{body: %{"checks" => %{"kms" => %{"status" => kms}}}}),
    do: {:ok, %{kms: kms_status(kms)}}

  defp kms_verdict(%{body: body}), do: {:error, {:unexpected_signer_response, body}}

  # The signer reports a bare status and no reason, deliberately. Anything we do
  # not recognise is an error, not a silent pass.
  defp kms_status("ok"), do: :ok
  defp kms_status("starting"), do: :starting
  defp kms_status(_), do: :error

  defp request(opts) do
    config = Application.get_env(:sovra, :signer, [])

    with {:ok, base} <- fetch(config, :url, :signer_url_missing),
         {:ok, auth} <- auth(config, opts[:auth]) do
      options =
        [
          method: opts[:method],
          url: base <> opts[:path],
          retry: false,
          receive_timeout: config[:receive_timeout] || 15_000
        ] ++ auth ++ (config[:req_options] || [])

      case Req.request(options) do
        {:ok, resp} -> {:ok, resp}
        {:error, reason} -> {:error, {:signer_unreachable, reason}}
      end
    end
  end

  defp auth(_config, false), do: {:ok, []}

  defp auth(config, true) do
    with {:ok, token} <- fetch(config, :token, :signer_token_missing),
         do: {:ok, [auth: {:bearer, token}]}
  end

  defp fetch(config, key, error) do
    case config[key] do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end
end
