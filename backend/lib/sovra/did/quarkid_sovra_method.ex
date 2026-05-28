defmodule Sovra.DID.QuarkidSovraMethod do
  @moduledoc """
  did:quarkid:sovra method resolver.

  A Quarkid Sovra DID has the form `did:quarkid:sovra:<sidetree-suffix>` where
  the suffix is the base64url-encoded Sidetree DID operation hash (typically
  starting with `Ei`). Resolution is delegated to the public Quarkid
  resolver at `node.sovra.io`, which returns a W3C DID Document with
  `verificationMethod[].publicKeyJwk` entries.

  Only signing-capable verification methods are returned — key-agreement
  entries (`X25519KeyAgreementKey2019`) are filtered out because they
  cannot verify signatures. Today the wallet only publishes Ed25519
  signing keys, so this method exclusively returns Ed25519 JWKs.

  Results are cached by `Sovra.DID.DocumentCache` to avoid hammering the
  resolver on every presentation. Resolution failures are negatively cached
  for a short TTL so a transient outage doesn't translate into a burst of
  retries.
  """

  require Logger

  alias Sovra.DID.DocumentCache

  @typedoc "Ed25519 JWK with the raw 32-byte public key in `x`."
  @type jwk :: %{kty: String.t(), crv: String.t(), x: binary}

  @default_base_url "https://node.sovra.io/resolve/"
  @default_request_timeout_ms 5_000
  @default_doc_ttl_s 300
  @default_negative_ttl_s 30

  @spec resolve(String.t()) :: {:ok, [jwk]} | {:error, atom}
  def resolve("did:quarkid:sovra:" <> suffix = did) do
    with :ok <- validate_suffix(suffix) do
      positive_ttl = config(:doc_cache_ttl_s, @default_doc_ttl_s)
      negative_ttl = config(:negative_cache_ttl_s, @default_negative_ttl_s)

      DocumentCache.fetch_or_wait(
        did,
        fn -> fetch_and_extract(did) end,
        positive_ttl,
        negative_ttl
      )
    end
  end

  def resolve(_), do: {:error, :unsupported_did_method}

  # ── Internals ───────────────────────────────────────────────

  defp validate_suffix(suffix) when is_binary(suffix) and byte_size(suffix) > 0 do
    if suffix =~ ~r/^[A-Za-z0-9_\-]+$/, do: :ok, else: {:error, :invalid_did}
  end

  defp validate_suffix(_), do: {:error, :invalid_did}

  defp fetch_and_extract(did) do
    case fetch_doc(did) do
      {:ok, doc} -> extract_signing_jwks(doc)
      {:error, _} = err -> err
    end
  end

  defp fetch_doc(did) do
    url = config(:base_url, @default_base_url) <> did

    req_opts =
      Keyword.merge(
        [
          receive_timeout: config(:request_timeout_ms, @default_request_timeout_ms),
          retry: :safe_transient
        ],
        config(:req_opts, [])
      )

    case Req.get(url, req_opts) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        {:ok, body}

      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        case Jason.decode(body) do
          {:ok, decoded} when is_map(decoded) -> {:ok, decoded}
          _ -> {:error, :did_unresolvable}
        end

      {:ok, %{status: status}} ->
        Logger.warning("Quarkid resolver returned status #{status} for #{did}")
        {:error, :did_unresolvable}

      {:error, reason} ->
        Logger.warning("Quarkid resolver transport error for #{did}: #{inspect(reason)}")
        {:error, :did_unresolvable}
    end
  end

  defp extract_signing_jwks(doc) do
    # Some resolver endpoints wrap the document in {"didDocument": ...}; tolerate both.
    document =
      case doc do
        %{"didDocument" => inner} when is_map(inner) -> inner
        other -> other
      end

    methods = document["verificationMethod"] || []

    jwks =
      methods
      |> Enum.map(&to_signing_jwk/1)
      |> Enum.reject(&is_nil/1)

    case jwks do
      [] -> {:error, :did_unresolvable}
      list -> {:ok, list}
    end
  end

  defp to_signing_jwk(%{"publicKeyJwk" => %{"kty" => "OKP", "crv" => "Ed25519", "x" => x_b64}})
       when is_binary(x_b64) do
    case decode_jwk_coordinate(x_b64) do
      {:ok, <<x::binary-size(32)>>} -> %{kty: "OKP", crv: "Ed25519", x: x}
      _ -> nil
    end
  end

  defp to_signing_jwk(_), do: nil

  # JOSE canonical form is unpadded base64url (RFC 7515 §2), but some
  # producers include `=` padding. Accept both shapes; strip whitespace
  # defensively before decoding either way.
  defp decode_jwk_coordinate(b64) do
    trimmed = String.trim(b64)

    case Base.url_decode64(trimmed, padding: false) do
      {:ok, _} = ok -> ok
      :error -> Base.url_decode64(trimmed, padding: true)
    end
  end

  defp config(key, default) do
    :sovra
    |> Application.get_env(:quarkid_resolver, [])
    |> Keyword.get(key, default)
  end
end
