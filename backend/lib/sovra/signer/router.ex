defmodule Sovra.Signer.Router do
  @moduledoc """
  Internal HTTP API for the signer service (reached only by API nodes over
  Tailscale). Every request must carry `Authorization: Bearer <SIGNER_TOKEN>`;
  the Tailscale ACL is the outer network gate.

    * `POST /v1/keys`             — `{holder_id}` → `{key_id, public_key_x, public_key_y}`
    * `POST /v1/sign`             — `{key, digest}` → `{r, s}`  (P-256 workspace keys)
    * `POST /v1/keys/:id/deletion` — schedule key deletion
    * `POST /v1/relayer/sign`     — `{digest}` → `{r, s, recovery_id}`  (secp256k1 relayer)
    * `GET  /v1/relayer/address`  — → `{address}`  (the relayer's 0x address)

  `digest` and returned binaries are lowercase hex (`0x` optional). Workspace
  signatures are P-256 `{r, s}`; the relayer's are secp256k1 `{r, s, recovery_id}`
  for Ethereum transaction assembly.
  """

  use Plug.Router

  require Logger

  alias Sovra.Signer.{Kms, Relayer}

  plug(:match)
  plug(Plug.Parsers, parsers: [:json], pass: ["application/json"], json_decoder: Jason)
  plug(:authenticate)
  plug(:dispatch)

  post "/v1/keys" do
    with {:ok, holder_id} <- fetch_holder_id(conn.body_params["holder_id"]),
         {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} <-
           Kms.create_key(holder_id) do
      send_json(conn, 201, %{key_id: key_id, public_key_x: hex(x), public_key_y: hex(y)})
    else
      {:error, reason} -> send_error(conn, reason)
    end
  end

  post "/v1/sign" do
    with {:ok, key_id} <- fetch_key(conn.body_params["key"]),
         {:ok, digest} <- decode_digest(conn.body_params["digest"]),
         {:ok, %{r: r, s: s}} <- Kms.sign(key_id, digest) do
      send_json(conn, 200, %{r: hex(r), s: hex(s)})
    else
      {:error, reason} -> send_error(conn, reason)
    end
  end

  post "/v1/keys/:id/deletion" do
    case Kms.schedule_deletion(id) do
      :ok -> send_json(conn, 200, %{status: "scheduled"})
      {:error, reason} -> send_error(conn, reason)
    end
  end

  post "/v1/relayer/sign" do
    with {:ok, digest} <- decode_digest(conn.body_params["digest"]),
         {:ok, %{r: r, s: s, recovery_id: v}} <- Relayer.sign(digest) do
      send_json(conn, 200, %{r: hex(r), s: hex(s), recovery_id: v})
    else
      {:error, reason} -> send_error(conn, reason)
    end
  end

  get "/v1/relayer/address" do
    case Relayer.address() do
      {:ok, address} -> send_json(conn, 200, %{address: address})
      {:error, reason} -> send_error(conn, reason)
    end
  end

  match _ do
    send_json(conn, 404, %{error: "not_found"})
  end

  # --- auth ------------------------------------------------------------------

  defp authenticate(conn, _opts) do
    if valid_token?(conn) do
      conn
    else
      conn |> send_json(401, %{error: "unauthorized"}) |> halt()
    end
  end

  defp valid_token?(conn) do
    expected = Application.get_env(:sovra, :signer_service, [])[:token]

    case get_req_header(conn, "authorization") do
      ["Bearer " <> presented] when is_binary(expected) and expected != "" ->
        Plug.Crypto.secure_compare(presented, expected)

      _ ->
        false
    end
  end

  # --- helpers ---------------------------------------------------------------

  defp fetch_key(key) when is_binary(key) and key != "", do: {:ok, key}
  defp fetch_key(_), do: {:error, :missing_key}

  # holder_id is optional (logging/traceability only) but must be a string.
  defp fetch_holder_id(nil), do: {:ok, ""}
  defp fetch_holder_id(holder_id) when is_binary(holder_id), do: {:ok, holder_id}
  defp fetch_holder_id(_), do: {:error, :invalid_holder_id}

  defp decode_digest("0x" <> hex), do: decode_digest(hex)

  defp decode_digest(hex) when is_binary(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, <<_::binary-size(32)>> = digest} -> {:ok, digest}
      {:ok, _} -> {:error, :bad_digest_length}
      :error -> {:error, :bad_digest_encoding}
    end
  end

  defp decode_digest(_), do: {:error, :missing_digest}

  # Client input → 400, KMS/backend failures → 502.
  defp error_status(reason)
       when reason in [
              :missing_key,
              :missing_digest,
              :bad_digest_length,
              :bad_digest_encoding,
              :invalid_hash_size,
              :invalid_holder_id
            ],
       do: 400

  # Server-side misconfiguration (relayer key id not set) vs KMS/recovery failure.
  defp error_status(:relayer_key_not_configured), do: 500
  defp error_status(_), do: 502

  defp hex(bin), do: Base.encode16(bin, case: :lower)

  defp send_error(conn, reason) do
    status = error_status(reason)
    message = error_message(reason)
    if status >= 500, do: Logger.warning("sovra signer request failed (#{status}): #{message}")
    send_json(conn, status, %{error: message})
  end

  # Never crash formatting an error: `to_string/1` raises on tuple/list reasons
  # (e.g. {:unexpected_kms_response, body}), so fall back to inspect/1.
  defp error_message(reason) when is_atom(reason), do: to_string(reason)
  defp error_message(reason) when is_binary(reason), do: reason
  defp error_message(reason), do: inspect(reason)

  defp send_json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
