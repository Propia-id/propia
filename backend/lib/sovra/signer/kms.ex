defmodule Sovra.Signer.Kms do
  @moduledoc """
  P-256-over-KMS signing primitive — the heart of the signer service.

  Mirrors what the OpenBao Transit key store used to do, but against AWS KMS:

    * `create_key/1` — `CreateKey` (ECC_NIST_P256, tagged) + `GetPublicKey`,
      returning the key id and its `(x, y)` public-key coordinates, then
      `CreateAlias` under `alias/sovra/<env>/app/<holder_id>` (the namespace the
      signer role may manage — see infra `iam.tf`). The alias is traceability
      only, so an alias failure logs a warning without failing the key.
    * `sign/2` — `Sign` a 32-byte digest (raw DER out), parsed into `{r, s}` and
      low-s normalized by `Sovra.Crypto.P256`, matching `KeyStore.sign/2`.
    * `schedule_deletion/1` — `ScheduleKeyDeletion`.

  The KMS backend is swappable for tests via
  `config :sovra, :kms_backend, Module` (default `Sovra.AWS.KMS`); it must expose
  `create_key/1`, `create_alias/2`, `sign/2`, `get_public_key/1` and
  `schedule_key_deletion/1`.
  """

  alias Sovra.Crypto.P256
  alias Sovra.Crypto.Spki

  require Logger

  @coord_size 32
  @kind_tag {"sovra:kind", "workspace-signer"}

  @doc """
  Create a P-256 KMS key and return its id plus the 32-byte `(x, y)` public-key
  coordinates. `holder_id` is recorded only for logging/traceability.
  """
  @spec create_key(String.t()) ::
          {:ok, %{key_id: String.t(), public_key_x: binary(), public_key_y: binary()}}
          | {:error, term()}
  def create_key(holder_id) when is_binary(holder_id) do
    tags = [@kind_tag, {"sovra:env", env()}]

    with {:ok, %{key_id: key_id}} <- backend().create_key(tags) do
      case fetch_public_key(key_id) do
        {:ok, {x, y}} ->
          put_alias(key_id, holder_id)
          {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}}

        {:error, reason} ->
          # The key already exists in KMS but is unusable to the caller; without
          # cleanup every provisioning retry would mint (and leak) another one.
          discard_key(key_id)
          {:error, reason}
      end
    end
  end

  def create_key(_holder_id), do: {:error, :invalid_holder_id}

  @doc "Sign a 32-byte digest with `key_id`; returns `%{r, s}` (low-s normalized)."
  @spec sign(String.t(), <<_::256>>) :: {:ok, %{r: binary(), s: binary()}} | {:error, term()}
  def sign(key_id, <<digest::binary-size(32)>>) when is_binary(key_id) do
    with {:ok, der_sig} <- backend().sign(key_id, digest) do
      P256.parse_der_signature(der_sig)
    end
  end

  def sign(_key_id, _digest), do: {:error, :invalid_hash_size}

  @doc "Schedule `key_id` for deletion."
  @spec schedule_deletion(String.t()) :: :ok | {:error, term()}
  def schedule_deletion(key_id) when is_binary(key_id),
    do: backend().schedule_key_deletion(key_id)

  # --- internals -------------------------------------------------------------

  # Console traceability only — the authoritative workspace<->key link is the
  # caller's DB row, so a failed alias (e.g. leftover from a retried
  # provisioning) must never fail the key.
  defp put_alias(key_id, holder_id) do
    case backend().create_alias(alias_name(key_id, holder_id), key_id) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning("Failed to create alias for KMS key #{key_id}: #{inspect(reason)}")
    end
  end

  # KMS alias charset is [a-zA-Z0-9/_-]; an empty holder_id falls back to the
  # (always unique) key id.
  defp alias_name(key_id, holder_id) do
    suffix =
      case String.replace(holder_id, ~r/[^a-zA-Z0-9_-]/, "-") do
        "" -> key_id
        sanitized -> String.slice(sanitized, 0, 200)
      end

    "alias/sovra/#{env()}/app/#{suffix}"
  end

  defp discard_key(key_id) do
    case backend().schedule_key_deletion(key_id) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "Failed to schedule deletion of orphaned KMS key #{key_id}: #{inspect(reason)}"
        )
    end
  end

  defp fetch_public_key(key_id) do
    with {:ok, der_spki} <- backend().get_public_key(key_id),
         {:ok, <<4, x::binary-size(@coord_size), y::binary-size(@coord_size)>>} <-
           Spki.uncompressed_point(der_spki) do
      {:ok, {x, y}}
    end
  end

  defp backend, do: Application.get_env(:sovra, :kms_backend, Sovra.AWS.KMS)

  defp env, do: Application.get_env(:sovra, :signer_service, [])[:env] || "dev"
end
