defmodule Sovra.AWS.KMS do
  @moduledoc """
  Thin wrapper over the aws-elixir KMS API for P-256 (secp256r1) signing keys.

  Only the signer service (`SERVICE=signer`) calls this — the API nodes reach
  the signer over HTTP and never talk to AWS. Credentials come from
  `:aws_credentials` (EC2 instance role via IMDS on the signer box); the region
  is read from config/env. HTTP is driven through `Sovra.AWS.ReqHTTPClient`.

  KMS speaks awsjson1.1, where blob members are base64 strings in the JSON body
  and aws-elixir does NOT auto-encode them — so `sign/2` base64-encodes the
  digest and decodes the returned signature/public key here.

  `sign/2` returns the raw DER-encoded ECDSA signature and `get_public_key/1`
  the DER (SPKI) public key exactly as KMS returns them; parsing DER,
  normalizing low-s and extracting the point is the caller's job
  (`Sovra.Signer.Kms`), not this wrapper's.
  """

  # P-256 (secp256r1) — matches Sovra.Crypto.P256, the curve the holder/workspace
  # signing keys use. (Distinct from the relayer's secp256k1, which is not KMS
  # yet — see the runtime.exs notes.)
  @key_spec "ECC_NIST_P256"
  @key_usage "SIGN_VERIFY"
  @signing_algorithm "ECDSA_SHA_256"
  @default_pending_deletion_days 7

  @doc "Sign a 32-byte digest with `key_id`. Returns the raw DER ECDSA signature."
  @spec sign(String.t(), <<_::256>>) :: {:ok, binary()} | {:error, term()}
  def sign(key_id, <<digest::binary-size(32)>>) when is_binary(key_id) do
    input = %{
      "KeyId" => key_id,
      "Message" => Base.encode64(digest),
      "MessageType" => "DIGEST",
      "SigningAlgorithm" => @signing_algorithm
    }

    with {:ok, client} <- client(),
         {:ok, %{"Signature" => sig_b64}, _resp} <- AWS.KMS.sign(client, input),
         {:ok, der} <- decode64(sig_b64) do
      {:ok, der}
    else
      {:ok, body, _resp} -> {:error, {:unexpected_kms_response, body}}
      {:error, _} = err -> err
    end
  end

  @doc "Fetch the DER (SPKI) public key for `key_id`."
  @spec get_public_key(String.t()) :: {:ok, binary()} | {:error, term()}
  def get_public_key(key_id) when is_binary(key_id) do
    with {:ok, client} <- client(),
         {:ok, %{"PublicKey" => pk_b64}, _resp} <-
           AWS.KMS.get_public_key(client, %{"KeyId" => key_id}),
         {:ok, der} <- decode64(pk_b64) do
      {:ok, der}
    else
      {:ok, body, _resp} -> {:error, {:unexpected_kms_response, body}}
      {:error, _} = err -> err
    end
  end

  @doc """
  Create a new asymmetric P-256 sign/verify KMS key. `tags` is a list of
  `{key, value}` string pairs. Returns the created key's id.

  Keys are created as multi-region primaries: MultiRegion is immutable after
  creation, and replicating a signing key to another region (same key id and
  material) is only possible if the primary was created this way.
  """
  @spec create_key([{String.t(), String.t()}]) ::
          {:ok, %{key_id: String.t()}} | {:error, term()}
  def create_key(tags \\ []) when is_list(tags) do
    input = %{
      "KeySpec" => @key_spec,
      "KeyUsage" => @key_usage,
      "MultiRegion" => true,
      "Tags" => Enum.map(tags, fn {k, v} -> %{"TagKey" => k, "TagValue" => v} end)
    }

    with {:ok, client} <- client(),
         {:ok, %{"KeyMetadata" => %{"KeyId" => key_id}}, _resp} <-
           AWS.KMS.create_key(client, input) do
      {:ok, %{key_id: key_id}}
    else
      {:ok, body, _resp} -> {:error, {:unexpected_kms_response, body}}
      {:error, _} = err -> err
    end
  end

  @doc "Point `alias_name` (`alias/...`) at `key_id`."
  @spec create_alias(String.t(), String.t()) :: :ok | {:error, term()}
  def create_alias(alias_name, key_id) when is_binary(alias_name) and is_binary(key_id) do
    with {:ok, client} <- client(),
         {:ok, _body, _resp} <-
           AWS.KMS.create_alias(client, %{"AliasName" => alias_name, "TargetKeyId" => key_id}) do
      :ok
    end
  end

  @doc "Schedule `key_id` for deletion (default 7-day pending window)."
  @spec schedule_key_deletion(String.t(), pos_integer()) :: :ok | {:error, term()}
  def schedule_key_deletion(key_id, pending_days \\ @default_pending_deletion_days)
      when is_binary(key_id) do
    with {:ok, client} <- client(),
         {:ok, _body, _resp} <-
           AWS.KMS.schedule_key_deletion(client, %{
             "KeyId" => key_id,
             "PendingWindowInDays" => pending_days
           }) do
      :ok
    else
      {:ok, body, _resp} -> {:error, {:unexpected_kms_response, body}}
      {:error, _} = err -> err
    end
  end

  # --- internals -------------------------------------------------------------

  defp client do
    with {:ok, region} <- region(),
         creds when is_map(creds) <- fetch_credentials() do
      client =
        AWS.Client.create(
          creds.access_key_id,
          creds.secret_access_key,
          Map.get(creds, :token),
          region
        )
        |> AWS.Client.put_http_client({Sovra.AWS.ReqHTTPClient, []})

      {:ok, client}
    else
      :undefined -> {:error, :no_aws_credentials}
      {:error, _} = err -> err
    end
  end

  defp fetch_credentials do
    case Application.ensure_all_started(:aws_credentials) do
      {:ok, _} -> :aws_credentials.get_credentials()
      {:error, reason} -> {:error, {:aws_credentials_start_failed, reason}}
    end
  end

  defp region do
    config = Application.get_env(:sovra, :signer_service, [])

    case config[:region] || System.get_env("AWS_REGION") do
      nil -> {:error, :aws_region_missing}
      "" -> {:error, :aws_region_missing}
      region -> {:ok, region}
    end
  end

  defp decode64(b64) do
    case Base.decode64(b64) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, :bad_base64}
    end
  end
end
