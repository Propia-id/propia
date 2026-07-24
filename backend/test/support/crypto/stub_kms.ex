defmodule SovraTest.Crypto.StubKms do
  @moduledoc """
  In-memory stand-in for `Sovra.AWS.KMS` used in signer tests. Generates real
  EC keys (so the DER/low-s/SPKI/recovery parsing is genuinely exercised) and
  encodes the curve + private key into the returned key id — no AWS, no external
  state to supervise.

    * `create_key/1` mints a P-256 key (`stub-p256-<privhex>`) — the workspace
      signing key path.
    * relayer keys are referenced by a pre-set `stub-k1-<privhex>` id (secp256k1);
      `sign/2` and `get_public_key/1` dispatch on the prefix.

  Failure injection is process-scoped (safe under `async: true`, since the
  caller runs in the test process): `Process.put(:stub_kms_fail_get_public_key,
  reason)` makes `get_public_key/1` return `{:error, reason}`. Every
  `schedule_key_deletion/2` call also sends the caller
  `{:stub_kms, :schedule_key_deletion, key_id}` so cleanup can be asserted.
  """

  # Standard SubjectPublicKeyInfo headers up to the BIT STRING unused-bits octet;
  # the 65-byte uncompressed point (04 || X || Y) follows. Lets the stub emit
  # exactly the DER shape AWS KMS GetPublicKey returns for each curve.
  @p256_spki Base.decode16!("3059301306072A8648CE3D020106082A8648CE3D030107034200")
  @k1_spki Base.decode16!("3056301006072A8648CE3D020106052B8104000A034200")

  def create_key(_tags \\ []) do
    {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    {:ok, %{key_id: "stub-p256-" <> Base.encode16(priv, case: :lower)}}
  end

  def sign("stub-" <> rest, <<digest::binary-size(32)>>) do
    {curve, priv} = decode(rest)
    {:ok, :crypto.sign(:ecdsa, :sha256, {:digest, digest}, [priv, curve])}
  end

  def get_public_key("stub-" <> rest) do
    case Process.get(:stub_kms_fail_get_public_key) do
      nil ->
        {curve, priv} = decode(rest)
        {pub, _priv} = :crypto.generate_key(:ecdh, curve, priv)
        {:ok, spki(curve) <> pub}

      reason ->
        {:error, reason}
    end
  end

  def schedule_key_deletion(key_id, _pending_days \\ 7) do
    send(self(), {:stub_kms, :schedule_key_deletion, key_id})
    :ok
  end

  defp decode("p256-" <> hex), do: {:secp256r1, Base.decode16!(hex, case: :mixed)}
  defp decode("k1-" <> hex), do: {:secp256k1, Base.decode16!(hex, case: :mixed)}

  defp spki(:secp256r1), do: @p256_spki
  defp spki(:secp256k1), do: @k1_spki
end
