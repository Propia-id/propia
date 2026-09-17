defmodule Sovra.Mdoc.DeviceAuth do
  @moduledoc """
  Verifies the holder's signature on an mdoc presentation — **seam 2** of the
  retrofit contract.

  Everything above this module hands over a session transcript and a parsed
  `COSE_Sign1`; which signature construction was used is decided here, by the
  `alg` in the protected header. Swapping the holder's key from a WebAuthn
  passkey to a raw Secure Enclave key later is one more `do_verify/4` clause.

  ## Why a private-use algorithm

  A WebAuthn authenticator does not sign the payload. It signs
  `authenticatorData || SHA-256(clientDataJSON)`, and the payload appears only
  as the `challenge` inside `clientDataJSON`. That is a different computation
  from ES256, so it carries a different identifier — labelling it `-7` would be
  a lie that a conformant reader fails on with no diagnostic.

  The envelope needed to check it rides in the *unprotected* header, which the
  signature does not cover. That is safe, and deliberately so: integrity comes
  from the challenge binding. We recompute `Sig_structure`, hash it, and require
  that value to appear at `challenge_index` inside the signed `clientDataJSON`.
  Tampering with the envelope breaks verification even though its bytes are
  unsigned — which is exactly what `Sovra.Crypto.WebAuthn.valid?/3` already
  enforces for the SD-JWT key-binding JWT.

  ## Why `deviceMac` is refused

  ISO allows a MAC instead of a signature, keyed by an ECDH exchange from device
  engagement. There is no engagement in an online presentation and so no session
  key; accepting one would mean accepting something we cannot check.
  """

  alias Sovra.Cbor
  alias Sovra.Cose
  alias Sovra.Crypto.P256
  alias Sovra.Crypto.WebAuthn

  @alg_es256 -7
  # IANA assigns Private Use to integers *less than* -65536 — -65536 itself is
  # in the Specification Required band — so this is the first value we can take
  # without registering anything. `holder-core`'s COSE_ALG mirrors the literal.
  @alg_sovra_webauthn_es256 -65537

  @webauthn_label "sovra_webauthn"
  @coord_size 32

  @doc "The COSE algorithm identifier for a WebAuthn-wrapped P-256 signature."
  def alg_sovra_webauthn, do: @alg_sovra_webauthn_es256

  @doc """
  The bytes a `DeviceAuth` signature covers.

  `device_name_spaces_bytes` comes off the wire, so it may be a value with no
  deterministic CBOR encoding — a float, say. That has to fail as a rejected
  presentation rather than as an `EncodeError` raised out of the pipeline.
  """
  @spec device_authentication_bytes(list(), String.t(), term()) ::
          {:ok, binary()} | {:error, :malformed_device_auth}
  def device_authentication_bytes(session_transcript, doc_type, device_name_spaces_bytes) do
    case Cbor.safe_encode([
           "DeviceAuthentication",
           session_transcript,
           doc_type,
           device_name_spaces_bytes
         ]) do
      {:ok, inner} -> {:ok, Cbor.encode(Cbor.embed_encoded(inner))}
      {:error, _} -> {:error, :malformed_device_auth}
    end
  end

  @doc """
  Verify a `DeviceAuth` against the key the issuer bound in `MSO.deviceKey`.

  The caller has already established that this key is one the holder's account
  currently authorizes; ISO §9.1.3 requires the signature to be by *that* key,
  not by any of them.
  """
  @spec verify(term(), list(), String.t(), term(), [map()]) :: :ok | {:error, atom()}
  def verify(device_auth, session_transcript, doc_type, device_name_spaces_bytes, holder_keys) do
    with {:ok, sign1} <- device_signature(device_auth),
         {:ok, tbs} <-
           device_authentication_bytes(session_transcript, doc_type, device_name_spaces_bytes),
         # Detached: nothing is transmitted, and the verifier rebuilds what was
         # covered from its own session. A holder cannot choose it.
         to_be_signed = Cose.Sign1.to_be_signed(sign1, <<>>, tbs),
         digest = :crypto.hash(:sha256, to_be_signed) do
      do_verify(Cose.Sign1.alg(sign1), sign1, digest, holder_keys)
    end
  end

  # ── Algorithm dispatch — the seam ───────────────────────

  defp do_verify(@alg_sovra_webauthn_es256, sign1, digest, holder_keys) do
    with {:ok, assertion} <- webauthn_assertion(sign1) do
      if Enum.any?(holder_keys, &WebAuthn.valid?(digest, assertion, {&1.x, &1.y})) do
        :ok
      else
        {:error, :holder_key_mismatch}
      end
    end
  end

  defp do_verify(@alg_es256, sign1, digest, holder_keys) do
    # The standards-conformant path. It costs nothing to support now, and having
    # it here means the retrofit is a wallet change rather than a protocol one.
    case sign1.signature do
      <<r::binary-size(@coord_size), s::binary-size(@coord_size)>> ->
        if Enum.any?(holder_keys, &P256.verify(digest, %{r: r, s: s}, {&1.x, &1.y})) do
          :ok
        else
          {:error, :holder_key_mismatch}
        end

      _ ->
        {:error, :holder_key_mismatch}
    end
  end

  defp do_verify(nil, _sign1, _digest, _keys), do: {:error, :missing_device_auth_alg}
  defp do_verify(_alg, _sign1, _digest, _keys), do: {:error, :unsupported_device_auth_alg}

  # ── Structure ───────────────────────────────────────────

  defp device_signature(%{"deviceSignature" => sign1}), do: Cose.Sign1.parse(sign1)

  defp device_signature(%{"deviceMac" => _}), do: {:error, :device_mac_unsupported}

  defp device_signature(_), do: {:error, :malformed_device_auth}

  # Rebuild the assertion `Sovra.Crypto.WebAuthn` expects. `r` and `s` come from
  # the COSE signature slot; everything else from the unprotected envelope.
  defp webauthn_assertion(sign1) do
    with %{@webauthn_label => envelope} when is_map(envelope) <- sign1.unprotected,
         <<r::binary-size(@coord_size), s::binary-size(@coord_size)>> <- sign1.signature,
         {:ok, authenticator_data} <- bytes(envelope["authenticator_data"]),
         {:ok, client_data_json} <- bytes(envelope["client_data_json"]),
         challenge_index when is_integer(challenge_index) <- envelope["challenge_index"],
         type_index when is_integer(type_index) <- envelope["type_index"] do
      {:ok,
       %{
         r: r,
         s: s,
         challenge_index: challenge_index,
         type_index: type_index,
         authenticator_data: authenticator_data,
         client_data_json: client_data_json
       }}
    else
      _ -> {:error, :malformed_device_auth}
    end
  end

  defp bytes(%CBOR.Tag{tag: :bytes, value: bin}) when is_binary(bin), do: {:ok, bin}
  defp bytes(bin) when is_binary(bin), do: {:ok, bin}
  defp bytes(_), do: :error
end
