defmodule SovraTest.MdocBuilder do
  @moduledoc """
  A wallet simulator: turns an issued `IssuerSigned` into a signed
  `DeviceResponse`, with selective disclosure.

  Exists so the verification pipeline can be tested against something a holder
  would actually send, rather than against a fixture written to match the
  verifier. It deliberately mirrors `holder-core`'s `buildDeviceResponse` —
  including the session transcript — so a divergence between the two shows up
  as a failing test here rather than in the field.

  Both device-auth algorithms are supported. The WebAuthn path is what the
  wallet ships today; the raw ES256 path is the standards-conformant one the
  retrofit will switch to, and testing both is what proves the seam works.
  """

  alias Sovra.Cbor
  alias Sovra.Cose
  alias Sovra.Crypto.P256
  alias Sovra.Mdoc.DeviceAuth
  alias Sovra.Mdoc.SessionTranscript

  import Bitwise, only: [|||: 2]

  @doc """
  Build a `DeviceResponse` from an issued credential.

  Options:
    * `:disclose` — element identifiers to include; defaults to all of them
    * `:alg` — `:webauthn` (default) or `:es256`
    * `:transcript` — override the session transcript, to simulate a wallet
      that bound to a different verifier
    * `:tamper` — `{element_identifier, new_value}`, to alter a disclosed
      element after the issuer signed it
    * `:issuer_header` — `:strip`, or a map to substitute, for the `IssuerAuth`
      unprotected header. The issuer's signature does not cover it, so anything
      in transit can rewrite it — no verification path may depend on it.
    * `:doc_type` — override the *document's* docType, leaving the signed MSO's
      alone, to simulate a holder claiming a different issuer
    * `:mso` — `{signing_key_id, fun}`, to rewrite the MSO and re-sign it with
      the issuer's real key. For MSO-level checks whose input our own issuer
      cannot produce: a credential is only reachable through `Issuer.Mdoc.build`,
      but a verifier's input is whatever a holder sends. The digests and
      `nameSpaces` are untouched, so `check_value_digests/3` still passes and
      the check under test is the one that fails.
  """
  def build_device_response(issuer_signed_b64, session, holder, opts \\ []) do
    issuer_signed = decode(issuer_signed_b64)
    doc_type = doc_type_of(issuer_signed)

    name_spaces =
      issuer_signed
      |> Map.fetch!("nameSpaces")
      |> filter_disclosed(Keyword.get(opts, :disclose))
      |> apply_tamper(Keyword.get(opts, :tamper))

    device_name_spaces_bytes = Cbor.embed(%{})

    transcript = Keyword.get(opts, :transcript) || SessionTranscript.build(session)

    to_be_signed =
      device_to_be_signed(transcript, doc_type, device_name_spaces_bytes, opts)

    device_signature = sign_device_auth(to_be_signed, holder, opts)

    issuer_auth =
      issuer_signed
      |> Map.fetch!("issuerAuth")
      |> apply_mso(Keyword.get(opts, :mso))
      |> apply_issuer_header(Keyword.get(opts, :issuer_header))

    response = %{
      "version" => "1.0",
      "status" => 0,
      "documents" => [
        %{
          "docType" => Keyword.get(opts, :doc_type) || doc_type,
          "issuerSigned" => %{
            "nameSpaces" => name_spaces,
            "issuerAuth" => issuer_auth
          },
          "deviceSigned" => %{
            "nameSpaces" => device_name_spaces_bytes,
            "deviceAuth" => %{"deviceSignature" => device_signature}
          }
        }
      ]
    }

    Base.url_encode64(Cbor.encode(response), padding: false)
  end

  @doc "A P-256 key pair in the shape the DID resolver stubs return."
  def holder_key do
    {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()
    %{private_key: priv, x: x, y: y}
  end

  # ── Internals ───────────────────────────────────────────

  defp decode(b64) do
    {:ok, bytes} = Base.url_decode64(b64, padding: false)
    {:ok, decoded} = Cbor.decode(bytes)
    decoded
  end

  defp apply_mso(issuer_auth, nil), do: issuer_auth

  defp apply_mso(issuer_auth, {signing_key_id, fun}) do
    {:ok, sign1} = Cose.Sign1.parse(issuer_auth)
    {:ok, wrapper} = Cbor.decode(sign1.payload)
    {:ok, mso_bytes} = Cbor.unwrap_embedded(wrapper)
    {:ok, mso} = Cbor.decode(mso_bytes)

    {:ok, resigned} =
      Cose.Sign1.sign(
        signing_key_id,
        %{1 => Cose.Sign1.alg_es256()},
        sign1.unprotected,
        Cbor.encode(Cbor.embed(fun.(mso)))
      )

    resigned
  end

  defp apply_issuer_header(issuer_auth, nil), do: issuer_auth

  defp apply_issuer_header([protected, _unprotected, payload, signature], :strip),
    do: [protected, %{}, payload, signature]

  defp apply_issuer_header([protected, _unprotected, payload, signature], header)
       when is_map(header),
       do: [protected, header, payload, signature]

  defp doc_type_of(issuer_signed) do
    {:ok, sign1} = Cose.Sign1.parse(Map.fetch!(issuer_signed, "issuerAuth"))
    {:ok, wrapper} = Cbor.decode(sign1.payload)
    {:ok, mso_bytes} = Cbor.unwrap_embedded(wrapper)
    {:ok, mso} = Cbor.decode(mso_bytes)
    Map.fetch!(mso, "docType")
  end

  defp filter_disclosed(name_spaces, nil), do: name_spaces

  defp filter_disclosed(name_spaces, disclose) do
    Map.new(name_spaces, fn {namespace, items} ->
      kept =
        Enum.filter(items, fn tagged ->
          # The Sovra meta namespace is not the holder's to withhold: the
          # verifier requires it, so a wallet always sends it.
          namespace == Sovra.Mdoc.MetaNamespace.namespace() or
            element_identifier(tagged) in disclose
        end)

      {namespace, kept}
    end)
  end

  defp apply_tamper(name_spaces, nil), do: name_spaces

  defp apply_tamper(name_spaces, {target, new_value}) do
    Map.new(name_spaces, fn {namespace, items} ->
      {namespace,
       Enum.map(items, fn tagged ->
         if element_identifier(tagged) == target do
           Cbor.embed(Map.put(decode_item(tagged), "elementValue", new_value))
         else
           tagged
         end
       end)}
    end)
  end

  defp element_identifier(tagged), do: Map.get(decode_item(tagged), "elementIdentifier")

  defp decode_item(tagged) do
    {:ok, raw} = Cbor.unwrap_embedded(tagged)
    {:ok, item} = Cbor.decode(raw)
    item
  end

  defp device_to_be_signed(transcript, doc_type, device_name_spaces_bytes, opts) do
    protected = %{1 => alg_value(opts)}

    {:ok, tbs} =
      DeviceAuth.device_authentication_bytes(transcript, doc_type, device_name_spaces_bytes)

    Cbor.encode([
      "Signature1",
      Cbor.bstr(Cbor.encode(protected)),
      Cbor.bstr(<<>>),
      Cbor.bstr(tbs)
    ])
  end

  defp sign_device_auth(to_be_signed, holder, opts) do
    digest = :crypto.hash(:sha256, to_be_signed)
    protected = Cbor.encode(%{1 => alg_value(opts)})

    case Keyword.get(opts, :alg, :webauthn) do
      :es256 ->
        {:ok, %{r: r, s: s}} = P256.sign(digest, holder.private_key)
        cose_sign1(protected, %{}, pad(r) <> pad(s))

      :webauthn ->
        {assertion, signature} = webauthn_assertion(digest, holder)
        cose_sign1(protected, assertion, signature)
    end
  end

  defp alg_value(opts) do
    case Keyword.get(opts, :alg, :webauthn) do
      :es256 -> Cose.Sign1.alg_es256()
      :webauthn -> DeviceAuth.alg_sovra_webauthn()
      other -> other
    end
  end

  # Builds a real WebAuthn assertion over `digest`: the authenticator signs
  # authenticator_data || SHA-256(client_data_json), with the digest carried as
  # the base64url challenge inside client_data_json.
  defp webauthn_assertion(digest, holder) do
    challenge = Base.url_encode64(digest, padding: false)

    client_data_json =
      ~s({"type":"webauthn.get","challenge":"#{challenge}","origin":"https://sovra.io"})

    challenge_index = :binary.match(client_data_json, ~s("challenge":)) |> elem(0)
    type_index = :binary.match(client_data_json, ~s("type":)) |> elem(0)

    # rpIdHash || flags (UP|UV|BE) || counter
    authenticator_data = :binary.copy(<<0>>, 32) <> <<0x01 ||| 0x04 ||| 0x08>> <> <<0::32>>

    signed = :crypto.hash(:sha256, authenticator_data <> :crypto.hash(:sha256, client_data_json))
    {:ok, %{r: r, s: s}} = P256.sign(signed, holder.private_key)

    envelope = %{
      "sovra_webauthn" => %{
        "authenticator_data" => Cbor.bstr(authenticator_data),
        "client_data_json" => Cbor.bstr(client_data_json),
        "challenge_index" => challenge_index,
        "type_index" => type_index
      }
    }

    {envelope, pad(r) <> pad(s)}
  end

  defp cose_sign1(protected, unprotected, signature) do
    [Cbor.bstr(protected), unprotected, nil, Cbor.bstr(signature)]
  end

  defp pad(bin), do: P256.pad_or_trim(bin, 32)
end
