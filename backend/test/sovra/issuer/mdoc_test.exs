defmodule Sovra.Issuer.MdocTest do
  use Sovra.DataCase, async: false

  alias Sovra.Cbor
  alias Sovra.Cose
  alias Sovra.Issuer
  alias Sovra.Issuer.Mdoc
  alias Sovra.Mdoc.DocType
  alias Sovra.Mdoc.IssuerTrust
  alias Sovra.Mdoc.MetaNamespace

  setup do
    %{workspace: ws} = fixture_workspace()
    ws = provision_workspace(ws)

    {:ok, schema} =
      Issuer.create_schema(ws.id, %{
        schema_id: "membership-card",
        credential_type: "MembershipCard",
        name: "Membership Card",
        format: "mso_mdoc",
        claims: [
          %{
            "key" => "member_name",
            "type" => "string",
            "required" => true,
            "disclosable" => true
          },
          %{"key" => "joined_on", "type" => "date", "required" => false, "disclosable" => true},
          %{"key" => "visits", "type" => "integer", "required" => false, "disclosable" => true},
          %{"key" => "tier", "type" => "string", "required" => true, "disclosable" => false}
        ],
        validity_period: "1y"
      })

    claims = %{
      "member_name" => "Ada Lovelace",
      "joined_on" => "2026-01-15",
      "visits" => 12,
      "tier" => "gold"
    }

    holder_key = holder_key()

    {:ok, built} =
      Mdoc.build(ws, schema, claims, "did:sovra:0xholder", holder_key, status_list_index: 42)

    %{
      workspace: ws,
      schema: schema,
      claims: claims,
      holder_key: holder_key,
      built: built,
      issuer_signed: decode_credential(built.credential)
    }
  end

  defp holder_key do
    {:ok, %{public_key_x: x, public_key_y: y}} = Sovra.Crypto.P256.generate_key_pair()
    {x, y}
  end

  defp decode_credential(b64) do
    {:ok, bytes} = Base.url_decode64(b64, padding: false)
    {:ok, issuer_signed} = Cbor.decode(bytes)
    issuer_signed
  end

  defp mso(issuer_signed) do
    {:ok, parsed} = Cose.Sign1.parse(issuer_signed["issuerAuth"])
    {:ok, inner} = Cbor.decode(parsed.payload)
    {:ok, mso_bytes} = Cbor.unwrap_embedded(inner)
    {:ok, mso} = Cbor.decode(mso_bytes)
    {parsed, mso}
  end

  # Returns the decoded item alongside the bytes its digest is taken over —
  # the *whole* `#6.24(bstr .cbor IssuerSignedItem)` encoding, tag head
  # included, not the inner item. Re-encoding the decoded wrapper reproduces
  # those bytes exactly, since the inner value is an opaque byte string.
  defp items(issuer_signed, namespace) do
    issuer_signed["nameSpaces"]
    |> Map.fetch!(namespace)
    |> Enum.map(fn tagged ->
      {:ok, inner} = Cbor.unwrap_embedded(tagged)
      {:ok, item} = Cbor.decode(inner)
      {item, Cbor.encode(tagged)}
    end)
  end

  describe "structure" do
    test "carries the schema namespace and the Sovra meta namespace", %{
      workspace: ws,
      schema: schema,
      issuer_signed: issuer_signed
    } do
      doc_type = DocType.build(ws, schema)

      assert Map.keys(issuer_signed["nameSpaces"]) |> Enum.sort() ==
               Enum.sort([doc_type, MetaNamespace.namespace()])
    end

    test "issues one item per supplied claim", %{workspace: ws, schema: schema, issuer_signed: is} do
      ids =
        is
        |> items(DocType.build(ws, schema))
        |> Enum.map(fn {item, _} -> item["elementIdentifier"] end)
        |> Enum.sort()

      assert ids == ["joined_on", "member_name", "tier", "visits"]
    end

    test "omits a declared but unsupplied optional claim", %{workspace: ws, schema: schema} do
      {:ok, built} =
        Mdoc.build(
          ws,
          schema,
          %{"member_name" => "Ada", "tier" => "gold"},
          "did:sovra:0xh",
          holder_key(),
          status_list_index: 1
        )

      ids =
        built.credential
        |> decode_credential()
        |> items(DocType.build(ws, schema))
        |> Enum.map(fn {item, _} -> item["elementIdentifier"] end)
        |> Enum.sort()

      assert ids == ["member_name", "tier"]
    end

    test "gives each item a 16-byte salt and a unique digestID", %{
      workspace: ws,
      schema: schema,
      issuer_signed: is
    } do
      parsed = items(is, DocType.build(ws, schema))

      for {item, _} <- parsed do
        assert %CBOR.Tag{tag: :bytes, value: random} = item["random"]
        assert byte_size(random) == 16
      end

      ids = Enum.map(parsed, fn {item, _} -> item["digestID"] end)
      assert length(Enum.uniq(ids)) == length(ids)
    end
  end

  describe "MSO" do
    test "digests cover the tag-24 wrapper, not the bare item", %{
      workspace: ws,
      schema: schema,
      issuer_signed: is
    } do
      # The detail most mdoc implementations get wrong. If this ever regresses,
      # every credential we issue will look correct and fail verification.
      {_parsed, mso} = mso(is)
      doc_type = DocType.build(ws, schema)

      for {item, raw_bytes} <- items(is, doc_type) do
        %CBOR.Tag{tag: :bytes, value: expected} = mso["valueDigests"][doc_type][item["digestID"]]

        assert expected == :crypto.hash(:sha256, raw_bytes),
               "digest mismatch for #{item["elementIdentifier"]}"
      end
    end

    test "digests every namespace, including the meta one", %{issuer_signed: is} do
      {_parsed, mso} = mso(is)

      assert Map.keys(mso["valueDigests"]) |> Enum.sort() ==
               Map.keys(is["nameSpaces"]) |> Enum.sort()
    end

    test "binds the holder key from the proof, not a DID reference", %{
      holder_key: {x, y},
      issuer_signed: is
    } do
      {_parsed, mso} = mso(is)

      assert {:ok, {^x, ^y}} = Cose.Key.parse_p256(mso["deviceKeyInfo"]["deviceKey"])
    end

    test "validity runs for the schema's period, unshortened", %{issuer_signed: is} do
      {_parsed, mso} = mso(is)

      # tag 0 comes back as a DateTime: the dependency's decoder is lossy, which
      # is exactly why digests are never taken over a re-decoded value.
      %DateTime{} = signed_at = mso["validityInfo"]["signed"]
      %DateTime{} = expires_at = mso["validityInfo"]["validUntil"]

      assert mso["validityInfo"]["validFrom"] == signed_at
      assert DateTime.diff(expires_at, signed_at) == 365 * 86400
    end

    test "declares version and digest algorithm", %{issuer_signed: is} do
      {_parsed, mso} = mso(is)

      assert mso["version"] == "1.0"
      assert mso["digestAlgorithm"] == "SHA-256"
    end
  end

  describe "issuerAuth" do
    test "is an ES256 COSE_Sign1 over the workspace signing key", %{
      workspace: ws,
      issuer_signed: is
    } do
      {parsed, _mso} = mso(is)

      assert Cose.Sign1.alg(parsed) == -7

      assert :ok =
               Cose.Sign1.verify_es256(
                 parsed,
                 <<>>,
                 nil,
                 {ws.signing_public_key_x, ws.signing_public_key_y}
               )
    end

    test "carries the issuer DID in the unprotected header as a hint",
         %{workspace: ws, issuer_signed: is} do
      # Still emitted, for a reader that would rather not parse a docType. No
      # verification path reads it: `IssuerTrust.resolve/2` takes the docType,
      # which the MSO signs, and only reaches the unprotected header when the
      # docType carries no address.
      {parsed, mso} = mso(is)

      assert parsed.unprotected == %{IssuerTrust.did_label() => ws.did}

      assert {:ok, resolved, key} = IssuerTrust.resolve(Map.fetch!(mso, "docType"), parsed)
      assert resolved.id == ws.id
      assert key == {ws.signing_public_key_x, ws.signing_public_key_y}
    end

    test "issues without a DID, and the credential still names its issuer", ctx do
      # Provisioning writes the EOA before the DID and persists each step, so a
      # retry between the two leaves a workspace that can build a docType but
      # has nothing to advertise. The header is a hint, so its absence must not
      # block issuance — and the credential stays fully resolvable, because the
      # signed docType carries the address.
      {:ok, no_did} =
        ctx.workspace |> Ecto.Changeset.change(%{did: nil}) |> Sovra.Repo.update()

      assert {:ok, built} =
               Mdoc.build(
                 no_did,
                 ctx.schema,
                 ctx.claims,
                 "did:sovra:0xholder",
                 ctx.holder_key,
                 status_list_index: 42
               )

      {parsed, mso} = mso(decode_credential(built.credential))

      assert parsed.unprotected == %{}
      assert {:ok, resolved, _key} = IssuerTrust.resolve(Map.fetch!(mso, "docType"), parsed)
      assert resolved.id == no_did.id
    end

    test "does not claim an x5chain it has not got", %{issuer_signed: is} do
      # COSE header 33 is x5chain. Putting a DID there would make a conformant
      # reader try to parse it as a certificate chain — and a workspace issuing
      # under a generated docType has no certificate to put there anyway.
      {parsed, _mso} = mso(is)
      refute Map.has_key?(parsed.unprotected, IssuerTrust.x5chain_label())
    end

    test "a tampered element breaks the digest, not the signature", %{
      workspace: ws,
      schema: schema,
      issuer_signed: is
    } do
      # The signature covers the MSO, which covers digests — so editing a
      # disclosed element leaves issuerAuth valid and the digest wrong. That
      # split is exactly what a verifier has to check separately.
      {parsed, mso} = mso(is)
      doc_type = DocType.build(ws, schema)

      assert :ok =
               Cose.Sign1.verify_es256(
                 parsed,
                 <<>>,
                 nil,
                 {ws.signing_public_key_x, ws.signing_public_key_y}
               )

      [{item, _} | _] = items(is, doc_type)
      forged = Cbor.encode(Cbor.embed(Map.put(item, "elementValue", "Mallory")))

      %CBOR.Tag{tag: :bytes, value: signed_digest} =
        mso["valueDigests"][doc_type][item["digestID"]]

      refute :crypto.hash(:sha256, forged) == signed_digest
    end
  end

  describe "meta namespace" do
    test "carries the holder DID, status index and mandatory elements", %{issuer_signed: is} do
      elements =
        is
        |> items(MetaNamespace.namespace())
        |> Map.new(fn {item, _} -> {item["elementIdentifier"], item["elementValue"]} end)

      assert {:ok, meta} = MetaNamespace.extract(%{MetaNamespace.namespace() => elements})
      assert meta.holder_did == "did:sovra:0xholder"
      assert meta.status_list_index == 42
      # Keyed by namespace: an element identifier is only unique within one, so
      # a flat list could not say which namespace's `tier` it meant.
      assert meta.mandatory_elements == %{meta.namespace => ["tier"]}
      # `disclosable: false` — the holder may not withhold it.
      assert meta.mandatory_elements[meta.namespace] == ["tier"]
    end
  end

  describe "end to end through OID4VCI" do
    test "offer, token exchange and issuance deliver a signed mdoc", %{
      workspace: ws,
      schema: schema,
      claims: claims
    } do
      {:ok, offer} = Issuer.create_credential_offer(ws.id, schema.schema_id, claims)

      # The preview is JSON even though the credential will be CBOR.
      assert offer.credential["doc_type"] == DocType.build(ws, schema)

      {:ok, token} = Issuer.exchange_token(offer.pre_authorized_code)

      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} =
        Sovra.Crypto.P256.generate_key_pair()

      holder_did = "did:sovra:0xholder456"
      proof = proof_jwt(priv, x, y, holder_did, token.c_nonce)

      assert {:ok, %{credential: credential, format: "mso_mdoc"}} =
               Issuer.issue_credential(token.access_token, schema.credential_type, proof)

      issuer_signed = decode_credential(credential)
      {parsed, mso} = mso(issuer_signed)

      # Signed by the workspace, bound to the key from the proof.
      assert :ok =
               Cose.Sign1.verify_es256(
                 parsed,
                 <<>>,
                 nil,
                 {ws.signing_public_key_x, ws.signing_public_key_y}
               )

      assert {:ok, {^x, ^y}} = Cose.Key.parse_p256(mso["deviceKeyInfo"]["deviceKey"])

      # The holder DID is recoverable, which an mdoc otherwise has nowhere to put.
      meta =
        issuer_signed
        |> items(MetaNamespace.namespace())
        |> Map.new(fn {item, _} -> {item["elementIdentifier"], item["elementValue"]} end)

      assert {:ok, %{holder_did: ^holder_did}} =
               MetaNamespace.extract(%{MetaNamespace.namespace() => meta})
    end

    test "the issued row's expiry matches the credential's own validity", %{
      workspace: ws,
      schema: schema,
      claims: claims
    } do
      # These used to agree because expiry was read back out of the finished
      # SD-JWT. Now both come from one instant, so the DB row and what a
      # verifier enforces cannot drift.
      {:ok, offer} = Issuer.create_credential_offer(ws.id, schema.schema_id, claims)
      {:ok, token} = Issuer.exchange_token(offer.pre_authorized_code)

      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} =
        Sovra.Crypto.P256.generate_key_pair()

      proof = proof_jwt(priv, x, y, "did:sovra:0xholder789", token.c_nonce)

      {:ok, %{credential: credential}} =
        Issuer.issue_credential(token.access_token, schema.credential_type, proof)

      {:ok, issued} = Issuer.get_issued_credential(ws.id, offer.offer.id)
      {_parsed, mso} = credential |> decode_credential() |> mso()

      assert DateTime.compare(issued.expires_at, mso["validityInfo"]["validUntil"]) == :eq
    end

    test "a custom expiry lands in validityInfo and on the issued row", %{
      workspace: ws,
      schema: schema,
      claims: claims
    } do
      valid_until = DateTime.add(DateTime.utc_now(), 400, :day) |> DateTime.truncate(:second)

      {:ok, offer} =
        Issuer.create_credential_offer(ws.id, schema.schema_id, claims, valid_until: valid_until)

      {:ok, token} = Issuer.exchange_token(offer.pre_authorized_code)

      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} =
        Sovra.Crypto.P256.generate_key_pair()

      proof = proof_jwt(priv, x, y, "did:sovra:0xholder789", token.c_nonce)

      {:ok, %{credential: credential}} =
        Issuer.issue_credential(token.access_token, schema.credential_type, proof)

      {_parsed, mso} = credential |> decode_credential() |> mso()

      # Overrides the schema's year, and validFrom still marks the signing
      # instant — only the far end of the window moves.
      assert DateTime.compare(mso["validityInfo"]["validUntil"], valid_until) == :eq
      assert mso["validityInfo"]["validFrom"] == mso["validityInfo"]["signed"]

      {:ok, issued} = Issuer.get_issued_credential(ws.id, offer.offer.id)
      assert DateTime.compare(issued.expires_at, valid_until) == :eq
    end

    test "rejects a value with no deterministic CBOR encoding at offer time", %{
      workspace: ws,
      schema: schema,
      claims: claims
    } do
      # Caught here rather than surfacing as a 500 mid-wallet-flow.
      assert {:error, {:unencodable_claims, ["visits"]}} =
               Issuer.create_credential_offer(
                 ws.id,
                 schema.schema_id,
                 Map.put(claims, "visits", "not-a-number")
               )
    end
  end

  defp proof_jwt(priv, x, y, holder_did, nonce) do
    header = %{
      "typ" => "openid4vci-proof+jwt",
      "alg" => "ES256",
      "jwk" => %{
        "kty" => "EC",
        "crv" => "P-256",
        "x" => Base.url_encode64(x, padding: false),
        "y" => Base.url_encode64(y, padding: false)
      }
    }

    payload = %{"iss" => holder_did, "nonce" => nonce}

    header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
    payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
    signing_input = "#{header_b64}.#{payload_b64}"

    {:ok, %{r: r, s: s}} = Sovra.Crypto.P256.sign(:crypto.hash(:sha256, signing_input), priv)
    raw_sig = Sovra.Crypto.P256.pad_or_trim(r, 32) <> Sovra.Crypto.P256.pad_or_trim(s, 32)

    %{
      "proof_type" => "jwt",
      "jwt" => "#{signing_input}.#{Base.url_encode64(raw_sig, padding: false)}"
    }
  end

  describe "mandatory elements" do
    test "lists only elements the issuer actually supplied", %{workspace: ws, schema: schema} do
      # `tier` is disclosable: false but not required. Omitting it must not put
      # it in the mandatory set — a credential listing an element it does not
      # carry issues cleanly and then fails every verification.
      {:ok, built} =
        Mdoc.build(
          ws,
          schema,
          %{"member_name" => "Ada"},
          "did:sovra:0xh",
          holder_key(),
          status_list_index: 1
        )

      meta =
        built.credential
        |> decode_credential()
        |> items(MetaNamespace.namespace())
        |> Map.new(fn {item, _} -> {item["elementIdentifier"], item["elementValue"]} end)

      assert {:ok, %{mandatory_elements: mandatory, namespace: namespace}} =
               MetaNamespace.extract(%{MetaNamespace.namespace() => meta})

      assert mandatory == %{namespace => []}
    end

    test "still lists a supplied non-disclosable element", %{issuer_signed: is} do
      meta =
        is
        |> items(MetaNamespace.namespace())
        |> Map.new(fn {item, _} -> {item["elementIdentifier"], item["elementValue"]} end)

      assert {:ok, %{mandatory_elements: mandatory, namespace: namespace}} =
               MetaNamespace.extract(%{MetaNamespace.namespace() => meta})

      assert mandatory == %{namespace => ["tier"]}
    end
  end

  describe "build_preview/4" do
    test "is plain JSON, not CBOR", %{workspace: ws, schema: schema, claims: claims} do
      preview = Mdoc.build_preview(ws, schema, claims, status_list_index: 42)

      assert preview["doc_type"] == DocType.build(ws, schema)
      assert preview["member_name"] == "Ada Lovelace"
      assert is_integer(preview["iat"])
      assert preview["exp"] - preview["iat"] == 365 * 86400

      # It must survive Jason — the dashboard and Sovra Gov render it directly.
      assert {:ok, _} = Jason.encode(preview)
    end

    test "describes revocation the same way the SD-JWT preview does", %{
      workspace: ws,
      schema: schema,
      claims: claims
    } do
      preview = Mdoc.build_preview(ws, schema, claims, status_list_index: 42)

      assert [%{"statusPurpose" => "revocation"}, %{"statusPurpose" => "suspension"}] =
               preview["credentialStatus"]
    end
  end

  describe "the certificate route" do
    setup %{workspace: ws, claims: claims, holder_key: holder_key} do
      %{workspace: ws, document_signer: signer, iaca: iaca} =
        SovraTest.MdlCertificates.provision_document_signer(ws)

      {:ok, schema} =
        Issuer.create_schema(ws.id, %{
          schema_id: "drivers-licence",
          credential_type: "DrivingLicence",
          name: "Driving Licence",
          format: "mso_mdoc",
          doc_type: "org.iso.18013.5.1.mDL",
          namespace: "org.iso.18013.5.1",
          claims: [
            %{
              "key" => "family_name",
              "type" => "string",
              "required" => true,
              "disclosable" => true
            },
            # Not `tier`: `org.iso.18013.5.1` is a closed element set, and an
            # element ISO does not define belongs in a namespace beside it.
            %{
              "key" => "document_number",
              "type" => "string",
              "required" => true,
              "disclosable" => false
            }
          ],
          validity_period: "1y"
        })

      {:ok, built} =
        Mdoc.build(
          ws,
          schema,
          %{"family_name" => "Lovelace", "document_number" => "D-1234567"},
          "did:sovra:0xholder",
          holder_key,
          status_list_index: 42
        )

      %{
        workspace: ws,
        schema: schema,
        document_signer: signer,
        iaca: iaca,
        issuer_signed: decode_credential(built.credential)
      }
    end

    test "signs with the key the certificate names, not the workspace's own", %{
      workspace: ws,
      issuer_signed: is
    } do
      # The whole point of a separate document signer key. Signing an ISO
      # docType with the SD-JWT key would produce a credential whose `x5chain`
      # describes a key that did not sign it — valid-looking, and rejected by
      # every reader that checks.
      {parsed, _mso} = mso(is)

      assert :ok =
               Cose.Sign1.verify_es256(
                 parsed,
                 <<>>,
                 nil,
                 {ws.mdl_signing_public_key_x, ws.mdl_signing_public_key_y}
               )

      refute :ok ==
               Cose.Sign1.verify_es256(
                 parsed,
                 <<>>,
                 nil,
                 {ws.signing_public_key_x, ws.signing_public_key_y}
               )
    end

    test "carries the document signer certificate in x5chain", %{
      document_signer: signer,
      issuer_signed: is
    } do
      # RFC 9360: a single certificate travels as a bare byte string rather than
      # as a one-element array. Both forms are read back, but only one is
      # emitted — there is no reason to make a reader handle our choice of
      # spelling.
      {parsed, _mso} = mso(is)

      assert %CBOR.Tag{tag: :bytes, value: der} =
               Map.fetch!(parsed.unprotected, IssuerTrust.x5chain_label())

      assert der == signer.der
    end

    test "does not advertise a DID beside the chain", %{issuer_signed: is} do
      # The chain is the answer on this route. A second, weaker copy of the same
      # fact is one a reader could believe instead.
      {parsed, _mso} = mso(is)
      refute Map.has_key?(parsed.unprotected, IssuerTrust.did_label())
    end

    test "puts the ISO docType in the MSO and the elements in the ISO namespace", %{
      issuer_signed: is
    } do
      {_parsed, mso} = mso(is)

      assert Map.fetch!(mso, "docType") == "org.iso.18013.5.1.mDL"
      assert Map.has_key?(is["nameSpaces"], "org.iso.18013.5.1")
      refute Map.has_key?(is["nameSpaces"], "org.iso.18013.5.1.mDL")
    end

    test "resolves back to the issuing workspace through the chain", %{
      workspace: ws,
      issuer_signed: is
    } do
      {parsed, mso} = mso(is)

      assert {:ok, resolved, key} = IssuerTrust.resolve(Map.fetch!(mso, "docType"), parsed)
      assert resolved.id == ws.id
      assert key == {ws.mdl_signing_public_key_x, ws.mdl_signing_public_key_y}
    end

    test "does not resolve once the chain is stripped", %{issuer_signed: is} do
      # An ISO docType names nobody. Without the chain there is nothing left to
      # resolve, which is the failure a reader should see — not a fallback to
      # some other way of guessing the issuer.
      {parsed, mso} = mso(is)

      assert {:error, :unknown_issuer} =
               IssuerTrust.resolve(Map.fetch!(mso, "docType"), %{parsed | unprotected: %{}})
    end

    test "does not resolve through a chain from an unadmitted root", %{issuer_signed: is} do
      # A self-signed root and a certificate under it are structurally
      # indistinguishable from a real pair — anyone can mint both. What makes
      # the difference is whether a platform admin admitted the root.
      {{x, y}, _private} = SovraTest.MdlCertificates.keypair_point()
      stranger_root = SovraTest.MdlCertificates.iaca()
      stranger = SovraTest.MdlCertificates.document_signer(stranger_root, {x, y})

      {parsed, mso} = mso(is)

      substituted = %{
        parsed
        | unprotected: %{IssuerTrust.x5chain_label() => Cbor.bstr(stranger.der)}
      }

      assert {:error, :unknown_issuer} =
               IssuerTrust.resolve(Map.fetch!(mso, "docType"), substituted)
    end
  end

  describe "issuing under an ISO docType without a document signer" do
    test "is refused at schema creation", %{workspace: ws} do
      # The operator chose the docType, so the operator is who should hear
      # about it — not the citizen whose issuance fails months later.
      assert {:error, :document_signer_required} =
               Issuer.create_schema(ws.id, %{
                 schema_id: "premature-licence",
                 credential_type: "DrivingLicence",
                 name: "Driving Licence",
                 format: "mso_mdoc",
                 doc_type: "org.iso.18013.5.1.mDL",
                 namespace: "org.iso.18013.5.1",
                 claims: [
                   %{
                     "key" => "family_name",
                     "type" => "string",
                     "required" => true,
                     "disclosable" => true
                   }
                 ],
                 validity_period: "1y"
               })
    end

    test "is refused at signing time too", %{
      workspace: ws,
      schema: schema,
      claims: claims,
      holder_key: holder_key
    } do
      # The last line, reached by writing the docType straight onto a schema.
      # Falling back to the workspace's own key here would issue a credential
      # that no verifier can attribute to anyone.
      iso_schema = %{schema | doc_type: "org.iso.18013.5.1.mDL"}

      assert {:error, :document_signer_required} =
               Mdoc.build(ws, iso_schema, claims, "did:sovra:0xholder", holder_key,
                 status_list_index: 42
               )
    end
  end
end
