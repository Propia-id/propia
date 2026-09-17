defmodule Sovra.Verification.MdocVerifierTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Cbor
  alias Sovra.Issuer
  alias Sovra.Mdoc.DocType
  alias Sovra.Mdl.Template
  alias Sovra.Mdoc.IssuerTrust
  alias Sovra.Mdoc.SessionTranscript
  alias Sovra.Verification
  alias Sovra.Verification.RequestObject
  alias SovraTest.MdocBuilder

  # ── Stubs, matching the SD-JWT suite's shape ────────────

  defmodule StubRegistryOk do
    def is_revoked(_addr, _idx), do: {:ok, false}
    def is_suspended(_addr, _idx), do: {:ok, false}
  end

  defmodule StubRegistryRevoked do
    def is_revoked(_addr, _idx), do: {:ok, true}
    def is_suspended(_addr, _idx), do: {:ok, false}
  end

  defmodule StubRegistrySuspended do
    def is_revoked(_addr, _idx), do: {:ok, false}
    def is_suspended(_addr, _idx), do: {:ok, true}
  end

  defmodule StubResolver do
    def resolve(_did), do: {:ok, Process.get(:holder_keys, [])}
  end

  setup do
    %{workspace: issuer_ws} = fixture_workspace()
    issuer_ws = provision_workspace(issuer_ws)

    %{workspace: verifier_ws} = fixture_workspace()
    verifier_ws = provision_workspace(verifier_ws)

    {:ok, schema} =
      Issuer.create_schema(issuer_ws.id, %{
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
          %{"key" => "visits", "type" => "integer", "required" => false, "disclosable" => true},
          %{"key" => "tier", "type" => "string", "required" => true, "disclosable" => false}
        ],
        validity_period: "1y"
      })

    holder = MdocBuilder.holder_key()
    Process.put(:holder_keys, [%{x: holder.x, y: holder.y}])

    claims = %{"member_name" => "Ada Lovelace", "visits" => 12, "tier" => "gold"}

    {:ok, credential} =
      Sovra.Issuer.Mdoc.build(
        issuer_ws,
        schema,
        claims,
        "did:sovra:0xholder",
        {holder.x, holder.y},
        status_list_index: 42
      )

    doc_type = DocType.build(issuer_ws, schema)

    %{
      issuer_ws: issuer_ws,
      verifier_ws: verifier_ws,
      schema: schema,
      holder: holder,
      credential: credential.credential,
      doc_type: doc_type
    }
  end

  defp query(doc_type, elements) do
    %{
      "credentials" => [
        %{
          "id" => "membership",
          "format" => "mso_mdoc",
          "meta" => %{"doctype_value" => doc_type},
          "claims" => Enum.map(elements, &%{"path" => [doc_type, &1]})
        }
      ]
    }
  end

  defp present(ctx, opts) do
    # The per-test option wins, then whatever the describe block's setup put on
    # the context — an ISO credential's claim paths use its namespace, which is
    # not its docType.
    dcql =
      Keyword.get(opts, :query) || Map.get(ctx, :query) || query(ctx.doc_type, ["member_name"])

    {:ok, %{session: session}} = Verification.create_session(ctx.verifier_ws.id, dcql)

    vp =
      MdocBuilder.build_device_response(
        ctx.credential,
        session,
        Keyword.get(opts, :holder, ctx.holder),
        Keyword.take(opts, [
          :disclose,
          :alg,
          :transcript,
          :tamper,
          :issuer_header,
          :doc_type,
          :mso
        ])
      )

    # OID4VP 1.0 keys the vp_token by DCQL credential id, same as SD-JWT.
    envelope = Jason.encode!(%{hd(dcql["credentials"])["id"] => vp})

    Verification.submit_presentation(session.state, envelope,
      revocation_registry: Keyword.get(opts, :registry, StubRegistryOk),
      did_resolver: StubResolver
    )
  end

  describe "happy path" do
    test "completes and records the disclosed claims", ctx do
      assert {:ok, session} = present(ctx, disclose: ["member_name", "tier"])

      assert session.status == "completed"
      assert session.holder_did == "did:sovra:0xholder"

      assert %{"credentials" => [credential]} = session.presentation_data
      assert credential["format"] == "mso_mdoc"
      assert credential["claims"]["#{ctx.doc_type}.member_name"] == "Ada Lovelace"
    end

    test "presentation_data survives JSON encoding", ctx do
      # It lands in a jsonb column, so a CBOR tag or DateTime reaching
      # Repo.insert would raise inside the transaction that finalizes the
      # session — this is required, not cosmetic.
      {:ok, session} = present(ctx, disclose: ["member_name", "tier"])
      assert {:ok, _} = Jason.encode(session.presentation_data)
    end

    test "enqueues the presentation.verified webhook", ctx do
      {:ok, _} = present(ctx, disclose: ["member_name", "tier"])

      assert_enqueued(
        worker: Sovra.Webhooks.DeliveryJob,
        args: %{"event" => "presentation.verified"}
      )
    end

    test "accepts a raw ES256 device signature", ctx do
      # The standards-conformant path the retrofit will switch to. Supporting
      # it now is what proves the alg dispatch is a real seam.
      assert {:ok, session} = present(ctx, disclose: ["member_name", "tier"], alg: :es256)
      assert session.status == "completed"
    end
  end

  describe "selective disclosure" do
    test "withholding an optional element leaves the credential valid", ctx do
      # Disclosure is subtractive: the issuer signed a digest per element, so
      # omitting one is free and issuerAuth still verifies.
      assert {:ok, session} = present(ctx, disclose: ["member_name", "tier"])
      assert session.status == "completed"

      refute Map.has_key?(
               session.presentation_data["credentials"] |> hd() |> Map.get("claims"),
               "#{ctx.doc_type}.visits"
             )
    end

    test "omitting a mandatory element is rejected", ctx do
      # `tier` is disclosable: false, frozen into the credential at issuance.
      assert {:ok, session} = present(ctx, disclose: ["member_name"])

      assert session.status == "failed"
      assert session.error == "missing_mandatory_element:#{ctx.doc_type}.tier"
    end

    test "a requested element that was not disclosed is rejected", ctx do
      assert {:ok, session} =
               present(ctx,
                 query: query(ctx.doc_type, ["visits"]),
                 disclose: ["member_name", "tier"]
               )

      assert session.status == "failed"
      assert session.error == "missing_required_claim:#{ctx.doc_type}.visits"
    end
  end

  describe "integrity" do
    test "a tampered element breaks its digest", ctx do
      # issuerAuth still verifies — the signature covers the MSO, which covers
      # digests — so this has to be caught by re-hashing, not by the signature.
      assert {:ok, session} =
               present(ctx, disclose: ["member_name", "tier"], tamper: {"member_name", "Mallory"})

      assert session.status == "failed"
      assert session.error == "invalid_disclosure"
    end

    test "verifies with the issuer's unprotected header stripped", ctx do
      # The header is a hint, not evidence: the issuer's signature does not
      # cover it, so anything in transit can drop it. The issuer is resolved
      # from the signed docType, so verification must not notice.
      assert {:ok, session} =
               present(ctx, disclose: ["member_name", "tier"], issuer_header: :strip)

      assert session.status == "completed"
    end

    test "verifies with another workspace's DID forged into the header", ctx do
      # Same reason. If this ever starts failing, something has begun trusting
      # an unsigned field again.
      other = fixture_workspace().workspace |> provision_workspace()

      assert {:ok, session} =
               present(ctx,
                 disclose: ["member_name", "tier"],
                 issuer_header: %{IssuerTrust.did_label() => other.did}
               )

      assert session.status == "completed"
    end

    test "a docType naming another workspace is rejected", ctx do
      # The docType selects which key to check, so claiming another issuer's
      # docType gets the signature verified against that issuer's key.
      other = fixture_workspace().workspace |> provision_workspace()

      assert {:ok, session} =
               present(ctx,
                 disclose: ["member_name", "tier"],
                 doc_type: DocType.issuer_prefix(other) <> "membership-card.1"
               )

      assert session.status == "failed"
      assert session.error == "credential_signature_invalid"
    end

    test "an inverted validity window is rejected", ctx do
      # 18013-5 requires `validUntil` to be later than `validFrom`. There is no
      # dedicated check for it because the window checks already imply it — they
      # require `validFrom <= now < validUntil` — and this pins that, so nobody
      # adds a third comparison that can never fire.
      #
      # Our own issuer cannot produce this: it sets `validFrom` to now and
      # derives `validUntil` from the schema. A verifier's input is whatever a
      # holder sends, so the MSO is rewritten and re-signed with the issuer's
      # real key, leaving the digests untouched.
      assert {:ok, session} =
               present(ctx,
                 disclose: ["member_name", "tier"],
                 mso:
                   {ctx.issuer_ws.signing_key_id,
                    fn mso ->
                      validity = Map.fetch!(mso, "validityInfo")
                      now = DateTime.utc_now() |> DateTime.truncate(:second)

                      Map.put(
                        mso,
                        "validityInfo",
                        validity
                        |> Map.put("validFrom", Cbor.tdate(DateTime.add(now, 3600, :second)))
                        |> Map.put("validUntil", Cbor.tdate(DateTime.add(now, 60, :second)))
                      )
                    end}
               )

      assert session.status == "failed"
      assert session.error == "credential_expired"
    end

    test "the same credential verifies with the window the right way round", ctx do
      # Guards the test above: without this, an assertion that a re-signed MSO
      # is rejected would pass even if re-signing itself were broken.
      assert {:ok, session} =
               present(ctx,
                 disclose: ["member_name", "tier"],
                 mso: {ctx.issuer_ws.signing_key_id, & &1}
               )

      assert session.status == "completed"
    end

    test "a docType naming no known issuer is rejected", ctx do
      assert {:ok, session} =
               present(ctx,
                 disclose: ["member_name", "tier"],
                 doc_type: "io.sovra.0x000000000000000000000000000000000000dead.card.1"
               )

      assert session.status == "failed"
      assert session.error == "unknown_issuer"
    end

    test "a query for a different doctype is rejected", ctx do
      dcql = %{
        "credentials" => [
          %{
            "id" => "membership",
            "format" => "mso_mdoc",
            "meta" => %{"doctype_value" => "io.sovra.0xdead.other.1"},
            "claims" => [%{"path" => [ctx.doc_type, "member_name"]}]
          }
        ]
      }

      assert {:ok, session} = present(ctx, query: dcql, disclose: ["member_name", "tier"])
      assert session.status == "failed"
      assert session.error == "doctype_mismatch"
    end
  end

  describe "holder binding" do
    test "a device key that is not currently authorized is rejected", ctx do
      # Trusting MSO.deviceKey alone would be ISO-native and would drop the
      # chain binding: a rotated-away passkey would keep working forever.
      other = MdocBuilder.holder_key()
      Process.put(:holder_keys, [%{x: other.x, y: other.y}])

      assert {:ok, session} = present(ctx, disclose: ["member_name", "tier"])
      assert session.status == "failed"
      assert session.error == "holder_key_mismatch"
    end

    test "a presentation signed by another authorized key is rejected", ctx do
      # ISO §9.1.3 binds the signature to `MSO.deviceKey`. Both keys here are
      # currently authorized, so the binding is the only thing separating them.
      other = MdocBuilder.holder_key()

      Process.put(:holder_keys, [
        %{x: ctx.holder.x, y: ctx.holder.y},
        %{x: other.x, y: other.y}
      ])

      assert {:ok, session} =
               present(ctx, disclose: ["member_name", "tier"], holder: other)

      assert session.status == "failed"
      assert session.error == "holder_key_mismatch"
    end

    test "an unresolvable holder DID is rejected", ctx do
      Process.put(:holder_keys, [])

      assert {:ok, session} = present(ctx, disclose: ["member_name", "tier"])
      assert session.status == "failed"
      assert session.error == "holder_did_unresolvable"
    end
  end

  describe "session binding" do
    test "a presentation bound to another verifier is rejected", ctx do
      # The nonce and client_id live inside the transcript, so a mismatch
      # surfaces as a signature failure rather than a distinct claim check.
      foreign =
        SessionTranscript.from_parts(
          "verifier:someone-else",
          "some-nonce",
          "https://elsewhere.example/post"
        )

      assert {:ok, session} =
               present(ctx, disclose: ["member_name", "tier"], transcript: foreign)

      assert session.status == "failed"
      assert session.error == "holder_key_mismatch"
    end

    test "a stale nonce is rejected", ctx do
      stale =
        SessionTranscript.from_parts(
          RequestObject.client_id(ctx.verifier_ws),
          "a-nonce-from-an-older-session",
          "https://api.example/post"
        )

      assert {:ok, session} = present(ctx, disclose: ["member_name", "tier"], transcript: stale)
      assert session.status == "failed"
      assert session.error == "holder_key_mismatch"
    end
  end

  describe "status and validity" do
    test "a revoked credential is rejected", ctx do
      assert {:ok, session} =
               present(ctx, disclose: ["member_name", "tier"], registry: StubRegistryRevoked)

      assert session.status == "failed"
      assert session.error == "credential_revoked"
    end

    test "a suspended credential is rejected", ctx do
      assert {:ok, session} =
               present(ctx, disclose: ["member_name", "tier"], registry: StubRegistrySuspended)

      assert session.status == "failed"
      assert session.error == "credential_suspended"
    end
  end

  describe "malformed input" do
    test "a non-CBOR vp_token is rejected", ctx do
      {:ok, %{session: session}} =
        Verification.create_session(ctx.verifier_ws.id, query(ctx.doc_type, ["member_name"]))

      vp = Jason.encode!(%{"membership" => "not-cbor-at-all"})

      assert {:ok, s} =
               Verification.submit_presentation(session.state, vp,
                 revocation_registry: StubRegistryOk,
                 did_resolver: StubResolver
               )

      assert s.status == "failed"
      assert s.error == "malformed_vp_token"
    end

    test "a DeviceResponse with no meta namespace is rejected", ctx do
      # The meta namespace carries enforcement inputs supplied by the party
      # being enforced against, so an incomplete one is a hard failure.
      {:ok, %{session: session}} =
        Verification.create_session(ctx.verifier_ws.id, query(ctx.doc_type, ["member_name"]))

      vp = Jason.encode!(%{"membership" => strip_meta_namespace(ctx, session)})

      assert {:ok, s} =
               Verification.submit_presentation(session.state, vp,
                 revocation_registry: StubRegistryOk,
                 did_resolver: StubResolver
               )

      assert s.status == "failed"
      assert String.starts_with?(s.error, "missing_mandatory_element:io.sovra.meta.1")
    end
  end

  # ── The certificate route ──────────────────────────────
  #
  # Everything above resolves the issuer from the address in a generated
  # docType. An ISO docType carries no address, so these run the same pipeline
  # over the other route: the `x5chain` leaf names the key, and the key names
  # the workspace.
  describe "an ISO docType, trusted through its certificate chain" do
    setup ctx do
      %{workspace: issuer_ws, iaca: iaca} =
        SovraTest.MdlCertificates.provision_document_signer(ctx.issuer_ws)

      {:ok, schema} =
        Issuer.create_schema(issuer_ws.id, %{
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

      {:ok, credential} =
        Sovra.Issuer.Mdoc.build(
          issuer_ws,
          schema,
          %{"family_name" => "Lovelace", "document_number" => "D-1234567"},
          "did:sovra:0xholder",
          {ctx.holder.x, ctx.holder.y},
          status_list_index: 42
        )

      %{
        issuer_ws: issuer_ws,
        schema: schema,
        iaca: iaca,
        credential: credential.credential,
        doc_type: "org.iso.18013.5.1.mDL",
        query: iso_query(["family_name"])
      }
    end

    test "verifies end to end, and the claims come back namespace-keyed", ctx do
      assert {:ok, session} = present(ctx, disclose: ["family_name", "document_number"])

      assert session.status == "completed"

      assert %{"credentials" => [credential]} = session.presentation_data
      assert credential["claims"]["org.iso.18013.5.1.family_name"] == "Lovelace"
    end

    test "is rejected once the chain is stripped", ctx do
      # The unprotected header is the only copy of the answer on this route, and
      # nothing protects it in transit. Losing it has to fail as "we cannot tell
      # who issued this", never as a fallback to some other way of guessing.
      assert {:ok, session} =
               present(ctx, disclose: ["family_name", "document_number"], issuer_header: :strip)

      assert session.status == "failed"
      assert session.error == "unknown_issuer"
    end

    test "is rejected when the chain comes from a root nobody admitted", ctx do
      # A self-signed root and a certificate under it are structurally
      # indistinguishable from the real pair — minting both takes a minute. What
      # separates them is a platform admin having admitted the root.
      {{x, y}, _private} = SovraTest.MdlCertificates.keypair_point()
      stranger_root = SovraTest.MdlCertificates.iaca()
      stranger = SovraTest.MdlCertificates.document_signer(stranger_root, {x, y})

      assert {:ok, session} =
               present(ctx,
                 disclose: ["family_name", "document_number"],
                 issuer_header: x5chain(stranger.der)
               )

      assert session.status == "failed"
      assert session.error == "unknown_issuer"
    end

    test "is rejected once the document signer certificate has expired", ctx do
      # The failure registration cannot catch, and the reason the chain is
      # re-validated at verification time rather than trusted because we checked
      # it once. The certificate is for the right key and from the admitted
      # root, so the signature still verifies — Annex B caps it at 457 days and
      # this one is past its window, which is the whole of what is wrong.
      expired =
        SovraTest.MdlCertificates.document_signer(
          ctx.iaca,
          {ctx.issuer_ws.mdl_signing_public_key_x, ctx.issuer_ws.mdl_signing_public_key_y},
          not_before: SovraTest.MdlCertificates.days_from_now(-100),
          not_after: SovraTest.MdlCertificates.days_from_now(-1)
        )

      assert {:ok, session} =
               present(ctx,
                 disclose: ["family_name", "document_number"],
                 issuer_header: x5chain(expired.der)
               )

      assert session.status == "failed"
      assert session.error == "unknown_issuer"
    end

    test "is rejected when the docType is rewritten in transit", ctx do
      # The docType selects nothing on this route, so this is not the check that
      # stops issuer substitution — it is what stops one document type being
      # presented as another. `check_doc_type/3` compares against the signed MSO.
      assert {:ok, session} =
               present(ctx,
                 disclose: ["family_name", "document_number"],
                 doc_type: "org.iso.18013.5.1.mVRC"
               )

      assert session.status == "failed"
      assert session.error == "credential_signature_invalid"
    end

    test "is rejected when its metadata names another workspace's address", ctx do
      # The attack this route would otherwise open. A generated docType carries
      # the address that selects the verifying key, so naming someone else fails
      # the signature; an ISO docType names nobody, and the certificate names a
      # key rather than a workspace. So the only remaining copy of the address
      # is one the issuer writes into its own meta namespace — and it is what
      # the revocation bitmaps and the Issuer Trust Registry are keyed by.
      #
      # Signed by this workspace's document signer throughout. Only the address
      # is someone else's, which is exactly what a workspace with a valid signer
      # could do unaided.
      %{workspace: victim} = fixture_workspace()
      victim = provision_workspace(victim)

      {:ok, forged} =
        Sovra.Issuer.Mdoc.build(
          %{ctx.issuer_ws | eoa_address: victim.eoa_address},
          ctx.schema,
          %{"family_name" => "Lovelace", "document_number" => "D-1234567"},
          "did:sovra:0xholder",
          {ctx.holder.x, ctx.holder.y},
          status_list_index: 42
        )

      assert {:ok, session} =
               present(%{ctx | credential: forged.credential},
                 disclose: ["family_name", "document_number"]
               )

      assert session.status == "failed"
      assert session.error == "unknown_issuer"
    end
  end

  # A two-pixel JPEG header — enough to be recognisably binary, and to be
  # nothing a base64 round trip could produce by accident.
  @portrait <<0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46>>

  # ── A whole mDL ────────────────────────────────────────
  #
  # Everything above proves one mechanism at a time. This proves the parts add
  # up: a schema seeded from `Sovra.Mdl.Template`, carrying all eleven of ISO's
  # mandatory elements including a byte-string portrait and a structured
  # `driving_privileges` array, issued through the certificate route and
  # verified by the real pipeline.
  describe "a complete mDL" do
    setup ctx do
      %{workspace: issuer_ws} =
        SovraTest.MdlCertificates.provision_document_signer(ctx.issuer_ws)

      {:ok, schema} =
        Issuer.create_schema(issuer_ws.id, %{
          schema_id: "mdl",
          credential_type: "DrivingLicence",
          name: "Driving Licence",
          format: "mso_mdoc",
          doc_type: Template.doc_type(),
          namespace: Template.namespace(),
          claims: Template.claim_definitions(),
          validity_period: "1y"
        })

      {:ok, credential} =
        Sovra.Issuer.Mdoc.build(
          issuer_ws,
          schema,
          mdl_claims(),
          "did:sovra:0xholder",
          {ctx.holder.x, ctx.holder.y},
          status_list_index: 42
        )

      %{
        issuer_ws: issuer_ws,
        schema: schema,
        credential: credential.credential,
        doc_type: Template.doc_type(),
        query: iso_query(["family_name", "portrait", "driving_privileges", "age_over_18"])
      }
    end

    test "verifies, and the portrait survives as bytes", ctx do
      assert {:ok, session} =
               present(ctx, disclose: Template.mandatory_elements() ++ ["age_over_18"])

      assert session.status == "completed"

      claims = session.presentation_data["credentials"] |> hd() |> Map.get("claims")

      assert claims["org.iso.18013.5.1.family_name"] == "Lovelace"
      assert claims["org.iso.18013.5.1.age_over_18"] == true

      # A byte string comes back base64url, because `presentation_data` is a
      # jsonb column and JSON has no bytes. What matters is that it round-trips
      # to the bytes the issuer supplied rather than to a base64 string that was
      # carried as text all along.
      assert {:ok, @portrait} =
               Base.url_decode64(claims["org.iso.18013.5.1.portrait"], padding: false)
    end

    test "driving privileges arrive structured, with their dates intact", ctx do
      assert {:ok, session} =
               present(ctx, disclose: Template.mandatory_elements() ++ ["age_over_18"])

      claims = session.presentation_data["credentials"] |> hd() |> Map.get("claims")

      assert [%{"vehicle_category_code" => "B"} = entry] =
               claims["org.iso.18013.5.1.driving_privileges"]

      # Tag 1004 is a `full-date`, and `to_json_value/1` unwraps it to the string
      # inside. A privilege whose dates came back as `%{"tag" => 1004}` would
      # mean the tag reached the column, which raises inside the transaction
      # that finalizes the session.
      assert entry["issue_date"] == "2020-03-01"
      assert entry["expiry_date"] == "2030-03-01"
      assert [%{"code" => "S01", "sign" => "<=", "value" => "70"}] = entry["codes"]
    end

    test "withholding a mandatory element fails the presentation", ctx do
      # ISO's eleven are `disclosable: false` in the template, which is how a
      # schema says an element must be in every presentation and not only in the
      # credential.
      assert {:ok, session} =
               present(ctx,
                 disclose: (Template.mandatory_elements() -- ["portrait"]) ++ ["age_over_18"]
               )

      assert session.status == "failed"
      assert session.error == "missing_mandatory_element:org.iso.18013.5.1.portrait"
    end
  end

  defp mdl_claims do
    %{
      "family_name" => "Lovelace",
      "given_name" => "Ada",
      "birth_date" => "1815-12-10",
      "issue_date" => "2020-03-01",
      "expiry_date" => "2030-03-01",
      "issuing_country" => "ES",
      "issuing_authority" => "Dirección General de Tráfico",
      "document_number" => "D-1234567",
      "portrait" => Base.encode64(@portrait),
      "un_distinguishing_sign" => "E",
      "age_over_18" => true,
      "driving_privileges" => [
        %{
          "vehicle_category_code" => "B",
          "issue_date" => "2020-03-01",
          "expiry_date" => "2030-03-01",
          "codes" => [%{"code" => "S01", "sign" => "<=", "value" => "70"}]
        }
      ]
    }
  end

  defp iso_query(elements) do
    %{
      "credentials" => [
        %{
          "id" => "membership",
          "format" => "mso_mdoc",
          "meta" => %{"doctype_value" => "org.iso.18013.5.1.mDL"},
          "claims" => Enum.map(elements, &%{"path" => ["org.iso.18013.5.1", &1]})
        }
      ]
    }
  end

  defp x5chain(der), do: %{IssuerTrust.x5chain_label() => Cbor.bstr(der)}

  defp strip_meta_namespace(ctx, session) do
    vp =
      MdocBuilder.build_device_response(ctx.credential, session, ctx.holder,
        disclose: ["member_name", "tier"]
      )

    {:ok, bytes} = Base.url_decode64(vp, padding: false)
    {:ok, response} = Cbor.decode(bytes)

    stripped =
      update_in(response, ["documents", Access.at(0), "issuerSigned", "nameSpaces"], fn ns ->
        Map.delete(ns, Sovra.Mdoc.MetaNamespace.namespace())
      end)

    Base.url_encode64(Cbor.encode(stripped), padding: false)
  end
end
