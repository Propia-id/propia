defmodule Sovra.Issuer.IssuanceEventsTest do
  @moduledoc """
  The issuance flow, from schema to revocation.

  The load-bearing property is that ONE `credential_id` spans the whole flow.
  `issuer.ex` already reuses `offer.id` as the `IssuedCredential` primary key
  "so external integrators have a single stable credential_id" — these tests
  assert the log actually emits it at every step, including the two wallet-side
  calls that only receive a token hash and have to resolve the offer to recover
  it.

  The other property: claim VALUES never appear. They are government-issued PII
  and New Relic flattens a map into queryable attributes, so only a count is
  logged.
  """

  use Sovra.DataCase, async: false

  import Sovra.LogHelpers

  alias Sovra.Crypto.P256
  alias Sovra.Issuer

  defp create_issuer, do: provision_workspace(fixture_workspace().workspace)

  # A status change is requested, then lands when its job runs.
  defp request_and_confirm(change, issuer, credential_id) do
    result = change.(issuer.id, credential_id)
    run_chain_jobs()
    result
  end

  defp create_schema(issuer, opts \\ []) do
    {:ok, schema} =
      Issuer.create_schema(issuer.id, %{
        schema_id: Keyword.get(opts, :schema_id, "evt-#{System.unique_integer([:positive])}"),
        credential_type: Keyword.get(opts, :credential_type, "TestCredential"),
        name: "Test Credential",
        claims: [
          %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true},
          %{"key" => "dni", "type" => "string", "required" => true, "disclosable" => true}
        ]
      })

    register_schema(schema)
  end

  @claims %{"name" => "Ada Lovelace", "dni" => "12345678"}

  defp holder_proof_jwt(c_nonce) do
    {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

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

    payload = %{"iss" => "did:sovra:0xholder", "nonce" => c_nonce}
    header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
    payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
    signing_input = "#{header_b64}.#{payload_b64}"
    hash = :crypto.hash(:sha256, signing_input)
    {:ok, %{r: r, s: s}} = P256.sign(hash, priv)
    raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)

    %{
      "proof_type" => "jwt",
      "jwt" => "#{signing_input}.#{Base.url_encode64(raw_sig, padding: false)}"
    }
  end

  describe "schemas" do
    test "created records the ref, kind and claim count" do
      issuer = create_issuer()

      {_, events} =
        capture_events(fn -> create_schema(issuer, schema_id: "evt-created") end)

      # No schema_version: create_schema/2 always produces 1, so the attribute
      # would spend one of the ten New Relic accepts to say nothing. The
      # revision event carries both versions, where they differ.
      event =
        assert_event(events, "credential.schema.created",
          workspace_id: issuer.id,
          schema_ref: "evt-created",
          credential_type: "TestCredential",
          kind: "credential",
          claim_count: 2
        )

      refute Map.has_key?(event.metadata, :schema_version)
    end

    test "revised records the version it was based on" do
      issuer = create_issuer()
      schema = create_schema(issuer)

      {{:ok, revised}, events} =
        capture_events(fn ->
          Issuer.revise_schema(issuer.id, schema.schema_id, 1, %{
            name: "Renamed",
            claims: [
              %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
            ]
          })
        end)

      assert_event(events, "credential.schema.revised",
        workspace_id: issuer.id,
        schema_ref: schema.schema_id,
        base_version: 1,
        schema_version: revised.version
      )
    end

    test "a stale base_version is a tagged rejection, not a silent failure" do
      issuer = create_issuer()
      schema = create_schema(issuer)

      {{:error, :schema_revision_conflict}, events} =
        capture_events(fn ->
          Issuer.revise_schema(issuer.id, schema.schema_id, 99, %{name: "Nope"})
        end)

      assert_event(events, "credential.schema.rejected",
        stage: :revise,
        reason: :schema_revision_conflict
      )
    end

    test "deleted records how many versions went" do
      issuer = create_issuer()
      schema = create_schema(issuer)

      {{:ok, _}, events} =
        capture_events(fn -> Issuer.delete_schema(issuer.id, schema.id) end)

      assert_event(events, "credential.schema.deleted",
        workspace_id: issuer.id,
        schema_ref: schema.schema_id,
        deleted_versions: 1
      )
    end

    test "the in-use deletion guard says why it refused" do
      issuer = create_issuer()
      schema = create_schema(issuer)
      {:ok, _} = Issuer.create_credential_offer(issuer.id, schema.schema_id, @claims)

      {{:error, :schema_in_use}, events} =
        capture_events(fn -> Issuer.delete_schema(issuer.id, schema.id) end)

      assert_event(events, "credential.schema.rejected",
        stage: :delete,
        reason: :schema_in_use
      )
    end
  end

  describe "the credential_id spans the whole flow" do
    test "offer, token exchange and issuance all carry the same id" do
      issuer = create_issuer()
      schema = create_schema(issuer)

      {{:ok, offer_result}, offer_events} =
        capture_events(fn ->
          Issuer.create_credential_offer(issuer.id, schema.schema_id, @claims)
        end)

      credential_id = offer_result.offer.id

      offer_event =
        assert_event(offer_events, "credential.offer.created",
          credential_id: credential_id,
          workspace_id: issuer.id,
          claim_count: 2
        )

      # The claims are government-issued PII: only the count may be logged.
      refute inspect(offer_event.metadata) =~ "Ada Lovelace"
      refute inspect(offer_event.metadata) =~ "12345678"
      # Nor may the pre-authorized code, which is a bearer credential.
      refute inspect(offer_event.metadata) =~ offer_result.pre_authorized_code

      {{:ok, token}, token_events} =
        capture_events(fn -> Issuer.exchange_token(offer_result.pre_authorized_code) end)

      # exchange_token/2 only ever sees a hash of the code, so recovering this
      # id means it resolved the offer on purpose.
      token_event =
        assert_event(token_events, "credential.token.exchanged", credential_id: credential_id)

      refute inspect(token_event.metadata) =~ token.access_token

      {{:ok, _sd_jwt}, issue_events} =
        capture_events(fn ->
          Issuer.issue_credential(
            token.access_token,
            schema.credential_type,
            holder_proof_jwt(token.c_nonce)
          )
        end)

      issued =
        assert_event(issue_events, "credential.issued",
          credential_id: credential_id,
          workspace_id: issuer.id,
          holder_did: "did:sovra:0xholder"
        )

      assert issued.metadata[:status_list_index] == offer_result.offer.status_list_index
    end

    test "revocation carries the same id and the previous status" do
      issuer = create_issuer()
      schema = create_schema(issuer)
      {:ok, offer_result} = Issuer.create_credential_offer(issuer.id, schema.schema_id, @claims)
      {:ok, token} = Issuer.exchange_token(offer_result.pre_authorized_code)

      {:ok, _} =
        Issuer.issue_credential(
          token.access_token,
          schema.credential_type,
          holder_proof_jwt(token.c_nonce)
        )

      credential_id = offer_result.offer.id

      {{:ok, _}, events} =
        capture_events(fn ->
          request_and_confirm(&Issuer.revoke_credential/2, issuer, credential_id)
        end)

      # Who asked is logged when the change is requested; the outcome when it
      # lands on-chain.
      assert_event(events, "credential.status_change.requested",
        credential_id: credential_id,
        status: "revoked",
        previous_status: "issued"
      )

      # The event name is the webhook's, so support can pivot between what we
      # told the customer and what we did on one identifier.
      # No `status`: the event name is the outcome. previous_status is the half
      # the name cannot carry — issued -> revoked and suspended -> revoked are
      # different stories.
      event =
        assert_event(events, "credential.revoked",
          credential_id: credential_id,
          workspace_id: issuer.id,
          previous_status: "issued"
        )

      refute Map.has_key?(event.metadata, :status)
    end

    test "suspend then unsuspend both record the transition" do
      issuer = create_issuer()
      schema = create_schema(issuer)
      {:ok, offer_result} = Issuer.create_credential_offer(issuer.id, schema.schema_id, @claims)
      {:ok, token} = Issuer.exchange_token(offer_result.pre_authorized_code)

      {:ok, _} =
        Issuer.issue_credential(
          token.access_token,
          schema.credential_type,
          holder_proof_jwt(token.c_nonce)
        )

      credential_id = offer_result.offer.id

      {{:ok, _}, events} =
        capture_events(fn ->
          request_and_confirm(&Issuer.suspend_credential/2, issuer, credential_id)
        end)

      assert_event(events, "credential.suspended",
        credential_id: credential_id,
        previous_status: "issued"
      )

      {{:ok, _}, events} =
        capture_events(fn ->
          request_and_confirm(&Issuer.unsuspend_credential/2, issuer, credential_id)
        end)

      # The one case where the event name and the resulting status differ —
      # unsuspend returns the credential to "issued" — and previous_status is
      # what makes that legible without spending an attribute on it.
      assert_event(events, "credential.unsuspended",
        credential_id: credential_id,
        previous_status: "suspended"
      )
    end

    test "an invalid transition is rejected with a reason" do
      issuer = create_issuer()
      schema = create_schema(issuer)
      {:ok, offer_result} = Issuer.create_credential_offer(issuer.id, schema.schema_id, @claims)

      # Still a pending offer, never issued.
      {{:error, :credential_not_yet_issued}, events} =
        capture_events(fn -> Issuer.revoke_credential(issuer.id, offer_result.offer.id) end)

      assert_event(events, "credential.status_change.rejected",
        credential_id: offer_result.offer.id,
        status: "revoked",
        reason: :credential_not_yet_issued
      )
    end
  end

  describe "wallet-side rejections" do
    test "an unknown pre-authorized code is recorded with no credential_id" do
      {{:error, :invalid_code}, events} =
        capture_events(fn -> Issuer.exchange_token("not-a-real-code") end)

      event =
        assert_event(events, "credential.request.rejected",
          stage: :token,
          reason: :invalid_code
        )

      assert event.level == :warning
      refute Map.has_key?(event.metadata, :credential_id)
    end

    test "reusing a spent code is tagged and does carry the credential_id" do
      issuer = create_issuer()
      schema = create_schema(issuer)
      {:ok, offer_result} = Issuer.create_credential_offer(issuer.id, schema.schema_id, @claims)
      {:ok, _} = Issuer.exchange_token(offer_result.pre_authorized_code)

      {{:error, :code_already_used}, events} =
        capture_events(fn -> Issuer.exchange_token(offer_result.pre_authorized_code) end)

      assert_event(events, "credential.request.rejected",
        stage: :token,
        reason: :code_already_used,
        credential_id: offer_result.offer.id
      )
    end

    test "a bad holder proof is rejected at the credential stage" do
      issuer = create_issuer()
      schema = create_schema(issuer)
      {:ok, offer_result} = Issuer.create_credential_offer(issuer.id, schema.schema_id, @claims)
      {:ok, token} = Issuer.exchange_token(offer_result.pre_authorized_code)

      {{:error, :invalid_proof}, events} =
        capture_events(fn ->
          Issuer.issue_credential(token.access_token, schema.credential_type, nil)
        end)

      assert_event(events, "credential.request.rejected",
        stage: :credential,
        reason: :invalid_proof,
        credential_id: offer_result.offer.id
      )
    end
  end

  describe "status list capacity" do
    # Width starts at 17 (131,072 slots), so a widen never happens naturally in
    # a test. Squeezing the list down to 1 bit leaves two slots: the third
    # offer cannot find a free index at any of the allocator's three attempts,
    # which is exactly the path that widens.
    test "the allocator records a widen with the old and new width" do
      issuer = create_issuer()
      squeeze_status_list(issuer.id, "revocation", 1)
      schema = create_schema(issuer)

      {_, events} =
        capture_events(fn ->
          for _ <- 1..3 do
            Issuer.create_credential_offer(issuer.id, schema.schema_id, @claims)
          end
        end)

      event =
        assert_event(events, "issuance.status_index.widened",
          workspace_id: issuer.id,
          status_purpose: "revocation",
          previous_width: 1
        )

      assert event.metadata[:width] == 2
    end

    # The exhaustion event (issuance.status_index.exhausted) is deliberately
    # not asserted here: reaching it needs either three index collisions at
    # width 30 — 2^30 slots — or 16 widens inside a single call, and neither is
    # reachable from the public API. Its alert condition is what covers it.
    test "widening refuses past the maximum width" do
      issuer = create_issuer()
      squeeze_status_list(issuer.id, "revocation", Sovra.Issuer.StatusList.max_width())

      assert {:error, :bitmap_exhausted} =
               Issuer.widen_status_list(
                 issuer.id,
                 "revocation",
                 Sovra.Issuer.StatusList.max_width()
               )
    end

    defp squeeze_status_list(workspace_id, purpose, width) do
      Sovra.Repo.get_by!(Sovra.Issuer.StatusList,
        workspace_id: workspace_id,
        status_purpose: purpose
      )
      |> Ecto.Changeset.change(width: width)
      |> Sovra.Repo.update!()
    end
  end
end
