defmodule Sovra.Documents.AnchorJobTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Documents
  alias Sovra.Documents.AnchorJob
  alias Sovra.Documents.Attestation
  alias Sovra.Issuer
  alias Sovra.Webhooks.DeliveryJob

  setup do
    workspace =
      provision_workspace(fixture_workspace(webhook_url: "https://example.com/hook").workspace)

    {:ok, schema} =
      Issuer.create_schema(workspace.id, %{
        schema_id: "letter-#{System.unique_integer([:positive])}",
        credential_type: "EmploymentLetter",
        name: "Employment letter",
        kind: "document",
        validity_period: "1y",
        claims: [%{"key" => "employee_name", "type" => "string", "required" => true}]
      })

    schema = register_schema(schema)

    {:ok, document} =
      Documents.issue(workspace.id, schema.schema_id, %{"employee_name" => "Ada Lovelace"})

    %{workspace: workspace, document: document}
  end

  defp args(document), do: %{"document_id" => document.id}

  defp with_registry(module, fun) do
    previous = Application.get_env(:sovra, :signature_registry)
    Application.put_env(:sovra, :signature_registry, module)

    try do
      fun.()
    after
      Application.put_env(:sovra, :signature_registry, previous)
    end
  end

  defp status_webhooks do
    all_enqueued(worker: DeliveryJob)
    |> Enum.filter(&(&1.args["event"] == "document.status-changed"))
    |> Enum.map(& &1.args["payload"]["data"])
  end

  test "anchors the document and announces it", %{document: document} do
    assert :ok = perform_job(AnchorJob, args(document))

    anchored = Repo.reload!(document)
    assert anchored.status == "anchored"
    assert anchored.tx_hash == "0xstubtxhash"
    assert %DateTime{} = anchored.anchored_at

    assert [
             %{
               "document_id" => id,
               "status" => "anchored",
               "schema_type" => "EmploymentLetter",
               "tx_hash" => "0xstubtxhash",
               "anchored_at" => anchored_at
             }
           ] = status_webhooks()

    assert id == document.id
    assert anchored_at == DateTime.to_iso8601(anchored.anchored_at)
  end

  test "recovers the earlier transaction when the signature is already on-chain",
       %{document: document} do
    with_registry(SovraTest.Ethereum.AlreadyRecordedSignatureRegistry, fn ->
      assert :ok = perform_job(AnchorJob, args(document))
    end)

    anchored = Repo.reload!(document)
    assert anchored.status == "anchored"
    assert anchored.tx_hash == "0xearliertxhash"
    assert anchored.anchored_at == ~U[2026-09-30 12:00:00Z]
  end

  test "leaves the document signed on an attempt that will be retried", %{document: document} do
    with_registry(SovraTest.Ethereum.AlwaysFailingSignatureRegistry, fn ->
      assert {:error, :transaction_reverted} =
               perform_job(AnchorJob, args(document), attempt: 1, max_attempts: 5)
    end)

    assert Repo.reload!(document).status == "signed"
    assert status_webhooks() == []
  end

  test "marks the document failed on the last attempt, and keeps it", %{document: document} do
    with_registry(SovraTest.Ethereum.AlwaysFailingSignatureRegistry, fn ->
      assert {:cancel, :transaction_reverted} =
               perform_job(AnchorJob, args(document), attempt: 5, max_attempts: 5)
    end)

    failed = document |> Repo.reload!() |> Repo.preload(:schema)
    assert failed.status == "failed"
    assert is_nil(failed.tx_hash)
    assert is_nil(failed.anchored_at)

    # Everything except the anchor is there, which is why the row is kept: the
    # transaction may still confirm. A verifier rejects it until then.
    assert Attestation.claims(failed.credential, failed.schema) == %{
             "employee_name" => "Ada Lovelace"
           }

    assert [%{"status" => "failed", "tx_hash" => nil, "anchored_at" => nil}] = status_webhooks()
  end

  test "does nothing for a document that is no longer signed", %{document: document} do
    assert :ok = perform_job(AnchorJob, args(document))
    assert :ok = perform_job(AnchorJob, args(document))

    assert [_only_one] = status_webhooks()
  end

  test "cancels when the document does not exist" do
    assert {:cancel, :document_not_found} =
             perform_job(AnchorJob, %{"document_id" => Ecto.UUID.generate()})
  end
end
