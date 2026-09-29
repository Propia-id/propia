defmodule Sovra.DocumentsTest do
  use Sovra.DataCase, async: false

  alias Sovra.Documents
  alias Sovra.Documents.Attestation
  alias Sovra.Issuer

  setup do
    workspace = provision_workspace(fixture_workspace().workspace)
    %{workspace: workspace, schema: create_schema(workspace, "document")}
  end

  defp create_schema(workspace, kind) do
    {:ok, schema} =
      Issuer.create_schema(workspace.id, %{
        schema_id: "letter-#{System.unique_integer([:positive])}",
        credential_type: "EmploymentLetter",
        name: "Employment letter",
        kind: kind,
        validity_period: "1y",
        claims: [
          %{"key" => "employee_name", "type" => "string", "required" => true},
          %{"key" => "role", "type" => "string"}
        ]
      })

    schema
  end

  defp with_registry(module, fun) do
    previous = Application.get_env(:sovra, :signature_registry)

    try do
      Application.put_env(:sovra, :signature_registry, module)
      fun.()
    after
      Application.put_env(:sovra, :signature_registry, previous)
    end
  end

  defp claims, do: %{"employee_name" => "Ada Lovelace", "role" => "Principal engineer"}

  describe "issue/3" do
    test "signs, stores and anchors", %{workspace: workspace, schema: schema} do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())

      assert document.status == "anchored"
      assert document.tx_hash == "0xstubtxhash"
      assert document.anchored_at
      assert Attestation.claims(document.credential, document.schema) == claims()
      assert byte_size(document.digest) == 32
      assert String.ends_with?(document.credential, "~")
    end

    test "signs the document id into the payload as jti", %{
      workspace: workspace,
      schema: schema
    } do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())

      assert payload(document.credential)["jti"] == document.id
    end

    test "anchors the sha256 of the signing input", %{workspace: workspace, schema: schema} do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())

      [signing_input, _signature] =
        document.credential |> String.trim_trailing("~") |> rsplit_on_last_dot()

      assert document.digest == :crypto.hash(:sha256, signing_input)
    end

    test "keeps the document when anchoring does not land", %{
      workspace: workspace,
      schema: schema
    } do
      {:ok, document} =
        with_registry(SovraTest.Ethereum.AlwaysFailingSignatureRegistry, fn ->
          Documents.issue(workspace.id, schema.schema_id, claims())
        end)

      assert document.status == "failed"
      assert is_nil(document.tx_hash)
      assert is_nil(document.anchored_at)

      # Everything except the anchor is there, which is why the row is kept: the
      # transaction may still confirm. A verifier rejects it until then.
      assert String.ends_with?(document.credential, "~")
      assert byte_size(document.digest) == 32
      assert Attestation.claims(document.credential, document.schema) == claims()
    end

    test "refuses to sign with no signature registry", %{workspace: workspace, schema: schema} do
      result =
        with_registry(SovraTest.Ethereum.UnconfiguredSignatureRegistry, fn ->
          Documents.issue(workspace.id, schema.schema_id, claims())
        end)

      assert result == {:error, :chain_not_configured}
      assert Documents.list(workspace.id) == []
    end

    test "refuses a credential schema", %{workspace: workspace} do
      schema = create_schema(workspace, "credential")

      assert {:error, {:wrong_schema_kind, "credential"}} =
               Documents.issue(workspace.id, schema.schema_id, claims())
    end

    test "refuses when a required claim is missing", %{workspace: workspace, schema: schema} do
      assert {:error, {:missing_claims, ["employee_name"]}} =
               Documents.issue(workspace.id, schema.schema_id, %{"role" => "Engineer"})
    end

    test "drops claims the schema does not declare", %{workspace: workspace, schema: schema} do
      {:ok, document} =
        Documents.issue(
          workspace.id,
          schema.schema_id,
          Map.put(claims(), "salary", "USD 120000")
        )

      refute Map.has_key?(Attestation.claims(document.credential, document.schema), "salary")
      refute Map.has_key?(payload(document.credential), "salary")
    end

    test "registered claims win over declared ones", %{workspace: workspace, schema: schema} do
      {:ok, document} =
        Documents.issue(workspace.id, schema.schema_id, Map.put(claims(), "iss", "whoever"))

      assert payload(document.credential)["iss"] =~ workspace.did
    end

    test "refuses an unknown schema", %{workspace: workspace} do
      assert {:error, :schema_not_found} = Documents.issue(workspace.id, "nope", claims())
    end
  end

  describe "issue/4 visibility" do
    test "defaults to private, so publishing is a choice", %{
      workspace: workspace,
      schema: schema
    } do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())

      assert document.visibility == "private"
    end

    test "accepts public", %{workspace: workspace, schema: schema} do
      {:ok, document} =
        Documents.issue(workspace.id, schema.schema_id, claims(), visibility: "public")

      assert document.visibility == "public"
    end

    test "refuses anything else", %{workspace: workspace, schema: schema} do
      assert {:error, {:invalid_visibility, "secret"}} =
               Documents.issue(workspace.id, schema.schema_id, claims(), visibility: "secret")
    end

    test "changes after issuance", %{workspace: workspace, schema: schema} do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())

      assert {:ok, updated} = Documents.set_visibility(workspace.id, document.id, "public")
      assert updated.visibility == "public"
      assert {:ok, back} = Documents.set_visibility(workspace.id, document.id, "private")
      assert back.visibility == "private"
    end

    test "leaves the credential alone when it changes", %{workspace: workspace, schema: schema} do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())
      {:ok, updated} = Documents.set_visibility(workspace.id, document.id, "public")

      assert updated.credential == document.credential
      assert updated.digest == document.digest
    end

    test "refuses to change to something unknown", %{workspace: workspace, schema: schema} do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())

      assert {:error, {:invalid_visibility, "secret"}} =
               Documents.set_visibility(workspace.id, document.id, "secret")

      assert {:error, {:invalid_visibility, nil}} =
               Documents.set_visibility(workspace.id, document.id, nil)
    end

    test "will not change another workspace's document", %{workspace: workspace, schema: schema} do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())
      other = provision_workspace(fixture_workspace().workspace)

      assert {:error, :document_not_found} =
               Documents.set_visibility(other.id, document.id, "public")
    end

    test "is not covered by the signature", %{workspace: workspace, schema: schema} do
      {:ok, document} =
        Documents.issue(workspace.id, schema.schema_id, claims(), visibility: "private")

      refute Map.has_key?(payload(document.credential), "visibility")
    end
  end

  describe "issue/3 — registered claims" do
    # `payload/4` omits `exp` when the schema declares no validity period. The
    # declared claims are merged under the registered ones, so without dropping
    # the registered names a schema claim called `exp` would take the vacated
    # slot and set an expiry the issuer never configured, under the issuer's key.
    test "a schema claim named exp cannot set the expiry", %{workspace: workspace} do
      schema = schema_declaring_exp(workspace, nil)

      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, %{"exp" => 1})

      refute Map.has_key?(payload(document.credential), "exp")
      refute Map.has_key?(Attestation.claims(document.credential, schema), "exp")
    end

    test "the issuer's expiry wins over a schema claim named exp", %{workspace: workspace} do
      schema = schema_declaring_exp(workspace, "1y")

      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, %{"exp" => 1})

      exp = payload(document.credential)["exp"]
      assert is_integer(exp)
      assert exp > System.system_time(:second)
    end

    test "a schema with no validity period signs no exp at all", %{workspace: workspace} do
      {:ok, schema} =
        Issuer.create_schema(workspace.id, %{
          schema_id: "letter-#{System.unique_integer([:positive])}",
          credential_type: "EmploymentLetter",
          name: "Employment letter",
          kind: "document",
          validity_period: nil,
          claims: [%{"key" => "employee_name", "type" => "string", "required" => true}]
        })

      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())

      signed = payload(document.credential)
      refute Map.has_key?(signed, "exp")
      assert signed["employee_name"] == "Ada Lovelace"
    end
  end

  describe "issue/4 — custom expiry" do
    test "a custom date overrides the schema's period", %{workspace: workspace, schema: schema} do
      valid_until = DateTime.add(DateTime.utc_now(), 1000, :day) |> DateTime.truncate(:second)

      {:ok, document} =
        Documents.issue(workspace.id, schema.schema_id, claims(), valid_until: valid_until)

      assert payload(document.credential)["exp"] == DateTime.to_unix(valid_until)
    end

    test "a custom date gives exp to a schema with no validity period", %{workspace: workspace} do
      {:ok, schema} =
        Issuer.create_schema(workspace.id, %{
          schema_id: "letter-#{System.unique_integer([:positive])}",
          credential_type: "EmploymentLetter",
          name: "Employment letter",
          kind: "document",
          validity_period: nil,
          claims: [%{"key" => "employee_name", "type" => "string", "required" => true}]
        })

      valid_until = DateTime.add(DateTime.utc_now(), 30, :day) |> DateTime.truncate(:second)

      {:ok, document} =
        Documents.issue(workspace.id, schema.schema_id, claims(), valid_until: valid_until)

      assert payload(document.credential)["exp"] == DateTime.to_unix(valid_until)
    end

    test "a schema claim named exp still cannot override a custom expiry", %{
      workspace: workspace
    } do
      schema = schema_declaring_exp(workspace, nil)
      valid_until = DateTime.add(DateTime.utc_now(), 30, :day) |> DateTime.truncate(:second)

      {:ok, document} =
        Documents.issue(workspace.id, schema.schema_id, %{"exp" => 1}, valid_until: valid_until)

      assert payload(document.credential)["exp"] == DateTime.to_unix(valid_until)
    end

    test "a past date is refused", %{workspace: workspace, schema: schema} do
      past = DateTime.add(DateTime.utc_now(), -1, :day) |> DateTime.to_iso8601()

      assert {:error, {:invalid_valid_until, reason}} =
               Documents.issue(workspace.id, schema.schema_id, claims(), valid_until: past)

      assert reason =~ "future"
    end

    test "a malformed date is refused", %{workspace: workspace, schema: schema} do
      assert {:error, {:invalid_valid_until, _}} =
               Documents.issue(workspace.id, schema.schema_id, claims(), valid_until: "whenever")
    end

    test "omitting it leaves the schema-derived expiry untouched", %{
      workspace: workspace,
      schema: schema
    } do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())

      signed = payload(document.credential)
      assert signed["exp"] == signed["iat"] + 365 * 86_400
    end
  end

  describe "get_public/1 and list/1" do
    test "serves a document to anyone holding the id", %{workspace: workspace, schema: schema} do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())

      assert {:ok, found} = Documents.get_public(document.id)
      assert found.credential == document.credential
    end

    test "scopes the listing to the workspace", %{workspace: workspace, schema: schema} do
      {:ok, document} = Documents.issue(workspace.id, schema.schema_id, claims())
      other = provision_workspace(fixture_workspace().workspace)

      assert Enum.map(Documents.list(workspace.id), & &1.id) == [document.id]
      assert Documents.list(other.id) == []
    end
  end

  defp schema_declaring_exp(workspace, validity_period) do
    {:ok, schema} =
      Issuer.create_schema(workspace.id, %{
        schema_id: "letter-#{System.unique_integer([:positive])}",
        credential_type: "EmploymentLetter",
        name: "Employment letter",
        kind: "document",
        validity_period: validity_period,
        claims: [%{"key" => "exp", "type" => "string", "required" => true}]
      })

    schema
  end

  defp payload(credential) do
    [_header, payload | _] = credential |> String.trim_trailing("~") |> String.split(".")
    payload |> Base.url_decode64!(padding: false) |> Jason.decode!()
  end

  defp rsplit_on_last_dot(jwt) do
    [signature | reversed] = jwt |> String.split(".") |> Enum.reverse()
    [reversed |> Enum.reverse() |> Enum.join("."), signature]
  end
end
