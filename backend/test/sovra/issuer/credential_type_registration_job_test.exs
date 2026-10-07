defmodule Sovra.Issuer.CredentialTypeRegistrationJobTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Ethereum.IssuerRegistry
  alias Sovra.Issuer
  alias Sovra.Issuer.CredentialTypeRegistrationJob

  setup do
    %{workspace: ws} = fixture_workspace()
    %{workspace: provision_workspace(ws)}
  end

  defp create_schema(workspace, opts \\ []) do
    {:ok, schema} =
      Issuer.create_schema(workspace.id, %{
        schema_id: Keyword.get(opts, :schema_id, "s-#{System.unique_integer([:positive])}"),
        credential_type: Keyword.get(opts, :credential_type, "MembershipCard"),
        name: "Membership",
        validity_period: "1y",
        claims: [
          %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
        ]
      })

    schema
  end

  defp args(workspace, credential_type \\ "MembershipCard"),
    do: %{"workspace_id" => workspace.id, "credential_type" => credential_type}

  defp with_registry(module, fun) do
    previous = Application.get_env(:sovra, :issuer_registry)
    Application.put_env(:sovra, :issuer_registry, module)

    try do
      fun.()
    after
      Application.put_env(:sovra, :issuer_registry, previous)
    end
  end

  describe "create_schema/2" do
    test "returns a pending schema and enqueues its registration instead of writing on-chain",
         %{workspace: ws} do
      schema = create_schema(ws)

      assert schema.registration_status == "pending"
      assert_enqueued(worker: CredentialTypeRegistrationJob, args: args(ws), queue: :chain)
      refute_received {:issuer_registry, :add_credential_types, _, _}
    end

    test "a revision carries its prior's registration status", %{workspace: ws} do
      schema = register_schema(create_schema(ws))

      {:ok, revision} =
        Issuer.revise_schema(ws.id, schema.schema_id, schema.version, %{
          name: "Membership v2",
          claims: schema.claims,
          validity_period: "1y"
        })

      assert revision.registration_status == "registered"
    end
  end

  describe "perform/1" do
    test "adds the type to the workspace's issuer entry and marks the schema registered",
         %{workspace: ws} do
      schema = create_schema(ws)

      assert :ok = perform_job(CredentialTypeRegistrationJob, args(ws))

      eoa = ws.eoa_address
      type_id = IssuerRegistry.credential_type_hash("MembershipCard")
      assert_received {:issuer_registry, :add_credential_types, ^eoa, [^type_id]}

      registered = Repo.reload!(schema)
      assert registered.registration_status == "registered"
      assert registered.registration_error == nil
    end

    test "sends nothing when the type is already trusted", %{workspace: ws} do
      schema = create_schema(ws)

      with_registry(SovraTest.Ethereum.AlreadyRegisteredIssuerRegistry, fn ->
        assert :ok = perform_job(CredentialTypeRegistrationJob, args(ws))
      end)

      refute_received {:issuer_registry, :add_credential_types, _, _}
      assert Repo.reload!(schema).registration_status == "registered"
    end

    test "marks every schema of the type, and only that type", %{workspace: ws} do
      first = create_schema(ws)
      second = create_schema(ws)
      other = create_schema(ws, credential_type: "OtherCard")

      assert :ok = perform_job(CredentialTypeRegistrationJob, args(ws))

      assert Repo.reload!(first).registration_status == "registered"
      assert Repo.reload!(second).registration_status == "registered"
      assert Repo.reload!(other).registration_status == "pending"
    end

    test "leaves the schema pending on an attempt that will be retried", %{workspace: ws} do
      schema = create_schema(ws)

      with_registry(SovraTest.Ethereum.AlwaysFailingIssuerRegistry, fn ->
        assert {:error, :rpc_down} =
                 perform_job(CredentialTypeRegistrationJob, args(ws),
                   attempt: 1,
                   max_attempts: 5
                 )
      end)

      assert Repo.reload!(schema).registration_status == "pending"
    end

    test "marks the schema failed on the last attempt", %{workspace: ws} do
      schema = create_schema(ws)

      with_registry(SovraTest.Ethereum.AlwaysFailingIssuerRegistry, fn ->
        assert {:cancel, :rpc_down} =
                 perform_job(CredentialTypeRegistrationJob, args(ws),
                   attempt: 5,
                   max_attempts: 5
                 )
      end)

      failed = Repo.reload!(schema)
      assert failed.registration_status == "failed"
      assert failed.registration_error == "rpc_down"
    end

    test "cancels when the workspace does not exist" do
      assert {:cancel, :workspace_not_found} =
               perform_job(CredentialTypeRegistrationJob, %{
                 "workspace_id" => Ecto.UUID.generate(),
                 "credential_type" => "MembershipCard"
               })
    end
  end

  describe "issuing from a schema that is not registered" do
    test "a credential offer is refused while pending, and after a failure", %{workspace: ws} do
      schema = create_schema(ws)

      assert {:error, :schema_registration_pending} =
               Issuer.create_credential_offer(ws.id, schema.schema_id, %{"name" => "Ada"})

      with_registry(SovraTest.Ethereum.AlwaysFailingIssuerRegistry, fn ->
        perform_job(CredentialTypeRegistrationJob, args(ws), attempt: 5, max_attempts: 5)
      end)

      assert {:error, :schema_registration_failed} =
               Issuer.create_credential_offer(ws.id, schema.schema_id, %{"name" => "Ada"})
    end

    test "a document is refused while pending, before anything is signed", %{workspace: ws} do
      {:ok, schema} =
        Issuer.create_schema(ws.id, %{
          schema_id: "letter-#{System.unique_integer([:positive])}",
          credential_type: "EmploymentLetter",
          name: "Employment letter",
          kind: "document",
          validity_period: "1y",
          claims: [%{"key" => "employee_name", "type" => "string", "required" => true}]
        })

      assert {:error, :schema_registration_pending} =
               Sovra.Documents.issue(ws.id, schema.schema_id, %{"employee_name" => "Ada"})

      assert Sovra.Documents.list(ws.id) == []
    end
  end
end
