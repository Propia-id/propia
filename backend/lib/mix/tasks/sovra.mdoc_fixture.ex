defmodule Mix.Tasks.Sovra.MdocFixture do
  @shortdoc "Regenerate the shared mdoc fixture the TypeScript tests read"

  @moduledoc """
  Regenerates `frontend/packages/holder-core/test/fixtures/mdoc-issuer-signed.json`.

  That fixture is an `IssuerSigned` credential this backend produced, which the
  wallet and SDK test suites parse, verify and present. It is what makes
  "Elixir and TypeScript agree" a test rather than an aspiration.

  It existed as a committed blob with no way to rebuild it, so any change to the
  issued structure — the Sovra meta namespace gaining a field, say — left it
  quietly describing a credential we no longer issue, and the TypeScript tests
  kept passing against the old shape. This task is the missing half.

      mix sovra.mdoc_fixture

  Run it whenever `Sovra.Issuer.Mdoc` or `Sovra.Mdoc.MetaNamespace` changes what
  goes on the wire, and commit the result.
  """

  use Mix.Task

  alias Sovra.Crypto.Key
  alias Sovra.Crypto.P256
  alias Sovra.Issuer.CredentialSchema
  alias Sovra.Issuer.Mdoc
  alias Sovra.Mdoc.DocType
  alias Sovra.Workspaces.Workspace

  @output "../frontend/packages/holder-core/test/fixtures/mdoc-issuer-signed.json"

  # Fixed so the fixture only changes when the *structure* does. A fresh address
  # every run would rewrite the docType and every digest, turning an empty diff
  # into a large one.
  @issuer_address "0xAb34Cd09F900112233445566778899aAbBcCdDeE"
  @holder_did "did:sovra:0xholder"
  @signed_at ~U[2026-08-25 12:00:00Z]
  @status_list_index 42

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")

    {:ok, %{key_id: key_id, public_key_x: issuer_x, public_key_y: issuer_y}} =
      Key.generate_key("mdoc-fixture-issuer")

    {:ok, holder} = P256.generate_key_pair()

    workspace = %Workspace{
      eoa_address: @issuer_address,
      signing_key_id: key_id,
      signing_public_key_x: issuer_x,
      signing_public_key_y: issuer_y,
      did: "did:sovra:" <> String.downcase(@issuer_address)
    }

    schema = schema()

    {:ok, built} =
      Mdoc.build(
        workspace,
        schema,
        %{
          "member_name" => "Ada Lovelace",
          "joined_on" => "2026-01-15",
          "visits" => 12,
          "tier" => "gold"
        },
        @holder_did,
        {holder.public_key_x, holder.public_key_y},
        status_list_index: @status_list_index,
        now: @signed_at
      )

    namespace = DocType.namespace(workspace, schema)

    fixture = %{
      "credentialType" => schema.credential_type,
      "docType" => built.doc_type,
      "namespace" => namespace,
      "holderDid" => @holder_did,
      "holderPrivateKey" => hex(holder.private_key),
      "holderPublicKey" => %{"x" => hex(holder.public_key_x), "y" => hex(holder.public_key_y)},
      "issuerAddress" => @issuer_address,
      "issuerPublicKey" => %{"x" => hex(issuer_x), "y" => hex(issuer_y)},
      "issuerSigned" => built.credential,
      # Keyed by namespace, mirroring `Sovra.Mdoc.MetaNamespace`.
      "mandatoryElements" => %{namespace => ["tier"]},
      "signedAt" => DateTime.to_iso8601(@signed_at),
      "statusListIndex" => @status_list_index
    }

    path = Path.expand(@output, File.cwd!())
    File.write!(path, Jason.encode!(fixture, pretty: true) <> "\n")
    Mix.shell().info("wrote #{path}")
  end

  defp schema do
    %CredentialSchema{
      schema_id: "membership-card",
      credential_type: "MembershipCard",
      name: "Membership Card",
      format: "mso_mdoc",
      validity_period: "1y",
      claims: [
        %{"key" => "member_name", "type" => "string", "required" => true, "disclosable" => true},
        %{"key" => "joined_on", "type" => "date", "required" => false, "disclosable" => true},
        %{"key" => "visits", "type" => "integer", "required" => false, "disclosable" => true},
        %{"key" => "tier", "type" => "string", "required" => true, "disclosable" => false}
      ]
    }
  end

  defp hex(binary), do: Base.encode16(binary, case: :lower)
end
