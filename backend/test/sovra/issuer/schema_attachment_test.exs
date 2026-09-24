defmodule Sovra.Issuer.SchemaAttachmentTest do
  use Sovra.DataCase, async: false

  alias Sovra.Issuer

  setup do
    %{workspace: ws} = fixture_workspace()
    {:ok, workspace: provision_workspace(ws)}
  end

  defp attachment(overrides \\ %{}) do
    Map.merge(
      %{"key" => "licence_scan", "type" => "attachment", "disclosable" => true},
      overrides
    )
  end

  defp attrs(overrides \\ %{}) do
    Map.merge(
      %{
        schema_id: "driving-licence-#{System.unique_integer([:positive])}",
        credential_type: "DrivingLicence",
        name: "Driving Licence",
        claims: [
          %{
            "key" => "family_name",
            "type" => "string",
            "required" => true,
            "disclosable" => true
          },
          attachment()
        ],
        validity_period: "5y"
      },
      overrides
    )
  end

  defp claims_error(changeset) do
    changeset |> errors_on() |> Map.get(:claims) |> List.first()
  end

  test "an sd-jwt credential schema may declare an attachment", %{workspace: ws} do
    assert {:ok, schema} = Issuer.create_schema(ws.id, attrs())
    assert Enum.any?(schema.claims, &(&1["type"] == "attachment"))
  end

  test "an mdoc schema may not", %{workspace: ws} do
    # ISO 18013-5 defines no element for an arbitrary attached document, and an
    # operator who wants CBOR bytes declares `bytes`, which MdocElement encodes.
    assert {:error, changeset} = Issuer.create_schema(ws.id, attrs(%{format: "mso_mdoc"}))
    assert claims_error(changeset) =~ "vc+sd-jwt"
  end

  test "a document schema may not", %{workspace: ws} do
    # A document schema renders its claims onto a printed page, where half a
    # megabyte of base64 is body text.
    assert {:error, changeset} = Issuer.create_schema(ws.id, attrs(%{kind: "document"}))
    assert claims_error(changeset) =~ "credential schemas"
  end

  test "a non-disclosable attachment is refused", %{workspace: ws} do
    # SDJWT.split_claims/2 merges a non-disclosable claim flat into the signed
    # payload: the document would ride in every presentation, unwithholdable,
    # and the wallet would have nothing to split out of the credential.
    claims = [attachment(%{"disclosable" => false})]
    assert {:error, changeset} = Issuer.create_schema(ws.id, attrs(%{claims: claims}))
    assert claims_error(changeset) =~ "must be disclosable"
  end

  test "an attachment with no disclosable flag at all is refused", %{workspace: ws} do
    claims = [%{"key" => "licence_scan", "type" => "attachment"}]
    assert {:error, changeset} = Issuer.create_schema(ws.id, attrs(%{claims: claims}))
    assert claims_error(changeset) =~ "must be disclosable"
  end

  test "the legacy `sd` spelling counts as disclosable", %{workspace: ws} do
    claims = [%{"key" => "licence_scan", "type" => "attachment", "sd" => true}]
    assert {:ok, _schema} = Issuer.create_schema(ws.id, attrs(%{claims: claims}))
  end

  test "an attachment with no key is refused", %{workspace: ws} do
    # Nothing else on a claim definition requires a key, and the webhook strip
    # needs one: without this the schema is accepted, offers are created, and
    # delivery crashes in the holder's wallet flow after the code is spent.
    for claim <- [Map.delete(attachment(), "key"), attachment(%{"key" => ""})] do
      assert {:error, changeset} = Issuer.create_schema(ws.id, attrs(%{claims: [claim]}))
      assert claims_error(changeset) =~ "must name its claim key"
    end
  end

  test "two attachments are refused", %{workspace: ws} do
    claims = [attachment(%{"key" => "front"}), attachment(%{"key" => "back"})]
    assert {:error, changeset} = Issuer.create_schema(ws.id, attrs(%{claims: claims}))
    assert claims_error(changeset) =~ "only one attachment"
  end

  # `do_insert_revision/3` rebuilds the attrs and calls `create_changeset/1`, so
  # this is the assertion that revisions are covered by the same rules with no
  # second call site to keep in step.
  test "a revision is held to the same rules", %{workspace: ws} do
    {:ok, schema} = Issuer.create_schema(ws.id, attrs(%{claims: [attachment()]}))

    assert {:error, changeset} =
             Issuer.revise_schema(ws.id, schema.schema_id, schema.version, %{
               name: schema.name,
               validity_period: schema.validity_period,
               claims: [attachment(%{"disclosable" => false})]
             })

    assert claims_error(changeset) =~ "must be disclosable"

    assert {:ok, revised} =
             Issuer.revise_schema(ws.id, schema.schema_id, schema.version, %{
               name: schema.name,
               validity_period: schema.validity_period,
               claims: [attachment(%{"key" => "certificate_scan"})]
             })

    assert revised.version == schema.version + 1
  end

  test "a schema declaring no attachment is untouched", %{workspace: ws} do
    claims = [%{"key" => "tier", "type" => "string", "required" => true, "disclosable" => false}]
    assert {:ok, _schema} = Issuer.create_schema(ws.id, attrs(%{claims: claims}))
  end
end
