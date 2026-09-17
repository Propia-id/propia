defmodule Sovra.Mdoc.DocTypeTest do
  use ExUnit.Case, async: true

  alias Sovra.Issuer.CredentialSchema
  alias Sovra.Mdoc.DocType
  alias Sovra.Workspaces.Workspace

  defp workspace(address), do: %Workspace{eoa_address: address}

  defp schema(attrs \\ []) do
    struct(
      %CredentialSchema{schema_id: "membership-card", format: "mso_mdoc"},
      attrs
    )
  end

  describe "build/2" do
    test "follows the io.sovra.<address>.<schema_id>.1 template" do
      assert DocType.build(workspace("0xAb34Cd09F9"), schema()) ==
               "io.sovra.0xab34cd09f9.membership-card.1"
    end

    test "lowercases the address so a checksummed one cannot fork the docType" do
      # EIP-55 mixed case is common in configuration. Two spellings of one
      # address must not produce two docTypes, or a credential issued under
      # one stops matching queries built from the other.
      checksummed = DocType.build(workspace("0xAb34Cd09F9"), schema())
      lowercase = DocType.build(workspace("0xab34cd09f9"), schema())

      assert checksummed == lowercase
    end

    test "returns nil for sd-jwt schemas, which have no docType" do
      assert DocType.build(workspace("0xabc"), schema(format: "vc+sd-jwt")) == nil
    end

    test "returns nil while the workspace is still provisioning" do
      # Provisioning is asynchronous and list_schemas/1 does not wait for it, so
      # this has to render rather than raise.
      assert DocType.build(workspace(nil), schema()) == nil
      assert DocType.build(workspace(""), schema()) == nil
    end
  end

  describe "issuer_address/1" do
    @address "0xab34cd09f900112233445566778899aabbccddee"

    test "round-trips the address out of a docType it built" do
      ws = workspace(@address)

      assert DocType.issuer_address(DocType.build(ws, schema())) == {:ok, @address}
    end

    test "does not mistake an address-shaped schema_id for the issuer" do
      # Why the parse is positional. `schema_id` is operator-chosen, so a schema
      # named like an address must not be able to redirect issuer resolution.
      ws = workspace(@address)
      doc_type = DocType.build(ws, schema(schema_id: "0xdeadbeef"))

      assert DocType.issuer_address(doc_type) == {:ok, @address}
    end

    test "rejects a mixed-case address" do
      # `build/2` only ever emits lowercase, so this is a docType this system
      # never issued — and the workspace lookup is exact.
      assert DocType.issuer_address("io.sovra.0xAB34CD09F900112233445566778899AABBCCDDEE.card.1") ==
               :error
    end

    test "rejects an address that is not forty hex digits" do
      # The length is not cosmetic: this predicate picks the *route*. An address
      # here means "resolve on-chain", its absence means "resolve through the
      # certificate chain", and `verification-sdk`'s `isGeneratedDocType`
      # requires forty. A shorter one accepted here would send the two verifiers
      # down different routes for the same credential.
      assert DocType.issuer_address("io.sovra.0xab34cd09f9.card.1") == :error
      assert DocType.issuer_address("io.sovra.#{@address}ff.card.1") == :error
    end

    test "rejects a bare issuer prefix naming no schema" do
      assert DocType.issuer_address("io.sovra.#{@address}") == :error
    end

    test "rejects a foreign prefix" do
      assert DocType.issuer_address("org.iso.18013.5.1.mDL") == :error
      assert DocType.issuer_address("io.example.#{@address}.card.1") == :error
    end

    test "rejects a non-hex address segment" do
      assert DocType.issuer_address("io.sovra.notanaddress.card.1") == :error
      assert DocType.issuer_address("io.sovra.0xzz.card.1") == :error
      assert DocType.issuer_address("io.sovra.0x.card.1") == :error
    end

    test "rejects non-string docTypes" do
      assert DocType.issuer_address(nil) == :error
    end
  end
end
