defmodule Sovra.Mdl.TemplateTest do
  use ExUnit.Case, async: true

  alias Sovra.Mdl.Template

  defp claim(key, type), do: %{"key" => key, "type" => type}

  describe "the ISO element set" do
    test "names the eleven elements 18013-5 requires" do
      # Pinned by name rather than by count, because a count passes whichever
      # eleven happen to be there.
      assert Template.mandatory_elements() == [
               "birth_date",
               "document_number",
               "driving_privileges",
               "expiry_date",
               "family_name",
               "given_name",
               "issue_date",
               "issuing_authority",
               "issuing_country",
               "portrait",
               "un_distinguishing_sign"
             ]
    end

    test "a docType is not its namespace" do
      assert Template.doc_type() == "org.iso.18013.5.1.mDL"
      assert Template.namespace() == "org.iso.18013.5.1"
    end

    test "every seeded claim definition passes the validation" do
      # The template is what the console offers an operator, so a definition it
      # seeds that the changeset then rejects would be a dead end reachable by
      # clicking the obvious button.
      assert :ok = Template.validate(Template.namespace(), Template.claim_definitions())
    end

    test "seeds mandatory elements as required and always-disclosed" do
      definitions = Map.new(Template.claim_definitions(), &{&1["key"], &1})

      portrait = definitions["portrait"]
      assert portrait["required"]
      refute portrait["disclosable"]
      assert portrait["type"] == "bytes"

      # The optional ones are the point of selective disclosure: proving you are
      # over 18 should not hand over your address.
      assert definitions["resident_address"]["disclosable"]
      assert definitions["age_over_18"]["type"] == "boolean"
    end
  end

  describe "validate/2" do
    test "accepts the elements ISO defines" do
      assert :ok =
               Template.validate(Template.namespace(), [
                 claim("family_name", "string"),
                 claim("portrait", "bytes"),
                 claim("driving_privileges", "driving_privileges")
               ])
    end

    test "accepts either date form for issue_date and expiry_date" do
      # The two elements ISO lets an issuer choose for — a full-date or a tdate.
      assert :ok = Template.validate(Template.namespace(), [claim("issue_date", "date")])
      assert :ok = Template.validate(Template.namespace(), [claim("expiry_date", "datetime")])
    end

    test "accepts the age_over_NN and biometric_template families" do
      assert :ok =
               Template.validate(Template.namespace(), [
                 claim("age_over_18", "boolean"),
                 claim("age_over_65", "boolean"),
                 claim("biometric_template_face", "bytes")
               ])
    end

    test "rejects an element ISO does not define" do
      # The closed-set rule. A reader handed `favourite_colour` in this
      # namespace has been given something the standard says cannot be there.
      assert {:error, {:undefined_iso_elements, ["favourite_colour", "loyalty_tier"]}} =
               Template.validate(Template.namespace(), [
                 claim("family_name", "string"),
                 claim("loyalty_tier", "string"),
                 claim("favourite_colour", "string")
               ])
    end

    test "rejects an ISO element declared with the wrong type" do
      # This is the one that would otherwise issue cleanly and verify: our
      # digests do not care what a value means, so a base64 string sitting where
      # every reader expects a byte string is invisible until a real reader
      # tries to render the photograph.
      assert {:error, {:wrong_iso_element_type, ["portrait"]}} =
               Template.validate(Template.namespace(), [claim("portrait", "string")])
    end

    test "rejects age_over_NN declared as anything but a boolean" do
      assert {:error, {:wrong_iso_element_type, ["age_over_18"]}} =
               Template.validate(Template.namespace(), [claim("age_over_18", "integer")])
    end

    test "leaves any other namespace alone" do
      # How an issuer carries what ISO has no opinion about — the way AAMVA does
      # with `org.iso.18013.5.1.aamva`. Applying ISO's list here would be this
      # module deciding what somebody else's document means.
      assert :ok =
               Template.validate("org.iso.18013.5.1.aamva", [
                 claim("domestic_driving_privileges", "string"),
                 claim("anything_at_all", "string")
               ])

      assert :ok = Template.validate(nil, [claim("member_name", "string")])
    end

    test "does not require a schema to be complete" do
      # A schema is a template, and an operator building one up a field at a
      # time must be able to save. The credential is what has to carry all
      # eleven, which is a different check against `mandatory_elements/0`.
      assert :ok = Template.validate(Template.namespace(), [claim("family_name", "string")])
    end
  end
end
