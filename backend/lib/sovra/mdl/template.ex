defmodule Sovra.Mdl.Template do
  @moduledoc """
  The ISO/IEC 18013-5 mDL: its document type, its namespace, and the data
  elements that namespace is allowed to carry.

  ## Why this is a fixed list rather than a starting point

  `org.iso.18013.5.1` is a **closed** element set. ISO defines exactly these
  identifiers and what each one means, and a reader that receives
  `favourite_colour` in that namespace has been handed something the standard
  says cannot be there. So `validate/2` rejects it rather than issuing a
  credential that is malformed in a way only a third-party reader would notice.

  ## How an issuer carries more than this

  By adding a namespace, which is how ISO intends documents to be extended and
  how AAMVA already does it — `org.iso.18013.5.1.aamva` holds the elements US
  jurisdictions need and ISO has no opinion about. A document may carry several
  namespaces, and `Sovra.Mdoc.MetaNamespace` already keys mandatory elements by
  namespace for exactly that reason.

  So the rule is: fixed inside the ISO namespace, extensible beside it. A
  schema that names any other namespace is not checked here at all.

  ## Types, and why they are checked too

  Each element has a CBOR type ISO fixes. `portrait` declared as a `string`
  would issue a credential carrying base64 text where every reader expects a
  byte string, and it would verify — our digests do not care what the value
  means. The type is therefore part of the element definition, not a hint.

  Two elements are families rather than single identifiers: `age_over_NN` for
  any two-digit NN, and `biometric_template_xx`. They are matched by pattern.
  """

  @doc_type "org.iso.18013.5.1.mDL"
  @namespace "org.iso.18013.5.1"

  # ISO/IEC 18013-5:2021 Table 5. The value is every claim type that encodes to
  # the CBOR type ISO specifies — `issue_date` and `expiry_date` are the two it
  # lets an issuer choose for, allowing a full-date or a tdate.
  @mandatory %{
    "family_name" => ["string"],
    "given_name" => ["string"],
    "birth_date" => ["date"],
    "issue_date" => ["date", "datetime"],
    "expiry_date" => ["date", "datetime"],
    "issuing_country" => ["string"],
    "issuing_authority" => ["string"],
    "document_number" => ["string"],
    "portrait" => ["bytes"],
    "driving_privileges" => ["driving_privileges"],
    "un_distinguishing_sign" => ["string"]
  }

  @optional %{
    "administrative_number" => ["string"],
    "sex" => ["integer"],
    "height" => ["integer"],
    "weight" => ["integer"],
    "eye_colour" => ["string"],
    "hair_colour" => ["string"],
    "birth_place" => ["string"],
    "resident_address" => ["string"],
    "portrait_capture_date" => ["datetime"],
    "age_in_years" => ["integer"],
    "age_birth_year" => ["integer"],
    "issuing_jurisdiction" => ["string"],
    "nationality" => ["string"],
    "resident_city" => ["string"],
    "resident_state" => ["string"],
    "resident_postal_code" => ["string"],
    "resident_country" => ["string"],
    "family_name_national_character" => ["string"],
    "given_name_national_character" => ["string"],
    "signature_usual_mark" => ["bytes"]
  }

  # `age_over_NN` is an attestation rather than a value — the whole point of an
  # mDL for age checks, since it discloses that you are over 18 without
  # disclosing when you were born.
  @age_over ~r/^age_over_\d{2}$/
  @biometric_template ~r/^biometric_template_[a-z_]+$/

  @doc "The ISO document type an mDL carries."
  def doc_type, do: @doc_type

  @doc "The namespace an mDL's data elements live in. Not the same string as the docType."
  def namespace, do: @namespace

  @doc "The eleven elements ISO requires every mDL to carry."
  @spec mandatory_elements() :: [String.t()]
  def mandatory_elements, do: Map.keys(@mandatory) |> Enum.sort()

  @doc """
  Every element the ISO namespace defines, as claim definitions ready to seed a
  schema.

  Mandatory elements come back `required` and not `disclosable`: ISO requires
  them to be *in* the credential, and `disclosable: false` is how a schema says
  an element must also be present in every presentation. The optional ones are
  disclosable, which is what makes selective disclosure worth having — a holder
  proving they are over 18 should not have to hand over their address.
  """
  @spec claim_definitions() :: [map()]
  def claim_definitions do
    mandatory =
      for {key, [type | _]} <- Enum.sort(@mandatory),
          do: %{"key" => key, "type" => type, "required" => true, "disclosable" => false}

    optional =
      for {key, [type | _]} <- Enum.sort(@optional),
          do: %{"key" => key, "type" => type, "required" => false, "disclosable" => true}

    age_over =
      for nn <- ["18", "21"],
          do: %{
            "key" => "age_over_#{nn}",
            "type" => "boolean",
            "required" => false,
            "disclosable" => true
          }

    mandatory ++ age_over ++ optional
  end

  @doc """
  Check a schema's claims against the ISO element set.

  A no-op for any namespace but ISO's — an operator's own namespace is theirs
  to define, and applying ISO's list to it would be this module deciding what
  someone else's document means.

  Missing mandatory elements are *not* an error. A schema is a template for
  issuance, and an issuer building up an mDL a field at a time would otherwise
  be unable to save their work; the credential itself is what has to be
  complete, and `mandatory_elements/0` is what a caller checks it against.
  """
  @spec validate(String.t() | nil, [map()]) :: :ok | {:error, {atom(), [String.t()]}}
  def validate(@namespace, claims) when is_list(claims) do
    with :ok <- check_unknown(claims) do
      check_types(claims)
    end
  end

  def validate(_namespace, _claims), do: :ok

  defp check_unknown(claims) do
    case Enum.reject(claim_keys(claims), &defined?/1) do
      [] -> :ok
      unknown -> {:error, {:undefined_iso_elements, Enum.sort(unknown)}}
    end
  end

  # Only reached once `check_unknown/1` has passed, so `accepted_types/1` is a
  # list for every key here.
  defp check_types(claims) do
    mismatched =
      for claim <- claims,
          key = claim["key"],
          is_binary(key),
          claim["type"] not in accepted_types(key),
          do: key

    case mismatched do
      [] -> :ok
      keys -> {:error, {:wrong_iso_element_type, Enum.sort(keys)}}
    end
  end

  defp claim_keys(claims) do
    for claim <- claims, key = claim["key"], is_binary(key), do: key
  end

  defp defined?(key), do: accepted_types(key) != nil

  # `nil` for an identifier the ISO namespace does not define, which is what
  # `defined?/1` reads. The two families are matched by pattern rather than
  # enumerated, since `age_over_NN` is a hundred identifiers.
  defp accepted_types(key) do
    cond do
      Map.has_key?(@mandatory, key) -> Map.fetch!(@mandatory, key)
      Map.has_key?(@optional, key) -> Map.fetch!(@optional, key)
      Regex.match?(@age_over, key) -> ["boolean"]
      Regex.match?(@biometric_template, key) -> ["bytes"]
      true -> nil
    end
  end
end
