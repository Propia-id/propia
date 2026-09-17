defmodule Sovra.X509.Certificate do
  @moduledoc """
  Parsing and ISO/IEC 18013-5 Annex B validation for the two certificates an
  mDL issuer registers: its IACA root, and the Document Signer Certificate that
  root issued for a workspace's KMS key.

  ## Why validate at registration

  Nothing here is required to *produce* a credential — an unchecked certificate
  would embed into `x5chain` and our own verifiers would be perfectly happy,
  because they resolve trust from the registered root either way. It is the
  readers we do not control that reject a non-conformant chain, and they do it
  silently, months later, in the field.

  So the profile is checked once, at the moment an operator hands the
  certificate over, where the failure can name the field and the operator still
  has their CA on the phone.

  ## The check that is actually load-bearing

  `certifies?/2` — that the DSC's public key is the workspace's KMS key. Every
  other check here is conformance; that one is correctness. A DSC for someone
  else's key produces credentials whose `x5chain` asserts a binding the
  signature does not have, and no amount of chain validation catches it,
  because the chain is perfectly valid — it just describes a different key.

  ## What is deliberately not checked

  Annex B also constrains the CRL distribution point and the IACA's own
  validity ceiling. Both are omitted rather than guessed at: a check that is
  too strict rejects certificates a real authority issued, which is worse than
  one that is absent, and the exact wording is worth reading before either is
  added. `Sovra.X509.CertificateTest` records which rules are enforced.
  """

  @enforce_keys [:der, :subject, :issuer, :not_before, :not_after, :public_key]
  defstruct [
    :der,
    :subject,
    :issuer,
    :not_before,
    :not_after,
    :public_key,
    :serial,
    version: :v3,
    key_usage: [],
    extended_key_usage: [],
    basic_constraints: nil,
    self_signed?: false
  ]

  @type name :: %{
          country: String.t() | nil,
          state: String.t() | nil,
          organization: String.t() | nil,
          common_name: String.t() | nil
        }

  @type t :: %__MODULE__{
          der: binary(),
          subject: name(),
          issuer: name(),
          not_before: DateTime.t(),
          not_after: DateTime.t(),
          public_key: {binary(), binary()},
          serial: integer() | nil,
          version: atom(),
          key_usage: [atom()],
          extended_key_usage: [tuple()],
          basic_constraints: {boolean(), integer() | nil} | nil,
          self_signed?: boolean()
        }

  # ISO/IEC 18013-5 Annex B: the extended key usage a Document Signer
  # Certificate carries. It is marked critical, which is why path validation
  # needs `verify_fun` — OTP has no rule for it and rejects the whole chain as
  # carrying an unknown critical extension.
  @mdl_document_signer_eku {1, 0, 18013, 5, 1, 2}

  # Annex B caps a Document Signer Certificate at 457 days.
  @max_document_signer_days 457

  @oid_key_usage {2, 5, 29, 15}
  @oid_extended_key_usage {2, 5, 29, 37}
  @oid_basic_constraints {2, 5, 29, 19}

  @oid_common_name {2, 5, 4, 3}
  @oid_country {2, 5, 4, 6}
  @oid_state {2, 5, 4, 8}
  @oid_organization {2, 5, 4, 10}

  @doc "The EKU OID a Document Signer Certificate must carry. Exposed for tests."
  def document_signer_eku, do: @mdl_document_signer_eku

  @doc "The Annex B ceiling on a Document Signer Certificate's validity, in days."
  def max_document_signer_days, do: @max_document_signer_days

  @doc """
  Parse a certificate from PEM or raw DER.

  Accepts both because an operator pastes PEM and an `x5chain` carries DER, and
  making the caller decide which it holds is how you get a call site that
  guesses.
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, term()}
  def parse(input) when is_binary(input) do
    with {:ok, der} <- to_der(input),
         {:ok, decoded} <- decode(der) do
      build(der, decoded)
    end
  end

  @doc """
  Validate an IACA root against Annex B.

  `:now` defaults to the current time and exists so a test can place a
  certificate outside its own window without waiting for it.
  """
  @spec validate_iaca(t(), keyword()) :: :ok | {:error, term()}
  def validate_iaca(%__MODULE__{} = cert, opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now())

    with :ok <- check(cert.version == :v3, {:iaca_profile, :not_v3}),
         :ok <- check(cert.self_signed?, {:iaca_profile, :not_self_signed}),
         :ok <- check_window(cert, now, :iaca_profile),
         :ok <- check(cert.subject.country, {:iaca_profile, :missing_country}),
         :ok <- check(cert.subject.common_name, {:iaca_profile, :missing_common_name}),
         :ok <- check_ca(cert),
         :ok <-
           check(
             :keyCertSign in cert.key_usage and :cRLSign in cert.key_usage,
             {:iaca_profile, :key_usage}
           ) do
      :ok
    end
  end

  @doc """
  Validate a Document Signer Certificate against Annex B and its issuing IACA.

  The subject rules are the ones that let a single national root certify one
  signer per region: country must match the IACA's, and `stateOrProvinceName`
  is only constrained when the IACA declares one of its own. A root that names
  no state can therefore certify signers that each name their own.
  """
  @spec validate_document_signer(t(), t(), keyword()) :: :ok | {:error, term()}
  def validate_document_signer(%__MODULE__{} = dsc, %__MODULE__{} = iaca, opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now())

    with :ok <- check(dsc.version == :v3, {:dsc_profile, :not_v3}),
         :ok <- check_window(dsc, now, :dsc_profile),
         :ok <- check_lifetime(dsc),
         :ok <- check_not_ca(dsc),
         :ok <- check(dsc.key_usage == [:digitalSignature], {:dsc_profile, :key_usage}),
         :ok <-
           check(
             @mdl_document_signer_eku in dsc.extended_key_usage,
             {:dsc_profile, :missing_mdl_eku}
           ),
         :ok <- check_subject_agreement(dsc, iaca),
         :ok <- verify_chain(dsc, iaca) do
      :ok
    end
  end

  @doc """
  Whether this certificate certifies `{x, y}`.

  The one check that is about correctness rather than conformance — see the
  moduledoc.
  """
  @spec certifies?(t(), {binary(), binary()}) :: boolean()
  def certifies?(%__MODULE__{public_key: point}, {x, y}), do: point == {x, y}

  # ── Parsing ─────────────────────────────────────────────

  defp to_der(input) do
    case :public_key.pem_decode(input) do
      [{:Certificate, der, :not_encrypted} | _] -> {:ok, der}
      # Not PEM. Assume DER and let the decoder be the judge, rather than
      # sniffing bytes and being wrong about a certificate that starts oddly.
      [] -> {:ok, input}
      _ -> {:error, {:certificate, :unsupported_pem_entry}}
    end
  rescue
    _ -> {:error, {:certificate, :malformed}}
  end

  defp decode(der) do
    {:ok, :public_key.pkix_decode_cert(der, :otp)}
  rescue
    _ -> {:error, {:certificate, :malformed}}
  catch
    _, _ -> {:error, {:certificate, :malformed}}
  end

  defp build(der, {:OTPCertificate, tbs, _signature_algorithm, _signature}) do
    {:OTPTBSCertificate, version, serial, _sig, issuer, validity, subject, spki, _iuid, _suid,
     extensions} = tbs

    with {:ok, not_before, not_after} <- window(validity),
         {:ok, point} <- public_key_point(spki) do
      extensions = List.wrap(extensions)

      {:ok,
       %__MODULE__{
         der: der,
         subject: name(subject),
         issuer: name(issuer),
         not_before: not_before,
         not_after: not_after,
         public_key: point,
         serial: serial,
         version: version,
         key_usage: extension(extensions, @oid_key_usage) |> List.wrap(),
         extended_key_usage: extension(extensions, @oid_extended_key_usage) |> List.wrap(),
         basic_constraints: basic_constraints(extensions),
         self_signed?: self_signed?(der)
       }}
    end
  end

  defp build(_der, _other), do: {:error, {:certificate, :malformed}}

  defp self_signed?(der) do
    :public_key.pkix_is_self_signed(der)
  rescue
    _ -> false
  end

  # An EC public key arrives as an uncompressed point. Anything else is a key
  # this profile has no use for, and saying so beats returning a shape callers
  # would have to re-check.
  defp public_key_point({:OTPSubjectPublicKeyInfo, _algorithm, {:ECPoint, point}}),
    do: split_point(point)

  defp public_key_point({:OTPSubjectPublicKeyInfo, _algorithm, point}) when is_binary(point),
    do: split_point(point)

  defp public_key_point(_), do: {:error, {:certificate, :unsupported_public_key}}

  defp split_point(<<0x04, x::binary-size(32), y::binary-size(32)>>), do: {:ok, {x, y}}
  defp split_point(_), do: {:error, {:certificate, :unsupported_public_key}}

  defp extension(extensions, oid) do
    Enum.find_value(extensions, fn
      {:Extension, ^oid, _critical, value} -> value
      _ -> nil
    end)
  end

  defp basic_constraints(extensions) do
    case extension(extensions, @oid_basic_constraints) do
      {:BasicConstraints, ca?, :asn1_NOVALUE} -> {ca?, nil}
      {:BasicConstraints, ca?, path_len} -> {ca?, path_len}
      _ -> nil
    end
  end

  # ── Names ───────────────────────────────────────────────

  defp name({:rdnSequence, rdns}) do
    attributes =
      for rdn <- List.wrap(rdns),
          {:AttributeTypeAndValue, oid, value} <- List.wrap(rdn),
          into: %{},
          do: {oid, attribute_value(value)}

    %{
      country: Map.get(attributes, @oid_country),
      state: Map.get(attributes, @oid_state),
      organization: Map.get(attributes, @oid_organization),
      common_name: Map.get(attributes, @oid_common_name)
    }
  end

  defp name(_), do: %{country: nil, state: nil, organization: nil, common_name: nil}

  # OTP releases disagree about whether an attribute value comes back as a term
  # or as the raw DER of a string — the same asymmetry that made
  # `Sovra.X509.Csr` encode its own subject. Normalise both.
  defp attribute_value({_string_type, value}) when is_binary(value), do: value
  defp attribute_value({_string_type, value}) when is_list(value), do: List.to_string(value)
  defp attribute_value(value) when is_list(value), do: List.to_string(value)

  defp attribute_value(<<tag, length, rest::binary>>)
       when tag in [0x13, 0x0C, 0x16, 0x14] and byte_size(rest) >= length,
       do: binary_part(rest, 0, length)

  defp attribute_value(value) when is_binary(value), do: value
  defp attribute_value(_), do: nil

  # ── Validity ────────────────────────────────────────────

  defp window({:Validity, not_before, not_after}) do
    with {:ok, from} <- timestamp(not_before),
         {:ok, until} <- timestamp(not_after) do
      {:ok, from, until}
    end
  end

  defp window(_), do: {:error, {:certificate, :malformed_validity}}

  # RFC 5280: UTCTime is two-digit, and a year of 50 or more means the 1900s.
  defp timestamp({:utcTime, value}) do
    case to_string(value) do
      <<yy::binary-size(2), rest::binary>> ->
        century = if String.to_integer(yy) >= 50, do: "19", else: "20"
        parse_time(century <> yy <> rest)

      _ ->
        {:error, {:certificate, :malformed_validity}}
    end
  end

  defp timestamp({:generalTime, value}), do: parse_time(to_string(value))
  defp timestamp(_), do: {:error, {:certificate, :malformed_validity}}

  defp parse_time(
         <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
           minute::binary-size(2), second::binary-size(2), "Z">>
       ) do
    with {:ok, date} <- Date.new(int(year), int(month), int(day)),
         {:ok, time} <- Time.new(int(hour), int(minute), int(second)) do
      DateTime.new(date, time, "Etc/UTC")
    else
      _ -> {:error, {:certificate, :malformed_validity}}
    end
  end

  defp parse_time(_), do: {:error, {:certificate, :malformed_validity}}

  defp int(binary), do: String.to_integer(binary)

  # ── Checks ──────────────────────────────────────────────

  defp check(true, _reason), do: :ok
  defp check(value, _reason) when is_binary(value) and value != "", do: :ok
  defp check(_falsey, reason), do: {:error, reason}

  defp check_window(cert, now, profile) do
    cond do
      DateTime.compare(now, cert.not_before) == :lt -> {:error, {profile, :not_yet_valid}}
      DateTime.compare(now, cert.not_after) != :lt -> {:error, {profile, :expired}}
      true -> :ok
    end
  end

  defp check_lifetime(dsc) do
    days = DateTime.diff(dsc.not_after, dsc.not_before, :day)

    if days > @max_document_signer_days,
      do: {:error, {:dsc_profile, :validity_too_long}},
      else: :ok
  end

  # CA:TRUE with a path length of zero — an IACA signs document signers, never
  # another CA. 18013-5's PKI is deliberately two levels.
  defp check_ca(%{basic_constraints: {true, path_len}}) when path_len in [0, nil], do: :ok
  defp check_ca(_), do: {:error, {:iaca_profile, :basic_constraints}}

  defp check_not_ca(%{basic_constraints: {true, _}}), do: {:error, {:dsc_profile, :is_a_ca}}
  defp check_not_ca(_), do: :ok

  defp check_subject_agreement(dsc, iaca) do
    cond do
      is_nil(dsc.subject.country) ->
        {:error, {:dsc_profile, :missing_country}}

      dsc.subject.country != iaca.subject.country ->
        {:error, {:dsc_profile, :country_mismatch}}

      # Only constrained when the root declares one; see the doc on
      # `validate_document_signer/3`.
      not is_nil(iaca.subject.state) and dsc.subject.state != iaca.subject.state ->
        {:error, {:dsc_profile, :state_mismatch}}

      true ->
        :ok
    end
  end

  # ── Chain ───────────────────────────────────────────────

  # The DSC's own EKU is critical and OTP has no rule for `id-mdlDS`, so without
  # a `verify_fun` every conformant mDL chain fails as carrying an unknown
  # critical extension. Accepting exactly that OID — and nothing else — keeps
  # the rest of OTP's processing intact.
  defp verify_chain(dsc, iaca) do
    verify_fun = fn
      _cert, {:extension, {:Extension, @oid_extended_key_usage, _critical, usages}}, state ->
        if @mdl_document_signer_eku in List.wrap(usages),
          do: {:valid, state},
          else: {:unknown, state}

      _cert, {:extension, _extension}, state ->
        {:unknown, state}

      _cert, {:bad_cert, reason}, _state ->
        {:fail, reason}

      _cert, _event, state ->
        {:valid, state}
    end

    case :public_key.pkix_path_validation(iaca.der, [dsc.der], verify_fun: {verify_fun, []}) do
      {:ok, _} -> :ok
      {:error, {:bad_cert, reason}} -> {:error, {:dsc_profile, {:chain, reason}}}
      {:error, reason} -> {:error, {:dsc_profile, {:chain, reason}}}
    end
  end
end
