defmodule Sovra.Cbor do
  @moduledoc """
  Deterministic CBOR encoding, for ISO/IEC 18013-5 mDoc.

  The `:cbor` dependency encodes map pairs in Erlang map iteration order
  (`deps/cbor/lib/cbor/encoder.ex`, `defimpl CBOR.Encoder, for: Map`), which is
  not deterministic. mDoc needs determinism: the `SessionTranscript` is built
  independently by the wallet and the verifier from the same inputs, so a
  key-order difference there yields signatures that verify against nothing.

  This module therefore owns encoding end to end rather than delegating nested
  values back to `CBOR.Encoder` — a map nested inside a list would otherwise
  slip into the non-deterministic path. Decoding still delegates.

  ## Map key ordering

  RFC 7049 §3.9 canonical: sort by the *encoded* key, shorter encodings first,
  then bytewise. RFC 8949 §4.2.1 core-deterministic drops the length-first step
  and is purely bytewise; the two orderings coincide for every map mDoc actually
  emits (COSE headers, COSE_Key, all-text-key maps, all-uint digest maps).
  Switching profiles is `key_order/1` and nothing else.

  Sorting is *our* choice, not a requirement. 18013-5 adopts three of RFC 7049
  §3.9's four canonical rules — shortest integers, shortest lengths for major
  types 2 through 5, definite-length items — and says of the fourth that "the
  rule regarding sorting of map keys is not required" (§7.2 in the DIS; the
  published edition renumbers). It buys us a deterministic encoder, which the
  session transcript depends on. It does not license assuming a third-party
  wallet sorted, and it is exactly why a signed map must never be re-encoded.

  ## Re-encoding: safe for embedded CBOR, never for maps

  The dependency's decoder is lossy: tag 0 becomes a `DateTime` (dropping the
  original string form), tags 2 and 3 become integers, tag 32 becomes a `URI`.
  A decoded value is therefore not a faithful stand-in for the bytes it came
  from, and anything hashed or signed has to be handled deliberately. The two
  cases differ, and conflating them is how this gets misread:

    * **Maps must be kept verbatim.** Key order is unconstrained by 18013-5, so
      a conformant issuer may emit header keys in any order and re-encoding a
      decoded map through `key_order/1` can reorder it — changing the bytes a
      signature covers. `Sovra.Cose.Sign1` keeps `protected_bytes` as received
      for this reason, and that is an invariant rather than an optimisation.

    * **`#6.24(bstr .cbor ...)` wrappers can be rebuilt**, because the payload is
      an opaque byte string the decoder never looks inside. Rebuilding is in fact
      *normalising*: both heads come back shortest-form, the only form 18013-5
      permits, so the result equals what a conformant issuer signed even if a
      transport rewrote the heads. `embed_encoded/1` is that rebuild.

  Floats are rejected rather than encoded. They have no deterministic form
  without shortest-float selection logic, and mDoc never needs them — failing
  loudly beats emitting something a verifier hashes differently.
  """

  defmodule EncodeError do
    @moduledoc "Raised when a value has no deterministic CBOR encoding."
    defexception [:value]

    @impl true
    def message(%{value: value}) do
      "no deterministic CBOR encoding for #{inspect(value)}"
    end
  end

  @doc """
  Encode a value as deterministic CBOR. Raises `EncodeError` on anything
  without a deterministic form (floats, bare atoms, unsupported structs).
  """
  @spec encode(term()) :: binary()
  def encode(value), do: enc(value, <<>>)

  @doc "Non-raising `encode/1`, for paths that validate caller-supplied data."
  @spec safe_encode(term()) :: {:ok, binary()} | {:error, {:unencodable, term()}}
  def safe_encode(value) do
    {:ok, encode(value)}
  rescue
    e in EncodeError -> {:error, {:unencodable, e.value}}
  end

  @doc """
  Decode CBOR, rejecting trailing bytes.

  A decoder that silently ignores trailing data is a signature-bypass vector
  for length-prefixed structures, so this is stricter than `CBOR.decode/1`.
  """
  @spec decode(binary()) :: {:ok, term()} | {:error, atom()}
  def decode(binary) when is_binary(binary) do
    case CBOR.decode(binary) do
      {:ok, value, ""} -> {:ok, value}
      {:ok, _value, _rest} -> {:error, :trailing_bytes}
      {:error, reason} -> {:error, reason}
    end
  end

  def decode(_), do: {:error, :not_a_binary}

  @doc "Mark a binary as a CBOR byte string (major type 2) rather than text."
  @spec bstr(binary()) :: CBOR.Tag.t()
  def bstr(bin) when is_binary(bin), do: %CBOR.Tag{tag: :bytes, value: bin}

  @doc """
  Wrap a value as `#6.24(bstr .cbor value)` — embedded CBOR.

  mDoc hashes and signs over these wrappers, never over the bare inner value,
  so this, `embed_encoded/1` and `unwrap_embedded/1` are the only places tag 24
  is handled.
  """
  @spec embed(term()) :: CBOR.Tag.t()
  def embed(value), do: embed_encoded(encode(value))

  @doc """
  Wrap **already-encoded** CBOR as `#6.24(bstr .cbor ...)`.

  `embed/1` when the value still needs encoding; this when the bytes came off
  the wire and must not be re-encoded — see the moduledoc on why rebuilding a
  wrapper around untouched payload bytes is safe, and normalising.
  """
  @spec embed_encoded(binary()) :: CBOR.Tag.t()
  def embed_encoded(bytes) when is_binary(bytes), do: %CBOR.Tag{tag: 24, value: bstr(bytes)}

  @doc "Inverse of `embed/1`: pull the raw inner bytes out of a tag-24 wrapper."
  @spec unwrap_embedded(term()) :: {:ok, binary()} | :error
  def unwrap_embedded(%CBOR.Tag{tag: 24, value: %CBOR.Tag{tag: :bytes, value: bin}})
      when is_binary(bin),
      do: {:ok, bin}

  def unwrap_embedded(_), do: :error

  @doc "A `tdate` (tag 0), truncated to the second as 18013-5 requires."
  @spec tdate(DateTime.t()) :: CBOR.Tag.t()
  def tdate(%DateTime{} = dt) do
    %CBOR.Tag{tag: 0, value: dt |> DateTime.truncate(:second) |> DateTime.to_iso8601()}
  end

  @doc "A `full-date` (tag 1004), the `YYYY-MM-DD` form mDoc uses for dates."
  @spec full_date(String.t()) :: CBOR.Tag.t()
  def full_date(<<_::binary-size(10)>> = date), do: %CBOR.Tag{tag: 1004, value: date}

  # ── Encoder ─────────────────────────────────────────────
  #
  # Clause order matters: the struct clauses must precede the generic map
  # clause, which is why that one guards on `not is_struct/1`.

  # Major types 0 and 1 — integers. `encode_head/3` already picks the shortest
  # head, which is what determinism requires.
  defp enc(n, acc) when is_integer(n) and n >= 0, do: CBOR.Utils.encode_head(0, n, acc)
  defp enc(n, acc) when is_integer(n), do: CBOR.Utils.encode_head(1, -1 - n, acc)

  # Major type 2 — byte strings, reachable only through `bstr/1`. Keeping bstr
  # behind a constructor is what stops a binary meant as bytes from silently
  # encoding as text (or the reverse), which would change every digest over it.
  defp enc(%CBOR.Tag{tag: :bytes, value: bin}, acc) when is_binary(bin),
    do: CBOR.Utils.encode_string(2, bin, acc)

  # Major type 6 — tags.
  defp enc(%CBOR.Tag{tag: tag, value: value}, acc) when is_integer(tag) and tag >= 0,
    do: enc(value, CBOR.Utils.encode_head(6, tag, acc))

  defp enc(%DateTime{} = dt, acc), do: enc(tdate(dt), acc)

  # Major type 3 — text strings.
  defp enc(bin, acc) when is_binary(bin), do: CBOR.Utils.encode_string(3, bin, acc)

  # Major type 4 — arrays.
  defp enc(list, acc) when is_list(list),
    do: Enum.reduce(list, CBOR.Utils.encode_head(4, length(list), acc), &enc/2)

  # Major type 5 — maps, canonically ordered.
  defp enc(map, acc) when is_map(map) and not is_struct(map) do
    map
    |> Enum.map(fn {k, v} -> {enc(k, <<>>), v} end)
    |> Enum.sort_by(fn {key_bytes, _v} -> key_order(key_bytes) end)
    |> Enum.reduce(CBOR.Utils.encode_head(5, map_size(map), acc), fn {key_bytes, v}, inner ->
      enc(v, <<inner::binary, key_bytes::binary>>)
    end)
  end

  # Major type 7 — the three simple values mDoc uses.
  defp enc(false, acc), do: <<acc::binary, 0xF4>>
  defp enc(true, acc), do: <<acc::binary, 0xF5>>
  defp enc(nil, acc), do: <<acc::binary, 0xF6>>

  defp enc(value, _acc), do: raise(EncodeError, value: value)

  # RFC 7049 §3.9: shorter encoded keys first, then bytewise.
  defp key_order(key_bytes), do: {byte_size(key_bytes), key_bytes}
end
