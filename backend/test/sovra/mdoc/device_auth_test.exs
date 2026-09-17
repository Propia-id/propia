defmodule Sovra.Mdoc.DeviceAuthTest do
  use ExUnit.Case, async: true

  alias Sovra.Cbor
  alias Sovra.Mdoc.DeviceAuth

  defp device_signature do
    [
      Cbor.bstr(Cbor.encode(%{1 => -7})),
      %{},
      nil,
      Cbor.bstr(:binary.copy(<<0>>, 64))
    ]
  end

  test "a DeviceNameSpaces value with no deterministic encoding is rejected, not raised" do
    # It comes off the wire, so a holder can send a float. Encoding it used to
    # raise out of the verification pipeline, which loses the session rather
    # than failing it.
    assert DeviceAuth.verify(
             %{"deviceSignature" => device_signature()},
             [nil, nil],
             "io.sovra.0xabc.card.1",
             1.5,
             []
           ) == {:error, :malformed_device_auth}
  end

  test "a well-formed DeviceNameSpaces reaches signature verification" do
    assert DeviceAuth.verify(
             %{"deviceSignature" => device_signature()},
             [nil, nil],
             "io.sovra.0xabc.card.1",
             Cbor.embed(%{}),
             []
           ) == {:error, :holder_key_mismatch}
  end
end
