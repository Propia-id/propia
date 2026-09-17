defmodule Sovra.Cose.Key do
  @moduledoc """
  `COSE_Key` (RFC 9052 §7) for P-256, the only curve Sovra uses.

  mDoc carries the holder's public key here — `MSO.deviceKeyInfo.deviceKey` —
  where SD-JWT VC carries a `cnf` DID reference instead. That difference is why
  `Sovra.Issuer.Issuer.verify_proof/2` has to surrender the coordinates it
  extracts from the OID4VCI proof rather than discarding them.
  """

  alias Sovra.Cbor

  # RFC 9053 §7.1: kty=EC2(2), crv=P-256(1). Labels: kty=1, crv=-1, x=-2, y=-3.
  @kty_ec2 2
  @crv_p256 1
  @coord_size 32

  @doc "Build a `COSE_Key` map for the P-256 point `(x, y)`."
  @spec p256(binary(), binary()) :: map()
  def p256(<<x::binary-size(@coord_size)>>, <<y::binary-size(@coord_size)>>) do
    %{1 => @kty_ec2, -1 => @crv_p256, -2 => Cbor.bstr(x), -3 => Cbor.bstr(y)}
  end

  @doc """
  Extract `{x, y}` from a decoded `COSE_Key`.

  Accepts coordinates either as raw binaries or as decoded `bstr` tags, since
  which one you get depends on whether the map came off the wire or out of
  `p256/2`.
  """
  @spec parse_p256(term()) :: {:ok, {binary(), binary()}} | {:error, :unsupported_cose_key}
  def parse_p256(%{1 => @kty_ec2, -1 => @crv_p256, -2 => x, -3 => y}) do
    with {:ok, x} <- coordinate(x),
         {:ok, y} <- coordinate(y) do
      {:ok, {x, y}}
    end
  end

  def parse_p256(_), do: {:error, :unsupported_cose_key}

  defp coordinate(%CBOR.Tag{tag: :bytes, value: <<bin::binary-size(@coord_size)>>}),
    do: {:ok, bin}

  defp coordinate(<<bin::binary-size(@coord_size)>>), do: {:ok, bin}
  defp coordinate(_), do: {:error, :unsupported_cose_key}
end
