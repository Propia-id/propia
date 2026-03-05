defmodule SovraWeb.Cosigner.SignController do
  use SovraWeb, :controller

  def sign(conn, %{"hash" => "0x" <> hex_hash}) do
    sovra_address = conn.assigns.current_holder.sovra_address

    with {:ok, hash} <- decode_hash(hex_hash),
         {:ok, sig} <- Sovra.Cosigner.cosign(sovra_address, hash) do
      json(conn, %{signature: format_signature(sig)})
    else
      {:error, :invalid_hash} ->
        conn |> put_status(400) |> json(%{error: "invalid_hash"})

      {:error, :invalid_hash_size} ->
        conn |> put_status(400) |> json(%{error: "hash_must_be_32_bytes"})

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  def sign(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_or_invalid_hash"})
  end

  defp decode_hash(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, <<hash::binary-size(32)>>} -> {:ok, hash}
      {:ok, _} -> {:error, :invalid_hash_size}
      :error -> {:error, :invalid_hash}
    end
  end

  defp format_signature(%{r: r, s: s}) do
    %{r: "0x" <> Base.encode16(r, case: :lower), s: "0x" <> Base.encode16(s, case: :lower)}
  end
end
