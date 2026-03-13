defmodule SovraWeb.Guardian.RecoveryController do
  use SovraWeb, :controller

  def initiate_recovery(conn, %{"messageHash" => hash_hex}) do
    sovra_address = conn.assigns.current_holder.sovra_address

    with {:ok, message_hash} <- decode_hex(hash_hex) do
      case Sovra.Guardian.initiate_recovery(sovra_address, message_hash) do
        {:ok, result} ->
          json(conn, %{signature: result.signature})

        {:error, :holder_not_found} ->
          conn |> put_status(404) |> json(%{error: "holder_not_found"})

        {:error, _} ->
          conn |> put_status(500) |> json(%{error: "internal_error"})
      end
    else
      _ ->
        conn |> put_status(400) |> json(%{error: "invalid_message_hash"})
    end
  end

  def initiate_recovery(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end

  def finalize(conn, %{"messageHash" => hash_hex}) do
    sovra_address = conn.assigns.current_holder.sovra_address

    with {:ok, message_hash} <- decode_hex(hash_hex) do
      case Sovra.Guardian.finalize_recovery(sovra_address, message_hash) do
        {:ok, result} ->
          json(conn, %{signature: result.signature})

        {:error, :holder_not_found} ->
          conn |> put_status(404) |> json(%{error: "holder_not_found"})

        {:error, :not_in_recovery} ->
          conn |> put_status(422) |> json(%{error: "not_in_recovery"})

        {:error, _} ->
          conn |> put_status(500) |> json(%{error: "internal_error"})
      end
    else
      _ ->
        conn |> put_status(400) |> json(%{error: "invalid_message_hash"})
    end
  end

  def finalize(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end

  defp decode_hex("0x" <> hex), do: Base.decode16(hex, case: :mixed)
  defp decode_hex(hex), do: Base.decode16(hex, case: :mixed)
end
