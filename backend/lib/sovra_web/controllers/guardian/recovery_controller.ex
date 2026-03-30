defmodule SovraWeb.Guardian.RecoveryController do
  use SovraWeb, :controller

  def initiate_recovery(conn, %{
        "newKeyX" => new_key_x_hex,
        "newKeyY" => new_key_y_hex,
        "keyToReplace" => key_to_replace
      })
      when key_to_replace in [0, 1] do
    sovra_address = conn.assigns.current_holder.sovra_address

    with {:ok, new_key_x} <- decode_hex(new_key_x_hex),
         {:ok, new_key_y} <- decode_hex(new_key_y_hex) do
      case Sovra.Guardian.initiate_recovery(sovra_address, %{
             new_key_x: new_key_x,
             new_key_y: new_key_y,
             key_to_replace: key_to_replace
           }) do
        {:ok, result} ->
          json(conn, %{signature: result.signature, messageHash: result.message_hash})

        {:error, :holder_not_found} ->
          conn |> put_status(404) |> json(%{error: "holder_not_found"})

        {:error, :recovery_pending} ->
          conn |> put_status(422) |> json(%{error: "recovery_already_pending"})

        {:error, _} ->
          conn |> put_status(500) |> json(%{error: "internal_error"})
      end
    else
      _ ->
        conn |> put_status(400) |> json(%{error: "invalid_key_parameters"})
    end
  end

  def initiate_recovery(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end

  def finalize(conn, _params) do
    sovra_address = conn.assigns.current_holder.sovra_address

    case Sovra.Guardian.finalize_recovery(sovra_address) do
      {:ok, result} ->
        json(conn, %{signature: result.signature, messageHash: result.message_hash})

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, :not_in_recovery} ->
        conn |> put_status(422) |> json(%{error: "not_in_recovery"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  defp decode_hex("0x" <> hex), do: Base.decode16(hex, case: :mixed)
  defp decode_hex(hex), do: Base.decode16(hex, case: :mixed)
end
