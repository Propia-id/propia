defmodule SovraWeb.Cosigner.RecoveryController do
  use SovraWeb, :controller

  def initiate_recovery(conn, %{"newPasskeyPublicKey" => %{"x" => x_b64, "y" => y_b64}}) do
    sovra_address = conn.assigns.current_holder.sovra_address

    with {:ok, x} <- Base.decode64(x_b64, padding: false),
         {:ok, y} <- Base.decode64(y_b64, padding: false) do
      case Sovra.Cosigner.initiate_recovery(sovra_address, %{x: x, y: y}) do
        {:ok, result} ->
          json(conn, %{signature: result.signature})

        {:error, :holder_not_found} ->
          conn |> put_status(404) |> json(%{error: "holder_not_found"})

        {:error, _} ->
          conn |> put_status(500) |> json(%{error: "internal_error"})
      end
    else
      _ ->
        conn |> put_status(400) |> json(%{error: "invalid_public_key_encoding"})
    end
  end

  def initiate_recovery(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end
end
