defmodule SovraWeb.Cosigner.RotateController do
  use SovraWeb, :controller

  def rotate(conn, _params) do
    sovra_address = conn.assigns.current_holder.sovra_address

    case Sovra.Cosigner.rotate_recovery_key(sovra_address) do
      {:ok, result} ->
        json(conn, %{
          newRecoveryPublicKey: result.new_recovery_public_key,
          rotationSignature: result.rotation_signature
        })

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end
end
