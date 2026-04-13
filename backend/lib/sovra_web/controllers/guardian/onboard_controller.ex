defmodule SovraWeb.Guardian.OnboardController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  tags(["Holder"])

  operation(:onboard,
    summary: "Onboard holder",
    description:
      "Register a new holder. Returns a recovery public key and session token for new holders (201), or the existing address and session for already-linked accounts (200).",
    request_body:
      {"Onboard params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:sovraAddress, :oauthToken],
         properties: %{
           sovraAddress: %OpenApiSpex.Schema{
             type: :string,
             description: "Holder's Sovra contract address"
           },
           oauthToken: %OpenApiSpex.Schema{type: :string, description: "Google ID token"}
         }
       }},
    responses: %{
      201 =>
        {"New holder onboarded", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             recoveryPublicKey: %OpenApiSpex.Schema{
               type: :string,
               description: "Hex-encoded recovery public key"
             },
             sessionToken: %OpenApiSpex.Schema{type: :string}
           }
         }},
      200 =>
        {"Existing holder linked", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             sovraAddress: %OpenApiSpex.Schema{type: :string},
             sessionToken: %OpenApiSpex.Schema{type: :string}
           }
         }},
      400 =>
        {"Missing fields", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      401 =>
        {"Invalid OAuth token", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      409 =>
        {"Already onboarded", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string, example: "already_onboarded"}}
         }}
    }
  )

  def onboard(conn, %{"sovraAddress" => sovra_address, "oauthToken" => oauth_token}) do
    case Sovra.Guardian.onboard(sovra_address, oauth_token) do
      {:ok, %{recovery_public_key: _} = result} ->
        conn
        |> put_status(201)
        |> json(%{
          recoveryPublicKey: result.recovery_public_key,
          sessionToken: result.session_token
        })

      {:ok, %{sovra_address: _} = result} ->
        conn
        |> put_status(200)
        |> json(%{
          sovraAddress: result.sovra_address,
          sessionToken: result.session_token
        })

      {:error, :already_onboarded} ->
        conn |> put_status(409) |> json(%{error: "already_onboarded"})

      {:error, :invalid_id_token} ->
        conn |> put_status(401) |> json(%{error: "invalid_oauth_token"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  def onboard(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end
end
