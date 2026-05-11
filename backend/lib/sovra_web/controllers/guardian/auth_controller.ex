defmodule SovraWeb.Guardian.AuthController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  tags(["Holder"])

  operation(:login,
    summary: "Authenticate holder",
    description:
      "Two authentication flows: (1) Send `oauth_token` for native mobile flow — verifies the ID token and returns a session. (2) Send `sovraAddress` for browser flow — returns a Google OAuth authorization URL.",
    request_body:
      {"Auth params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         properties: %{
           oauth_token: %OpenApiSpex.Schema{
             type: :string,
             description: "Google ID token (native flow)"
           },
           sovraAddress: %OpenApiSpex.Schema{
             type: :string,
             description: "Holder address (browser flow)"
           }
         }
       }},
    responses: %{
      200 =>
        {"Auth response", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             sessionToken: %OpenApiSpex.Schema{type: :string},
             expiresAt: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
             authorizationUrl: %OpenApiSpex.Schema{type: :string}
           }
         }},
      400 =>
        {"Missing fields", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      401 =>
        {"Invalid token", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      404 =>
        {"Holder not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:callback,
    summary: "OAuth callback",
    description: "Handle the Google OAuth callback after browser-based authentication.",
    request_body:
      {"Callback params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:code, :state],
         properties: %{
           code: %OpenApiSpex.Schema{type: :string},
           state: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      200 =>
        {"Session token", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{session: %OpenApiSpex.Schema{type: :string}}
         }},
      400 =>
        {"Missing fields", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      403 =>
        {"OAuth mismatch", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      404 =>
        {"Holder not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  # Native mobile flow: verify ID token directly, issue session
  def login(conn, %{"oauth_token" => oauth_token}) do
    case Sovra.Guardian.authenticate_with_token(oauth_token) do
      {:ok, %{session_token: session_token, expires_at: expires_at}} ->
        json(conn, %{sessionToken: session_token, expiresAt: expires_at})

      {:error, :invalid_id_token} ->
        conn |> put_status(401) |> json(%{error: "invalid_oauth_token"})

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  # Browser-based flow: redirect to Google OAuth
  def login(conn, %{"sovraAddress" => sovra_address}) do
    case Sovra.Guardian.get_auth_url(sovra_address) do
      {:ok, url} ->
        json(conn, %{authorizationUrl: url})

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  def login(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end

  def callback(conn, %{"code" => code, "state" => state}) do
    case Sovra.Guardian.handle_auth_callback(code, state) do
      {:ok, session_token} ->
        json(conn, %{session: session_token})

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, :oauth_mismatch} ->
        conn |> put_status(403) |> json(%{error: "oauth_identity_mismatch"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  def callback(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end
end
