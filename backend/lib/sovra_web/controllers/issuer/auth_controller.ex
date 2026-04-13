defmodule SovraWeb.Issuer.AuthController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer.Accounts
  alias Sovra.Auth.IssuerSession

  tags(["Issuer Auth"])

  operation(:login,
    summary: "Issuer login",
    description:
      "Authenticate an issuer account. Returns admin role or issuer profile. Sets an HTTP-only session cookie.",
    request_body:
      {"Login credentials", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:email, :password],
         properties: %{
           email: %OpenApiSpex.Schema{type: :string, format: :email},
           password: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      200 =>
        {"Login success", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             role: %OpenApiSpex.Schema{type: :string, example: "admin"},
             issuer: %OpenApiSpex.Schema{
               type: :object,
               properties: %{
                 id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                 name: %OpenApiSpex.Schema{type: :string},
                 did: %OpenApiSpex.Schema{type: :string},
                 status: %OpenApiSpex.Schema{type: :string}
               }
             }
           }
         }},
      401 =>
        {"Invalid credentials", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             error: %OpenApiSpex.Schema{type: :string, example: "invalid_credentials"}
           }
         }}
    }
  )

  operation(:logout,
    summary: "Issuer logout",
    description: "Revoke the current issuer session and clear the session cookie.",
    responses: %{
      200 =>
        {"Logout success", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{ok: %OpenApiSpex.Schema{type: :boolean, example: true}}
         }}
    }
  )

  @cookie_name "issuer_session"
  @cookie_opts [
    http_only: true,
    secure: Application.compile_env(:sovra, :env) == :prod,
    same_site: "Strict",
    path: "/api/v1/issuer",
    max_age: 3600
  ]

  def login(conn, %{"email" => email, "password" => password}) do
    case Accounts.authenticate(email, password) do
      {:ok, %{token: token, role: "admin"}} ->
        conn
        |> put_resp_cookie(@cookie_name, token, @cookie_opts)
        |> json(%{role: "admin"})

      {:ok, %{token: token, issuer: issuer}} ->
        conn
        |> put_resp_cookie(@cookie_name, token, @cookie_opts)
        |> json(%{
          issuer: %{id: issuer.id, name: issuer.name, did: issuer.did, status: issuer.status}
        })

      {:error, :invalid_credentials} ->
        conn |> put_status(401) |> json(%{error: "invalid_credentials"})
    end
  end

  def logout(conn, _params) do
    # Revoke the current session token if present
    conn = fetch_cookies(conn)

    if token = conn.cookies[@cookie_name] do
      IssuerSession.revoke(token)
    end

    conn
    |> delete_resp_cookie(@cookie_name, path: "/api/v1/issuer")
    |> json(%{ok: true})
  end
end
