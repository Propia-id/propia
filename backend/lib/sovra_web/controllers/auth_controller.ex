defmodule SovraWeb.AuthController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  require Logger

  alias Sovra.Accounts
  alias Sovra.Auth.PasswordReset
  alias Sovra.Auth.RefreshTokens
  alias Sovra.Auth.UserSession
  alias Sovra.Workspaces

  tags(["Auth"])

  @auth_response %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      user: %OpenApiSpex.Schema{
        type: :object,
        properties: %{
          id: %OpenApiSpex.Schema{type: :string, format: :uuid},
          email: %OpenApiSpex.Schema{type: :string, format: :email},
          full_name: %OpenApiSpex.Schema{type: :string},
          is_admin: %OpenApiSpex.Schema{type: :boolean}
        }
      },
      workspaces: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :object}},
      current_workspace_id: %OpenApiSpex.Schema{type: :string, format: :uuid}
    }
  }

  @ok_response %OpenApiSpex.Schema{
    type: :object,
    properties: %{ok: %OpenApiSpex.Schema{type: :boolean, example: true}}
  }

  @validation_error %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      error: %OpenApiSpex.Schema{type: :string, example: "validation_error"},
      details: %OpenApiSpex.Schema{type: :object}
    }
  }

  @invalid_credentials %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string, example: "invalid_credentials"}}
  }

  @invalid_refresh %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string, example: "invalid_refresh"}}
  }

  @invalid_token_error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string, example: "invalid_or_expired_token"}}
  }

  operation(:register,
    summary: "User registration",
    description:
      "Create a user with a default organization (as owner) and a default workspace. Sets HTTP-only access and refresh cookies.",
    request_body:
      {"Registration", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:email, :password, :full_name],
         properties: %{
           email: %OpenApiSpex.Schema{type: :string, format: :email},
           password: %OpenApiSpex.Schema{type: :string, minLength: 12},
           full_name: %OpenApiSpex.Schema{type: :string, minLength: 1, maxLength: 200},
           workspace_name: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      201 => {"Registration success", "application/json", @auth_response},
      422 => {"Validation error", "application/json", @validation_error}
    }
  )

  operation(:login,
    summary: "Email/password login",
    description: "Authenticate by email + password. Sets HTTP-only access and refresh cookies.",
    request_body:
      {"Credentials", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:email, :password],
         properties: %{
           email: %OpenApiSpex.Schema{type: :string, format: :email},
           password: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      200 => {"Login success", "application/json", @auth_response},
      401 => {"Invalid credentials", "application/json", @invalid_credentials}
    }
  )

  operation(:logout,
    summary: "Logout",
    description: "Revoke the access token, revoke the refresh token, clear both cookies.",
    responses: %{200 => {"Logout success", "application/json", @ok_response}}
  )

  operation(:refresh,
    summary: "Refresh access token",
    description:
      "Rotate the refresh token: revoke the presented one, mint new access + refresh, update cookies.",
    responses: %{
      200 => {"Refresh success", "application/json", @auth_response},
      401 => {"Invalid refresh", "application/json", @invalid_refresh}
    }
  )

  operation(:password_reset_request,
    summary: "Request password reset",
    description:
      "Send a time-limited reset link to the user's email if it matches an account. Always returns 200 to avoid account enumeration.",
    request_body:
      {"Email", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:email],
         properties: %{email: %OpenApiSpex.Schema{type: :string, format: :email}}
       }},
    responses: %{200 => {"Request accepted", "application/json", @ok_response}}
  )

  operation(:password_reset_confirm,
    summary: "Confirm password reset",
    description:
      "Consume a single-use reset token and set a new password. Revokes all of the user's refresh tokens on success.",
    request_body:
      {"New password", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:token, :password],
         properties: %{
           token: %OpenApiSpex.Schema{type: :string},
           password: %OpenApiSpex.Schema{type: :string, minLength: 12}
         }
       }},
    responses: %{
      200 => {"Reset success", "application/json", @ok_response},
      422 => {"Invalid or expired token", "application/json", @invalid_token_error}
    }
  )

  @access_cookie "session"
  @refresh_cookie "refresh_token"
  @access_max_age 3600
  @refresh_max_age 14 * 24 * 3600
  # Cookie path covers /refresh AND /logout so the cookie is sent on both.
  @refresh_cookie_path "/api/v1/auth"

  def register(conn, params) do
    case Accounts.register_user(params) do
      {:ok, %{user: user, workspace: workspace}} ->
        # Use the same listing query as login/refresh so the response shape is
        # symmetric (organization_id, webhook_url, role columns all present).
        # Note: the workspace's webhook_secret is intentionally NOT returned —
        # registering a new account isn't the right surface to reveal a
        # one-time API secret. Users rotate via the workspace settings UI.
        workspaces = Workspaces.list_workspaces_for_user(user.id)

        conn
        |> set_auth_cookies(user, workspace.id)
        |> put_status(201)
        |> json(%{
          user: user_payload(user),
          workspaces: workspaces,
          current_workspace_id: workspace.id
        })

      {:error, %Ecto.Changeset{errors: errors} = changeset} ->
        if email_taken?(errors) do
          # Don't disclose existence — respond with a generic message that
          # doesn't tell the caller whether the email is registered.
          conn
          |> put_status(422)
          |> json(%{
            error: "registration_failed",
            message:
              "Could not create account. If you already have one, sign in or reset your password."
          })
        else
          # Real per-field validation errors (password length, full_name, etc.)
          # Strip any `:email` key as belt-and-braces — we never want this
          # endpoint to disclose email-existence via field-level errors.
          details = changeset |> changeset_errors() |> Map.delete(:email)

          conn
          |> put_status(422)
          |> json(%{error: "validation_error", details: details})
        end

      {:error, reason} ->
        Logger.error("register_user failed with non-changeset reason: #{inspect(reason)}")
        conn |> put_status(422) |> json(%{error: "registration_failed"})
    end
  end

  defp email_taken?(errors) do
    Enum.any?(errors, fn
      {:email, {"has already been taken", _}} -> true
      _ -> false
    end)
  end

  def login(conn, %{"email" => email, "password" => password}) do
    case Accounts.authenticate(email, password) do
      {:ok, user} ->
        workspaces = Workspaces.list_workspaces_for_user(user.id)
        current_workspace_id = workspaces |> List.first() |> get_in([Access.key(:id)])

        conn
        |> set_auth_cookies(user, current_workspace_id)
        |> json(%{
          user: user_payload(user),
          workspaces: workspaces,
          current_workspace_id: current_workspace_id
        })

      {:error, :invalid_credentials} ->
        conn |> put_status(401) |> json(%{error: "invalid_credentials"})
    end
  end

  def logout(conn, _params) do
    conn = fetch_cookies(conn)

    if access = conn.cookies[@access_cookie] do
      UserSession.revoke(access)
    end

    if refresh = conn.cookies[@refresh_cookie] do
      RefreshTokens.revoke(refresh)
    end

    conn
    |> delete_resp_cookie(@access_cookie, path: "/api/v1")
    |> delete_resp_cookie(@refresh_cookie, path: @refresh_cookie_path)
    |> json(%{ok: true})
  end

  def refresh(conn, _params) do
    conn = fetch_cookies(conn)

    case conn.cookies[@refresh_cookie] do
      nil ->
        conn |> put_status(401) |> json(%{error: "invalid_refresh"})

      plaintext ->
        case RefreshTokens.rotate(plaintext) do
          {:ok, user_id, new_refresh, _new_record} ->
            case Accounts.get_user(user_id) do
              nil ->
                conn |> put_status(401) |> json(%{error: "invalid_refresh"})

              user ->
                workspaces = Workspaces.list_workspaces_for_user(user.id)
                current_workspace_id = workspaces |> List.first() |> get_in([Access.key(:id)])
                {:ok, access} = UserSession.create(user.id, current_workspace_id, user.is_admin)

                conn
                |> put_resp_cookie(@access_cookie, access, access_cookie_opts())
                |> put_resp_cookie(@refresh_cookie, new_refresh, refresh_cookie_opts())
                |> json(%{
                  user: user_payload(user),
                  workspaces: workspaces,
                  current_workspace_id: current_workspace_id
                })
            end

          {:error, _reason} ->
            # Clear cookies so a compromised or stale client can't keep retrying.
            conn
            |> delete_resp_cookie(@access_cookie, path: "/api/v1")
            |> delete_resp_cookie(@refresh_cookie, path: @refresh_cookie_path)
            |> put_status(401)
            |> json(%{error: "invalid_refresh"})
        end
    end
  end

  def password_reset_request(conn, %{"email" => email}) when is_binary(email) do
    :ok = PasswordReset.request(email)
    json(conn, %{ok: true})
  end

  def password_reset_request(conn, _params) do
    json(conn, %{ok: true})
  end

  def password_reset_confirm(conn, %{"token" => token, "password" => password})
      when is_binary(token) and is_binary(password) do
    case PasswordReset.confirm(token, password) do
      {:ok, _user} ->
        json(conn, %{ok: true})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})

      {:error, _} ->
        conn |> put_status(422) |> json(%{error: "invalid_or_expired_token"})
    end
  end

  def password_reset_confirm(conn, _params) do
    conn |> put_status(422) |> json(%{error: "invalid_or_expired_token"})
  end

  # ── helpers ────────────────────────────────────────────

  defp set_auth_cookies(conn, user, workspace_id) do
    {:ok, access} = UserSession.create(user.id, workspace_id, user.is_admin)
    {:ok, refresh, _record} = RefreshTokens.create(user.id)

    conn
    |> put_resp_cookie(@access_cookie, access, access_cookie_opts())
    |> put_resp_cookie(@refresh_cookie, refresh, refresh_cookie_opts())
  end

  defp access_cookie_opts do
    [
      http_only: true,
      secure: Application.get_env(:sovra, :env) == :prod,
      same_site: "Strict",
      path: "/api/v1",
      max_age: @access_max_age
    ]
  end

  defp refresh_cookie_opts do
    [
      http_only: true,
      secure: Application.get_env(:sovra, :env) == :prod,
      same_site: "Strict",
      path: @refresh_cookie_path,
      max_age: @refresh_max_age
    ]
  end

  defp user_payload(user) do
    %{id: user.id, email: user.email, full_name: user.full_name, is_admin: user.is_admin}
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
