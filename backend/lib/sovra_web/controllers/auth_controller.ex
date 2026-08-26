defmodule SovraWeb.AuthController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  require Logger

  alias Sovra.Accounts
  alias Sovra.Auth.PasswordReset
  alias Sovra.Auth.RefreshTokens
  alias Sovra.Auth.UserSession
  alias Sovra.Workspaces

  # Registration provisions an organization (plus workspace, keys, DID and an
  # on-chain issuer registration), so it gets its own kill switch alongside
  # ORGANIZATION_CREATION_ENABLED on POST /dashboard/organizations. 403 (not
  # 404): the route stays a documented part of the dashboard API, the
  # capability is what's withdrawn. Gated here rather than in
  # Accounts.register_user/1 — the admin issuer-account endpoint calls that
  # same function and must keep working while self-service is closed.
  plug :ensure_registration_enabled when action == :register

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

  @registration_disabled %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      error: %OpenApiSpex.Schema{type: :string, example: "registration_disabled"},
      message: %OpenApiSpex.Schema{type: :string}
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
    description: """
    Create a user with a default organization (as owner) and a default workspace.
    Sets HTTP-only access and refresh cookies.

    Signing up provisions an organization, so deployments can close it:
    answers 403 `registration_disabled` when REGISTRATION_ENABLED=false.
    Existing users keep logging in either way.
    """,
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
      403 => {"Registration disabled", "application/json", @registration_disabled},
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
  @refresh_cookie_path "/dashboard/auth"
  # Access cookie path covers the dashboard surface (the only callers that
  # need a session JWT). Narrower than the previous "/api/v1" — API-key
  # endpoints never need the session cookie.
  @access_cookie_path "/dashboard"
  # The same access token again, scoped to the document endpoints, because a
  # private document has to open for a logged-in person following a link and a
  # cookie is only sent to its own path. Kept as a second cookie rather than
  # widening the one above, which would send the session to every endpoint.
  @document_cookie "document_session"
  @document_cookie_path "/api/v1/documents"

  defp ensure_registration_enabled(conn, _opts) do
    if Application.get_env(:sovra, :registration_enabled, true) == true do
      conn
    else
      conn
      |> put_status(403)
      |> json(%{
        error: "registration_disabled",
        message: "Sign-up is disabled. Contact your administrator for an account."
      })
      |> halt()
    end
  end

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

        Logger.info("[Auth] login ok user_id=#{user.id} workspace=#{current_workspace_id}")

        conn
        |> set_auth_cookies(user, current_workspace_id)
        |> json(%{
          user: user_payload(user),
          workspaces: workspaces,
          current_workspace_id: current_workspace_id
        })

      {:error, :invalid_credentials} ->
        # No email here: these logs leave the host for New Relic.
        Logger.info("[Auth] login failed reason=invalid_credentials")
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
    |> delete_access_cookies()
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
                |> put_access_cookies(access)
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
            |> delete_access_cookies()
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
    |> put_access_cookies(access)
    |> put_resp_cookie(@refresh_cookie, refresh, refresh_cookie_opts())
  end

  # The access token goes out twice, under the two paths that need it.
  defp put_access_cookies(conn, access) do
    conn
    |> put_resp_cookie(@access_cookie, access, access_cookie_opts())
    |> put_resp_cookie(@document_cookie, access, document_cookie_opts())
  end

  defp delete_access_cookies(conn) do
    conn
    |> delete_resp_cookie(@access_cookie, path: @access_cookie_path)
    |> delete_resp_cookie(@document_cookie, path: @document_cookie_path)
  end

  defp access_cookie_opts do
    [
      http_only: true,
      secure: Application.get_env(:sovra, :env) == :prod,
      same_site: "Strict",
      path: @access_cookie_path,
      max_age: @access_max_age
    ]
  end

  defp document_cookie_opts,
    do: Keyword.put(access_cookie_opts(), :path, @document_cookie_path)

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
