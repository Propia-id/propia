defmodule SovraWeb.AuthControllerTest do
  use SovraWeb.ConnCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  import Swoosh.TestAssertions

  alias Sovra.Accounts.User
  alias Sovra.Auth.MailerJob
  alias Sovra.Auth.PasswordReset
  alias Sovra.Auth.RefreshTokens
  alias Sovra.Organizations.Organization

  describe "POST /dashboard/auth/register" do
    setup do
      # Reset the per-IP rate limit bucket so tests in this describe don't
      # collide on the 5/min/IP cap.
      Hammer.delete_buckets("rate_limit:/dashboard/auth/register:127.0.0.1")
      :ok
    end

    test "creates user, default org, default workspace, sets cookies, sends welcome email",
         %{conn: conn} do
      email = "reg-#{System.unique_integer([:positive])}@example.com"

      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/register", %{
          "email" => email,
          "password" => "a-very-strong-password-123",
          "full_name" => "Riley Register"
        })

      resp = json_response(conn, 201)
      assert resp["user"]["email"] == email
      assert resp["user"]["full_name"] == "Riley Register"
      assert resp["user"]["is_admin"] == false
      assert is_binary(resp["current_workspace_id"])
      assert [_workspace] = resp["workspaces"]

      cookies = conn.resp_cookies
      # Session cookie is scoped to /dashboard so every dashboard endpoint
      # receives it; refresh cookie is scoped to /dashboard/auth so it only
      # travels on refresh/logout.
      assert %{value: _, http_only: true, path: "/dashboard"} = cookies["session"]
      assert %{value: _, http_only: true, path: "/dashboard/auth"} = cookies["refresh_token"]

      assert_enqueued(worker: MailerJob, args: %{"kind" => "welcome"})
    end

    test "returns 422 on validation error", %{conn: conn} do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/register", %{
          "email" => "x",
          "password" => "short",
          "full_name" => ""
        })

      resp = json_response(conn, 422)
      assert resp["error"] == "validation_error"
      assert resp["details"]
      # Defense in depth: never expose email field-level errors from this endpoint.
      refute Map.has_key?(resp["details"] || %{}, "email")
    end

    test "duplicate email → generic 422 (no enumeration)", %{conn: conn} do
      email = "dup-#{System.unique_integer([:positive])}@example.com"

      # First registration succeeds.
      conn
      |> put_req_header("content-type", "application/json")
      |> post("/dashboard/auth/register", %{
        "email" => email,
        "password" => "a-very-strong-password-123",
        "full_name" => "First Person"
      })
      |> json_response(201)

      # Second attempt with the same email returns a generic message.
      conn2 =
        build_conn()
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/register", %{
          "email" => email,
          "password" => "a-different-strong-password-456",
          "full_name" => "Second Person"
        })

      resp = json_response(conn2, 422)
      assert resp["error"] == "registration_failed"
      assert resp["message"] =~ "Could not create account"
      # Crucially, no field-level disclosure of "email has already been taken".
      refute Map.has_key?(resp, "details")
    end

    test "case-insensitive email uniqueness — Foo@x and foo@x are duplicates",
         %{conn: conn} do
      base = "case-#{System.unique_integer([:positive])}"

      conn
      |> put_req_header("content-type", "application/json")
      |> post("/dashboard/auth/register", %{
        "email" => "#{base}@example.com",
        "password" => "a-very-strong-password-123",
        "full_name" => "Lower Case"
      })
      |> json_response(201)

      conn2 =
        build_conn()
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/register", %{
          "email" => "#{String.upcase(base)}@EXAMPLE.COM",
          "password" => "a-different-strong-password-456",
          "full_name" => "Upper Case"
        })

      # citext makes the unique constraint case-insensitive, so the
      # duplicate-email path triggers regardless of case.
      resp = json_response(conn2, 422)
      assert resp["error"] == "registration_failed"
    end
  end

  describe "POST /dashboard/auth/register with registration disabled" do
    setup do
      Hammer.delete_buckets("rate_limit:/dashboard/auth/register:127.0.0.1")

      previous = Application.get_env(:sovra, :registration_enabled)
      Application.put_env(:sovra, :registration_enabled, false)
      on_exit(fn -> Application.put_env(:sovra, :registration_enabled, previous) end)
      :ok
    end

    test "403 and provisions nothing", %{conn: conn} do
      email = "closed-#{System.unique_integer([:positive])}@example.com"
      orgs_before = Sovra.Repo.aggregate(Organization, :count)

      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/register", %{
          "email" => email,
          "password" => "a-very-strong-password-123",
          "full_name" => "Nope Nobody"
        })

      resp = json_response(conn, 403)
      assert resp["error"] == "registration_disabled"

      # The whole provisioning fan-out (org, workspace, keys, DID, on-chain
      # issuer registration, welcome mail) hangs off register_user/1, so
      # nothing downstream may run either.
      refute Sovra.Repo.get_by(User, email: email)
      assert Sovra.Repo.aggregate(Organization, :count) == orgs_before
      refute conn.resp_cookies["session"]
      refute conn.resp_cookies["refresh_token"]
      refute_enqueued(worker: MailerJob, args: %{"kind" => "welcome"})
    end

    test "existing users can still log in", %{conn: conn} do
      email = "existing-#{System.unique_integer([:positive])}@example.com"

      {:ok, _user} =
        User.registration_changeset(%{
          email: email,
          password: "a-very-strong-password-123",
          full_name: "Ada Already"
        })
        |> Sovra.Repo.insert()

      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/login", %{
          "email" => email,
          "password" => "a-very-strong-password-123"
        })

      assert json_response(conn, 200)["user"]["email"] == email
    end
  end

  describe "POST /dashboard/auth/login" do
    setup do
      email = "login-#{System.unique_integer([:positive])}@example.com"

      {:ok, _u} =
        User.registration_changeset(%{
          email: email,
          password: "a-very-strong-password-123",
          full_name: "Lou Login"
        })
        |> Sovra.Repo.insert()

      %{email: email}
    end

    test "valid credentials → 200 with cookies and user payload", %{conn: conn, email: email} do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/login", %{
          "email" => email,
          "password" => "a-very-strong-password-123"
        })

      resp = json_response(conn, 200)
      assert resp["user"]["email"] == email
      assert is_list(resp["workspaces"])
      assert conn.resp_cookies["session"]
      assert conn.resp_cookies["refresh_token"]
    end

    test "wrong password → 401", %{conn: conn, email: email} do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/login", %{"email" => email, "password" => "nope-nope-nope"})

      assert json_response(conn, 401) == %{"error" => "invalid_credentials"}
    end
  end

  describe "POST /dashboard/auth/refresh" do
    test "rotates refresh token and mints new access cookie", %{conn: conn} do
      email = "rf-#{System.unique_integer([:positive])}@example.com"

      {:ok, user} =
        User.registration_changeset(%{
          email: email,
          password: "a-very-strong-password-123",
          full_name: "Rae Refresh"
        })
        |> Sovra.Repo.insert()

      {:ok, refresh_plaintext, _record} = RefreshTokens.create(user.id)

      conn =
        conn
        |> put_req_cookie("refresh_token", refresh_plaintext)
        |> post("/dashboard/auth/refresh")

      resp = json_response(conn, 200)
      assert resp["user"]["email"] == email
      assert conn.resp_cookies["session"]
      assert %{value: new_refresh} = conn.resp_cookies["refresh_token"]
      assert new_refresh != refresh_plaintext

      # Re-presenting the original (already-rotated) refresh token is treated as
      # reuse — the entire family for that user is revoked.
      assert {:error, :reuse_detected} = RefreshTokens.rotate(refresh_plaintext)
    end

    test "missing cookie → 401", %{conn: conn} do
      conn = post(conn, "/dashboard/auth/refresh")
      assert json_response(conn, 401) == %{"error" => "invalid_refresh"}
    end

    test "garbage cookie → 401", %{conn: conn} do
      conn =
        conn
        |> put_req_cookie("refresh_token", "garbage")
        |> post("/dashboard/auth/refresh")

      assert json_response(conn, 401) == %{"error" => "invalid_refresh"}
    end

    test "valid refresh token but the user has been deleted → 401", %{conn: conn} do
      email = "rfd-#{System.unique_integer([:positive])}@example.com"

      {:ok, user} =
        User.registration_changeset(%{
          email: email,
          password: "a-very-strong-password-123",
          full_name: "Roo Removed"
        })
        |> Sovra.Repo.insert()

      {:ok, refresh_plaintext, _} = RefreshTokens.create(user.id)

      # User is gone (the refresh_tokens row cascades via on_delete: :delete_all,
      # but we mint the token first then delete to simulate a stale rotation
      # where Accounts.get_user/1 returns nil).
      Sovra.Repo.delete!(user)

      # The cascading delete also dropped the refresh_token row, so the rotate
      # itself returns :invalid. Either way the controller returns 401 and
      # clears cookies — that's the contract we care about for this branch.
      conn =
        conn
        |> put_req_cookie("refresh_token", refresh_plaintext)
        |> post("/dashboard/auth/refresh")

      assert json_response(conn, 401) == %{"error" => "invalid_refresh"}
      # Deletion must target the same paths as the cookies set originally,
      # otherwise the browser keeps the stale cookies.
      assert %{max_age: 0, path: "/dashboard"} = conn.resp_cookies["session"]
      assert %{max_age: 0, path: "/dashboard/auth"} = conn.resp_cookies["refresh_token"]
    end
  end

  describe "POST /dashboard/auth/password/reset-request" do
    test "always returns 200 (no enumeration) and enqueues a mailer for known email",
         %{conn: conn} do
      email = "reset-#{System.unique_integer([:positive])}@example.com"

      {:ok, _} =
        User.registration_changeset(%{
          email: email,
          password: "a-very-strong-password-123",
          full_name: "Pat Reset"
        })
        |> Sovra.Repo.insert()

      conn = post(conn, "/dashboard/auth/password/reset-request", %{"email" => email})
      assert json_response(conn, 200) == %{"ok" => true}

      assert_enqueued(worker: MailerJob, args: %{"kind" => "password_reset"})
    end

    test "returns 200 for unknown email and does NOT enqueue", %{conn: conn} do
      conn =
        post(conn, "/dashboard/auth/password/reset-request", %{
          "email" => "ghost-#{System.unique_integer([:positive])}@example.com"
        })

      assert json_response(conn, 200) == %{"ok" => true}
      refute_enqueued(worker: MailerJob)
    end
  end

  describe "POST /dashboard/auth/password/reset" do
    test "consumes token, updates password, sends mailer", %{conn: conn} do
      email = "rcfm-#{System.unique_integer([:positive])}@example.com"

      {:ok, _} =
        User.registration_changeset(%{
          email: email,
          password: "a-very-strong-password-123",
          full_name: "Pat Reset"
        })
        |> Sovra.Repo.insert()

      :ok = PasswordReset.request(email)
      [%Oban.Job{args: args} = job] = all_enqueued(worker: MailerJob)
      {:ok, token} = Sovra.Auth.ArgsCrypto.decrypt(args["encrypted_token"])

      # Drain the mailer job → email is actually delivered via Swoosh.Test.
      assert :ok = perform_job(MailerJob, job.args)
      assert_email_sent(subject: "Reset your Sovra password")

      conn =
        post(conn, "/dashboard/auth/password/reset", %{
          "token" => token,
          "password" => "a-new-strong-password-456"
        })

      assert json_response(conn, 200) == %{"ok" => true}

      # A password-changed notification is enqueued
      assert_enqueued(worker: MailerJob, args: %{"kind" => "password_changed"})

      # Login with the new password works
      conn =
        build_conn()
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/login", %{
          "email" => email,
          "password" => "a-new-strong-password-456"
        })

      assert json_response(conn, 200)
    end

    test "invalid token → 422", %{conn: conn} do
      conn =
        post(conn, "/dashboard/auth/password/reset", %{
          "token" => "definitely-not-real",
          "password" => "a-new-strong-password-456"
        })

      assert json_response(conn, 422) == %{"error" => "invalid_or_expired_token"}
    end
  end

  describe "POST /dashboard/auth/logout" do
    test "clears cookies and revokes tokens", %{conn: conn} do
      email = "lo-#{System.unique_integer([:positive])}@example.com"

      {:ok, _} =
        User.registration_changeset(%{
          email: email,
          password: "a-very-strong-password-123",
          full_name: "Lex Out"
        })
        |> Sovra.Repo.insert()

      login_conn =
        build_conn()
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/login", %{
          "email" => email,
          "password" => "a-very-strong-password-123"
        })

      session = login_conn.resp_cookies["session"][:value]
      refresh = login_conn.resp_cookies["refresh_token"][:value]

      conn =
        conn
        |> put_req_cookie("session", session)
        |> put_req_cookie("refresh_token", refresh)
        |> post("/dashboard/auth/logout")

      assert json_response(conn, 200) == %{"ok" => true}
      # Cookies are cleared with max_age: 0 at the same paths used to set them.
      assert %{max_age: 0, path: "/dashboard"} = conn.resp_cookies["session"]
      assert %{max_age: 0, path: "/dashboard/auth"} = conn.resp_cookies["refresh_token"]

      # The refresh token is revoked server-side too — re-presenting it fails.
      assert {:error, _} = RefreshTokens.rotate(refresh)
    end
  end

  describe "Origin allow-list (CSRF defense-in-depth)" do
    setup do
      # Reset the Hammer rate-limit bucket so prior tests don't interfere.
      Hammer.delete_buckets("rate_limit:/dashboard/auth/refresh:127.0.0.1")
      :ok
    end

    test "rejects POST with a foreign Origin header", %{conn: conn} do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> put_req_header("origin", "https://attacker.example")
        |> post("/dashboard/auth/refresh")

      assert json_response(conn, 403) == %{"error" => "origin_not_allowed"}
    end

    test "allows POST with a missing Origin header (e.g. server-to-server)", %{conn: conn} do
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post("/dashboard/auth/refresh")

      # Doesn't 403 from the origin plug; gets a normal auth failure instead
      # (no refresh cookie present).
      assert json_response(conn, 401)
    end
  end
end
