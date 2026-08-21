defmodule SovraWeb.Invitations.AdminInvitationController do
  @moduledoc """
  Issuing and cancelling invitations. Super-admin only, because authorizing a
  new issuer is Sovra's decision rather than an organization's.

  The token is never returned here: it exists only in the email. To hand
  someone a fresh link, revoke and invite again.
  """
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Auth.IssuerInvitations

  tags(["Invitations"])
  security([%{"SessionCookie" => []}])

  @invitation %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      email: %OpenApiSpex.Schema{type: :string, format: :email},
      expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
      invited_by_user_id: %OpenApiSpex.Schema{type: :string, format: :uuid, nullable: true},
      inserted_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"}
    }
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  operation(:create,
    summary: "Invite someone to create an issuer organization",
    description: """
    Authorizes one address to create an issuer account and emails it a link,
    valid for 48 hours.

    Answers 409 when the address already has an account (`already_registered`)
    or an invitation still pending (`already_invited`).
    """,
    request_body:
      {"Invitation", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:email],
         properties: %{email: %OpenApiSpex.Schema{type: :string, format: :email}}
       }},
    responses: %{
      201 => {"Invitation sent", "application/json", @invitation},
      403 => {"Not an admin", "application/json", @error},
      409 => {"Already registered or invited", "application/json", @error},
      422 => {"Validation error", "application/json", @error}
    }
  )

  operation(:index,
    summary: "List invitations still redeemable",
    responses: %{
      200 =>
        {"Invitations", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             invitations: %OpenApiSpex.Schema{type: :array, items: @invitation}
           }
         }},
      403 => {"Not an admin", "application/json", @error}
    }
  )

  operation(:revoke,
    summary: "Cancel a pending invitation",
    parameters: [id: [in: :path, type: :string, required: true]],
    responses: %{
      204 => {"Revoked", nil, nil},
      403 => {"Not an admin", "application/json", @error},
      404 => {"Unknown invitation", "application/json", @error},
      409 => {"Already redeemed", "application/json", @error}
    }
  )

  def create(conn, %{"email" => email}) when is_binary(email) do
    case IssuerInvitations.create(email, conn.assigns.current_user.user_id) do
      {:ok, invitation} ->
        conn |> put_status(201) |> json(invitation_json(invitation))

      {:error, reason} when reason in [:already_registered, :already_invited] ->
        conn |> put_status(409) |> json(%{error: to_string(reason)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def create(conn, _params) do
    conn |> put_status(422) |> json(%{error: "email_required"})
  end

  def index(conn, _params) do
    json(conn, %{invitations: Enum.map(IssuerInvitations.list_pending(), &invitation_json/1)})
  end

  def revoke(conn, %{"id" => id}) do
    case IssuerInvitations.revoke(id) do
      {:ok, _invitation} -> conn |> put_status(204) |> text("")
      {:error, :not_found} -> conn |> put_status(404) |> json(%{error: "invitation_not_found"})
      {:error, :already_used} -> conn |> put_status(409) |> json(%{error: "already_used"})
      {:error, _reason} -> conn |> put_status(422) |> json(%{error: "revoke_failed"})
    end
  end

  defp invitation_json(invitation) do
    %{
      id: invitation.id,
      email: invitation.email,
      expires_at: invitation.expires_at,
      invited_by_user_id: invitation.invited_by_user_id,
      inserted_at: invitation.inserted_at
    }
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
