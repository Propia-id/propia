defmodule SovraWeb.Invitations.InvitationController do
  @moduledoc """
  Redeeming an invitation. Public: holding the token is the authorization, and
  the code emailed to the invited address is what makes a forwarded link
  useless to anyone else.

  The token travels in the body, never in the path or query, so it stays out of
  access logs.

  `accept` does not mint a session. It answers 201, and the client signs in
  through the ordinary login endpoint with the password it just set.
  """
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Auth.IssuerInvitations

  tags(["Invitations"])

  @token_body {"Invitation token", "application/json",
               %OpenApiSpex.Schema{
                 type: :object,
                 required: [:token],
                 properties: %{token: %OpenApiSpex.Schema{type: :string}}
               }}

  @email_response %OpenApiSpex.Schema{
    type: :object,
    properties: %{email: %OpenApiSpex.Schema{type: :string, format: :email}}
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  @validation_error %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      error: %OpenApiSpex.Schema{type: :string, example: "validation_error"},
      details: %OpenApiSpex.Schema{type: :object}
    }
  }

  operation(:lookup,
    summary: "Resolve an invitation token",
    description: """
    The address an invitation was issued for, so the form can show who is
    signing up. Answers 404 `invalid_invitation` for a token that is unknown,
    expired, already used or revoked, deliberately indistinguishable.
    """,
    request_body: @token_body,
    responses: %{
      200 => {"Invitation", "application/json", @email_response},
      404 => {"Not redeemable", "application/json", @error}
    }
  )

  operation(:request_code,
    summary: "Email a confirmation code",
    description: """
    Sends a 6-digit code to the invited address, valid for 15 minutes. Call
    again to resend: the new code supersedes the previous one and clears the
    attempts spent on it.
    """,
    request_body: @token_body,
    responses: %{
      200 => {"Code sent", "application/json", @email_response},
      404 => {"Not redeemable", "application/json", @error}
    }
  )

  operation(:accept,
    summary: "Redeem an invitation",
    description: """
    Creates the user, their organization, an `owner` membership and a first
    workspace whose keys and DID are provisioned asynchronously.

    The account's email comes from the invitation, not from this payload.
    """,
    request_body:
      {"Redemption", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:token, :code, :full_name, :organization_name, :password],
         properties: %{
           token: %OpenApiSpex.Schema{type: :string},
           code: %OpenApiSpex.Schema{type: :string, example: "123456"},
           full_name: %OpenApiSpex.Schema{type: :string, minLength: 1, maxLength: 200},
           organization_name: %OpenApiSpex.Schema{type: :string, minLength: 1, maxLength: 200},
           password: %OpenApiSpex.Schema{type: :string, minLength: 12}
         }
       }},
    responses: %{
      201 =>
        {"Account created", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             email: %OpenApiSpex.Schema{type: :string, format: :email},
             organization: %OpenApiSpex.Schema{
               type: :object,
               properties: %{
                 id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                 name: %OpenApiSpex.Schema{type: :string}
               }
             }
           }
         }},
      404 => {"Not redeemable", "application/json", @error},
      422 => {"Bad code or invalid fields", "application/json", @validation_error},
      429 => {"Code burnt by too many attempts", "application/json", @error}
    }
  )

  def lookup(conn, %{"token" => token}) do
    case IssuerInvitations.lookup(token) do
      {:ok, %{email: email}} -> json(conn, %{email: email})
      {:error, reason} -> error(conn, reason)
    end
  end

  def lookup(conn, _params), do: error(conn, :invalid_invitation)

  def request_code(conn, %{"token" => token}) do
    case IssuerInvitations.request_code(token) do
      {:ok, %{email: email}} -> json(conn, %{email: email})
      {:error, reason} -> error(conn, reason)
    end
  end

  def request_code(conn, _params), do: error(conn, :invalid_invitation)

  def accept(conn, %{"token" => token, "code" => code} = params) do
    attrs = %{
      full_name: params["full_name"],
      organization_name: params["organization_name"],
      password: params["password"]
    }

    case IssuerInvitations.accept(token, code, attrs) do
      {:ok, %{user: user, organization: organization}} ->
        conn
        |> put_status(201)
        |> json(%{
          email: user.email,
          organization: %{id: organization.id, name: organization.name}
        })

      {:error, reason} ->
        error(conn, reason)
    end
  end

  def accept(conn, _params), do: error(conn, :invalid_invitation)

  defp error(conn, %Ecto.Changeset{} = changeset) do
    conn
    |> put_status(422)
    |> json(%{error: "validation_error", details: changeset_errors(changeset)})
  end

  defp error(conn, :too_many_attempts) do
    conn |> put_status(429) |> json(%{error: "too_many_attempts"})
  end

  defp error(conn, reason) when reason in [:invalid_code, :code_expired, :code_not_requested] do
    conn |> put_status(422) |> json(%{error: to_string(reason)})
  end

  # Unknown, expired, used and revoked all land here as :invalid_invitation.
  defp error(conn, _reason) do
    conn |> put_status(404) |> json(%{error: "invalid_invitation"})
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
