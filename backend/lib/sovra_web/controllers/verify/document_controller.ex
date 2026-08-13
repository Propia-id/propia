defmodule SovraWeb.Verify.DocumentController do
  @moduledoc """
  Lookup of a signed document, backing the verification link.

  Serves the credential and no verdict. A verdict would have to be trusted; the
  credential can be checked. We can fail to respond, but we cannot lie: altering
  a byte breaks the signature, and the signature is anchored on-chain.

  The id is a UUIDv4, so the link is a capability: 122 bits of entropy make it
  unguessable, and for a `public` document holding it is the only authorization
  needed. A `private` one also requires a session on both actions.
  """

  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Documents

  tags(["Signed Documents"])

  # Overrides the spec-wide API key requirement: holding the id is the authorization.
  security([])

  @document_response %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      credential: %OpenApiSpex.Schema{
        type: :string,
        description:
          "The signed document, as an SD-JWT VC with no disclosures: `<jwt>~`. " <>
            "The only field here worth trusting on its own, since everything else " <>
            "is the issuer's word and this can be checked against the chain."
      },
      issuer: %OpenApiSpex.Schema{
        type: :object,
        properties: %{
          did: %OpenApiSpex.Schema{type: :string},
          name: %OpenApiSpex.Schema{type: :string},
          address: %OpenApiSpex.Schema{type: :string}
        }
      },
      schema: %OpenApiSpex.Schema{
        type: :object,
        properties: %{
          name: %OpenApiSpex.Schema{type: :string},
          claims: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :object}}
        }
      },
      layout: %OpenApiSpex.Schema{
        type: :object,
        nullable: true,
        description: "Where the fields sit on the page. Presentation only, not signed."
      },
      anchor: %OpenApiSpex.Schema{
        type: :object,
        properties: %{
          status: %OpenApiSpex.Schema{
            type: :string,
            enum: ["signed", "anchored", "failed", "revoked"]
          },
          tx_hash: %OpenApiSpex.Schema{type: :string, nullable: true},
          anchored_at: %OpenApiSpex.Schema{type: :string, format: :"date-time", nullable: true}
        }
      }
    }
  }

  @not_found %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string, example: "document_not_found"}}
  }

  operation(:show,
    summary: "Fetch a signed document",
    description:
      "Serves the credential so a verifier can check it, never a verdict. " <>
        "Answers `Access-Control-Allow-Origin: *`, so a browser must send no credentials.",
    parameters: [
      id: [in: :path, type: :string, description: "Document UUID", required: true]
    ],
    responses: %{
      200 => {"Signed document", "application/json", @document_response},
      401 =>
        {"The document is private and the request carries no session", "application/json",
         @not_found},
      404 => {"No document with that id", "application/json", @not_found}
    }
  )

  def show(conn, %{"id" => id}) do
    # Readable from any origin: a verifier's app lives on a domain we cannot know.
    # Safe because the response carries no cookies and no secrets, and the
    # credential is meant to be public to whoever holds the link.
    conn = put_resp_header(conn, "access-control-allow-origin", "*")

    with {:ok, uuid} <- cast_uuid(id),
         {:ok, document} <- Documents.get_public(uuid),
         :ok <- authorize(conn, document) do
      json(conn, %{
        id: document.id,
        credential: document.credential,
        # Hints for rendering only. Anything served here is our word, so a
        # verifier has to decode the credential itself.
        issuer: %{
          did: document.workspace.did,
          name: document.workspace.name,
          address: document.workspace.eoa_address
        },
        schema: %{name: document.schema.name, claims: document.schema.claims},
        # Presentation only, and not covered by the signature. A consumer can
        # render the verified claims however it likes and ignore this entirely.
        layout: Documents.layout_for(document.schema_id),
        anchor: %{
          status: document.status,
          tx_hash: document.tx_hash,
          anchored_at: document.anchored_at && DateTime.to_iso8601(document.anchored_at)
        }
      })
    else
      {:error, :unauthenticated} ->
        conn |> put_status(:unauthorized) |> json(%{error: "authentication_required"})

      _ ->
        conn |> put_status(:not_found) |> json(%{error: "document_not_found"})
    end
  end

  @doc """
  The same document, rendered. Paste the URL in a browser or fetch it from an
  agent: no auth, no client side rendering, nothing to install.

  A convenience, not the source of truth. The page is our rendering of the
  claims; `show/2` serves the credential itself for anyone who wants to check
  the signature rather than trust the page.
  """
  operation(:page,
    summary: "The document rendered as a page",
    description:
      "A self-contained A4 sheet: the issuer's layout, a provenance footer, and a QR " <>
        "carrying the whole credential. Our rendering of the claims, not the source of " <>
        "truth. Sent with a strict CSP that forbids scripts and framing.",
    parameters: [
      id: [in: :path, type: :string, description: "Document UUID", required: true],
      print: [
        in: :query,
        type: :string,
        description:
          "`1` or `true` opens the browser print dialog on load, which is where a PDF comes from",
        required: false
      ]
    ],
    responses: %{
      200 => {"The rendered page", "text/html", %OpenApiSpex.Schema{type: :string}},
      401 =>
        {"The document is private and the request carries no session", "text/html",
         %OpenApiSpex.Schema{type: :string}},
      404 => {"No document with that id", "text/html", %OpenApiSpex.Schema{type: :string}}
    }
  )

  def page(conn, %{"id" => id} = params) do
    conn = put_resp_header(conn, "access-control-allow-origin", "*")

    with {:ok, uuid} <- cast_uuid(id),
         {:ok, document} <- Documents.get_public(uuid),
         :ok <- authorize(conn, document) do
      # `?print=1` opens the print dialog, which is where a PDF comes from.
      print = params["print"] in ["1", "true"]

      conn
      |> put_resp_content_type("text/html")
      |> put_resp_header("content-security-policy", SovraWeb.DocumentPage.csp(print: print))
      |> send_resp(200, SovraWeb.DocumentPage.render(document, print: print))
    else
      {:error, :unauthenticated} ->
        conn
        |> put_resp_content_type("text/html")
        |> send_resp(
          401,
          "<!DOCTYPE html><title>Sign in</title><p>This document is private. " <>
            "Sign in to the dashboard and open the link again."
        )

      _ ->
        conn
        |> put_resp_content_type("text/html")
        |> send_resp(404, "<!DOCTYPE html><title>Not found</title><p>No document with that id.")
    end
  end

  # A public document is readable by whoever holds the id. A private one also
  # needs a session, so the issuer's layout is not readable by everyone a link
  # reaches. Only our endpoints are gated: a credential already handed out stays
  # verifiable against the chain by anyone holding it.
  #
  # The session arrives in `document_session`, the copy of the access cookie
  # scoped to this path, since the dashboard's own cookie is never sent here.
  @session_cookie "document_session"

  defp authorize(_conn, %{visibility: "public"}), do: :ok

  defp authorize(conn, _document) do
    with token when is_binary(token) <-
           SovraWeb.Plugs.UserSessionPlug.session_token(conn, @session_cookie),
         {:ok, _claims} <- Sovra.Auth.UserSession.verify(token) do
      :ok
    else
      _ -> {:error, :unauthenticated}
    end
  end

  defp cast_uuid(id) do
    case Ecto.UUID.cast(id) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> :error
    end
  end
end
