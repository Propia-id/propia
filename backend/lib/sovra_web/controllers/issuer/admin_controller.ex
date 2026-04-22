defmodule SovraWeb.Issuer.AdminController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer
  alias Sovra.Issuer.Accounts

  tags(["Issuer Admin"])
  security([%{"IssuerCookieAuth" => []}])

  operation(:create_issuer_account,
    summary: "Create issuer account (super-admin)",
    description: "Create a new issuer account. Requires admin role.",
    request_body:
      {"Issuer account params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:email, :password, :issuer_name],
         properties: %{
           email: %OpenApiSpex.Schema{type: :string, format: :email},
           password: %OpenApiSpex.Schema{type: :string},
           issuer_name: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      201 =>
        {"Issuer created", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             issuer: %OpenApiSpex.Schema{
               type: :object,
               properties: %{
                 id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                 name: %OpenApiSpex.Schema{type: :string},
                 did: %OpenApiSpex.Schema{type: :string},
                 status: %OpenApiSpex.Schema{type: :string}
               }
             },
             email: %OpenApiSpex.Schema{type: :string}
           }
         }},
      422 =>
        {"Validation error", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             error: %OpenApiSpex.Schema{type: :string},
             details: %OpenApiSpex.Schema{type: :object}
           }
         }}
    }
  )

  operation(:get_issuer,
    summary: "Get issuer profile",
    description: "Get the authenticated issuer's profile.",
    responses: %{
      200 =>
        {"Issuer profile", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             name: %OpenApiSpex.Schema{type: :string},
             did: %OpenApiSpex.Schema{type: :string},
             eoa_address: %OpenApiSpex.Schema{type: :string},
             status: %OpenApiSpex.Schema{type: :string}
           }
         }},
      404 =>
        {"Issuer not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:create_schema,
    summary: "Create credential schema",
    description: "Create a new credential schema for the authenticated issuer.",
    request_body:
      {"Schema params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:schema_id, :credential_type, :name, :claims],
         properties: %{
           schema_id: %OpenApiSpex.Schema{type: :string},
           credential_type: %OpenApiSpex.Schema{type: :string},
           name: %OpenApiSpex.Schema{type: :string},
           claims: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :object}},
           validity_period: %OpenApiSpex.Schema{type: :string, example: "1y"}
         }
       }},
    responses: %{
      201 =>
        {"Schema created", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             schema_id: %OpenApiSpex.Schema{type: :string},
             credential_type: %OpenApiSpex.Schema{type: :string},
             name: %OpenApiSpex.Schema{type: :string},
             claims: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :object}},
             validity_period: %OpenApiSpex.Schema{type: :string}
           }
         }},
      422 =>
        {"Validation error", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             error: %OpenApiSpex.Schema{type: :string},
             details: %OpenApiSpex.Schema{type: :object}
           }
         }}
    }
  )

  operation(:list_schemas,
    summary: "List credential schemas",
    description: "List all credential schemas for the authenticated issuer.",
    responses: %{
      200 =>
        {"Schema list", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             schemas: %OpenApiSpex.Schema{
               type: :array,
               items: %OpenApiSpex.Schema{
                 type: :object,
                 properties: %{
                   id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                   schema_id: %OpenApiSpex.Schema{type: :string},
                   credential_type: %OpenApiSpex.Schema{type: :string},
                   name: %OpenApiSpex.Schema{type: :string},
                   claims: %OpenApiSpex.Schema{
                     type: :array,
                     items: %OpenApiSpex.Schema{type: :object}
                   },
                   validity_period: %OpenApiSpex.Schema{type: :string},
                   version: %OpenApiSpex.Schema{type: :integer}
                 }
               }
             }
           }
         }}
    }
  )

  operation(:delete_schema,
    summary: "Delete credential schema",
    description: "Delete a credential schema by ID.",
    parameters: [
      id: [in: :path, type: :string, description: "Schema UUID", required: true]
    ],
    responses: %{
      204 => {"Schema deleted", nil, nil},
      404 =>
        {"Schema not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:create_offer,
    summary: "Create credential offer",
    description: "Create a credential offer for a holder from the admin panel.",
    request_body:
      {"Offer params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:schema_id, :holder_did],
         properties: %{
           schema_id: %OpenApiSpex.Schema{type: :string},
           holder_did: %OpenApiSpex.Schema{type: :string},
           claims: %OpenApiSpex.Schema{type: :object}
         }
       }},
    responses: %{
      201 =>
        {"Offer created", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             status: %OpenApiSpex.Schema{type: :string},
             holder_did: %OpenApiSpex.Schema{type: :string},
             offer_uri: %OpenApiSpex.Schema{type: :string},
             pre_authorized_code: %OpenApiSpex.Schema{type: :string},
             expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"}
           }
         }},
      404 =>
        {"Not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      422 =>
        {"Validation error", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:list_offers,
    summary: "List credential offers",
    description: "List all credential offers for the authenticated issuer.",
    responses: %{
      200 =>
        {"Offer list", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             offers: %OpenApiSpex.Schema{
               type: :array,
               items: %OpenApiSpex.Schema{
                 type: :object,
                 properties: %{
                   id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                   holder_did: %OpenApiSpex.Schema{type: :string},
                   status: %OpenApiSpex.Schema{type: :string},
                   expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
                   inserted_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
                   schema: %OpenApiSpex.Schema{
                     type: :object,
                     properties: %{
                       id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                       credential_type: %OpenApiSpex.Schema{type: :string},
                       name: %OpenApiSpex.Schema{type: :string}
                     }
                   }
                 }
               }
             }
           }
         }}
    }
  )

  operation(:list_issued_credentials,
    summary: "List issued credentials",
    description: "List all credentials issued by the authenticated issuer.",
    responses: %{
      200 =>
        {"Credential list", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             credentials: %OpenApiSpex.Schema{
               type: :array,
               items: %OpenApiSpex.Schema{
                 type: :object,
                 properties: %{
                   id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                   holder_did: %OpenApiSpex.Schema{type: :string},
                   status: %OpenApiSpex.Schema{type: :string},
                   issued_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
                   expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
                   schema: %OpenApiSpex.Schema{
                     type: :object,
                     properties: %{
                       id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                       credential_type: %OpenApiSpex.Schema{type: :string},
                       name: %OpenApiSpex.Schema{type: :string}
                     }
                   }
                 }
               }
             }
           }
         }}
    }
  )

  def create_issuer_account(conn, %{
        "email" => email,
        "password" => password,
        "issuer_name" => issuer_name
      }) do
    case Accounts.register_issuer(email, password, issuer_name) do
      {:ok, %{token: _token, account: _account, issuer: issuer}} ->
        conn
        |> put_status(201)
        |> json(%{
          issuer: %{id: issuer.id, name: issuer.name, did: issuer.did, status: issuer.status},
          email: String.downcase(email)
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})

      {:error, _reason} ->
        conn |> put_status(422) |> json(%{error: "registration_failed"})
    end
  end

  def list_issuers(conn, _params) do
    issuers = Issuer.list_issuers()

    json(conn, %{
      issuers:
        Enum.map(issuers, fn i ->
          %{id: i.id, name: i.name, did: i.did, status: i.status, email: i.email}
        end)
    })
  end

  def get_issuer(conn, _params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id

    case Issuer.get_issuer(issuer_id) do
      {:ok, issuer} ->
        json(conn, %{
          id: issuer.id,
          name: issuer.name,
          did: issuer.did,
          eoa_address: issuer.eoa_address,
          status: issuer.status
        })

      {:error, _} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})
    end
  end

  def create_schema(conn, params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id

    attrs = %{
      schema_id: params["schema_id"],
      credential_type: params["credential_type"],
      name: params["name"],
      claims: normalize_claims(params["claims"]),
      validity_period: to_string(params["validity_period"] || "1y")
    }

    case Issuer.create_schema(issuer_id, attrs) do
      {:ok, schema} ->
        conn
        |> put_status(201)
        |> json(%{
          id: schema.id,
          schema_id: schema.schema_id,
          credential_type: schema.credential_type,
          name: schema.name,
          claims: schema.claims,
          validity_period: schema.validity_period
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})

      {:error, _reason} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  def list_schemas(conn, _params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id
    schemas = Issuer.list_schemas(issuer_id)

    json(conn, %{
      schemas:
        Enum.map(schemas, fn s ->
          %{
            id: s.id,
            schema_id: s.schema_id,
            credential_type: s.credential_type,
            name: s.name,
            claims: s.claims,
            validity_period: s.validity_period,
            version: s.version
          }
        end)
    })
  end

  def delete_schema(conn, %{"id" => schema_id}) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id

    case Issuer.delete_schema(issuer_id, schema_id) do
      {:ok, _} ->
        conn |> put_status(204) |> text("")

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})
    end
  end

  def create_offer(conn, params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id

    case Issuer.create_credential_offer(
           issuer_id,
           params["schema_id"],
           params["claims"] || %{}
         ) do
      {:ok, %{offer: offer, offer_uri: offer_uri, pre_authorized_code: code}} ->
        conn
        |> put_status(201)
        |> json(%{
          id: offer.id,
          status: offer.status,
          offer_uri: offer_uri,
          pre_authorized_code: code,
          expires_at: DateTime.to_iso8601(offer.expires_at)
        })

      {:error, {:missing_claims, missing}} ->
        conn |> put_status(422) |> json(%{error: "missing_claims", details: missing})

      {:error, :key_not_found} ->
        conn
        |> put_status(500)
        |> json(%{
          error: "signing_key_not_found",
          message:
            "Issuer signing key is unavailable. Re-register the issuer if the server was restarted."
        })

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})

      {:error, :issuer_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: to_string(reason)})
    end
  end

  def list_offers(conn, _params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id
    offers = Issuer.list_offers(issuer_id)

    json(conn, %{
      offers:
        Enum.map(offers, fn o ->
          %{
            id: o.id,
            status: o.status,
            expires_at: DateTime.to_iso8601(o.expires_at),
            inserted_at: DateTime.to_iso8601(o.inserted_at),
            schema: %{
              id: o.schema.id,
              credential_type: o.schema.credential_type,
              name: o.schema.name
            }
          }
        end)
    })
  end

  operation(:revoke_credential,
    summary: "Revoke a credential",
    description: "Permanently revoke a credential. Sets the revocation bit on-chain.",
    parameters: [
      id: [in: :path, type: :string, description: "Credential UUID", required: true]
    ],
    responses: %{
      200 =>
        {"Credential revoked", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             status: %OpenApiSpex.Schema{type: :string}
           }
         }},
      404 =>
        {"Credential not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      422 =>
        {"Invalid transition", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:suspend_credential,
    summary: "Suspend a credential",
    description: "Temporarily suspend a credential. Can be reversed with unsuspend.",
    parameters: [
      id: [in: :path, type: :string, description: "Credential UUID", required: true]
    ],
    responses: %{
      200 =>
        {"Credential suspended", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             status: %OpenApiSpex.Schema{type: :string}
           }
         }},
      404 =>
        {"Credential not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      422 =>
        {"Invalid transition", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:unsuspend_credential,
    summary: "Unsuspend a credential",
    description: "Reverse a suspension, restoring the credential to active status.",
    parameters: [
      id: [in: :path, type: :string, description: "Credential UUID", required: true]
    ],
    responses: %{
      200 =>
        {"Credential unsuspended", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             id: %OpenApiSpex.Schema{type: :string, format: :uuid},
             status: %OpenApiSpex.Schema{type: :string}
           }
         }},
      404 =>
        {"Credential not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      422 =>
        {"Invalid transition", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  def list_issued_credentials(conn, _params) do
    issuer_id = conn.assigns.current_issuer_account.issuer_id
    credentials = Issuer.list_issued_credentials(issuer_id)

    json(conn, %{
      credentials:
        Enum.map(credentials, fn c ->
          %{
            id: c.id,
            holder_did: c.holder_did,
            status: c.status,
            issued_at: DateTime.to_iso8601(c.issued_at),
            expires_at: DateTime.to_iso8601(c.expires_at),
            schema: %{
              id: c.schema.id,
              credential_type: c.schema.credential_type,
              name: c.schema.name
            }
          }
        end)
    })
  end

  def revoke_credential(conn, %{"id" => id}) do
    handle_status_change(conn, &Issuer.revoke_credential/1, id)
  end

  def suspend_credential(conn, %{"id" => id}) do
    handle_status_change(conn, &Issuer.suspend_credential/1, id)
  end

  def unsuspend_credential(conn, %{"id" => id}) do
    handle_status_change(conn, &Issuer.unsuspend_credential/1, id)
  end

  defp handle_status_change(conn, action, credential_id) do
    case action.(credential_id) do
      {:ok, cred} ->
        json(conn, %{id: cred.id, status: cred.status})

      {:error, :credential_not_found} ->
        conn |> put_status(404) |> json(%{error: "credential_not_found"})

      {:error, :invalid_status_transition} ->
        conn |> put_status(422) |> json(%{error: "invalid_status_transition"})

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: to_string(reason)})
    end
  end

  defp normalize_claims(%{"claims" => claims}) when is_list(claims), do: claims
  defp normalize_claims(claims) when is_list(claims), do: claims
  defp normalize_claims(other), do: other

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
