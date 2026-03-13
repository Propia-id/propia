defmodule Sovra.Guardian do
  @moduledoc """
  Guardian server context. Orchestrates onboarding, authentication,
  blind hash co-signing, key rotation, and recovery.
  """

  alias Sovra.Guardian.HolderRecord
  alias Sovra.Crypto.Key
  alias Sovra.Auth.Session
  alias Sovra.Repo

  def onboard(sovra_address, oauth_token) do
    with {:ok, %{sub: sub, email: _email}} <- auth_provider().verify_id_token(oauth_token),
         :ok <- check_address_available(sovra_address) do
      case get_holder_by_oauth_subject(sub) do
        {:ok, existing_holder} ->
          # Same Google account on a different device — login instead of onboard
          {:ok, session_token} = Session.create(sovra_address)

          {:ok,
           %{
             sovra_address: existing_holder.sovra_address,
             session_token: session_token
           }}

        {:error, :holder_not_found} ->
          create_new_holder(sovra_address, sub)
      end
    end
  end

  defp create_new_holder(sovra_address, oauth_subject) do
    {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} =
      Key.generate_key(sovra_address)

    changeset =
      HolderRecord.create_changeset(%{
        sovra_address: sovra_address,
        recovery_key_id: key_id,
        recovery_public_key_x: x,
        recovery_public_key_y: y,
        oauth_provider: "google",
        oauth_subject: oauth_subject
      })

    case Repo.insert(changeset) do
      {:ok, _record} ->
        {:ok, session_token} = Session.create(sovra_address)

        {:ok,
         %{
           recovery_public_key: %{
             x: Base.encode64(x, padding: false),
             y: Base.encode64(y, padding: false)
           },
           session_token: session_token
         }}

      {:error, changeset} ->
        {:error, {:changeset, changeset}}
    end
  end

  def authenticate_with_token(oauth_token) do
    with {:ok, %{sub: sub}} <- auth_provider().verify_id_token(oauth_token),
         {:ok, holder} <- get_holder_by_oauth_subject(sub),
         {:ok, session_token} <- Session.create(holder.sovra_address) do
      expires_at = System.system_time(:second) + 900

      {:ok, %{session_token: session_token, expires_at: expires_at}}
    end
  end

  def get_auth_url(sovra_address) do
    case get_active_holder(sovra_address) do
      {:ok, _holder} ->
        state = encode_state(sovra_address)
        auth_provider().get_authorization_url(state)

      error ->
        error
    end
  end

  def handle_auth_callback(code, state) do
    with {:ok, sovra_address} <- decode_state(state),
         {:ok, %{sub: sub, provider: _provider}} <- auth_provider().handle_callback(code),
         {:ok, holder} <- get_active_holder(sovra_address),
         :ok <- verify_oauth_binding(holder, sub) do
      Session.create(holder.sovra_address)
    end
  end

  def rotate_recovery_key(sovra_address) do
    with {:ok, holder} <- get_active_holder(sovra_address),
         {:ok, %{key_id: new_key_id, public_key_x: new_x, public_key_y: new_y}} <-
           Key.generate_key("#{sovra_address}_rotation"),
         rotation_hash <- :crypto.hash(:sha256, <<new_x::binary, new_y::binary>>),
         {:ok, rotation_sig} <- Key.sign(holder.recovery_key_id, rotation_hash) do
      changeset =
        HolderRecord.update_key_changeset(holder, %{
          recovery_key_id: new_key_id,
          recovery_public_key_x: new_x,
          recovery_public_key_y: new_y,
          previous_recovery_key_id: holder.recovery_key_id
        })

      case Repo.update(changeset) do
        {:ok, _updated} ->
          {:ok,
           %{
             new_recovery_public_key: %{
               x: Base.encode64(new_x, padding: false),
               y: Base.encode64(new_y, padding: false)
             },
             rotation_signature: format_signature(rotation_sig)
           }}

        {:error, changeset} ->
          Key.delete_key(new_key_id)
          {:error, {:changeset, changeset}}
      end
    end
  end

  def confirm_rotation(sovra_address) do
    with {:ok, holder} <- get_active_holder(sovra_address),
         previous_key_id when is_binary(previous_key_id) <- holder.previous_recovery_key_id do
      Key.delete_key(previous_key_id)

      changeset =
        holder
        |> Ecto.Changeset.change(previous_recovery_key_id: nil)

      case Repo.update(changeset) do
        {:ok, _} -> :ok
        {:error, changeset} -> {:error, {:changeset, changeset}}
      end
    else
      nil -> {:error, :no_pending_rotation}
      error -> error
    end
  end

  def initiate_recovery(sovra_address, message_hash) when is_binary(message_hash) do
    with {:ok, holder} <- get_active_holder(sovra_address),
         {:ok, sig} <- Key.sign(holder.recovery_key_id, message_hash) do
      changeset = HolderRecord.status_changeset(holder, "recovery_pending")

      case Repo.update(changeset) do
        {:ok, _updated} -> {:ok, %{signature: format_signature(sig)}}
        {:error, changeset} -> {:error, {:changeset, changeset}}
      end
    end
  end

  def initiate_recovery(_sovra_address, _message_hash), do: {:error, :invalid_message_hash}

  def finalize_recovery(sovra_address, message_hash) when is_binary(message_hash) do
    with {:ok, holder} <- get_recovery_pending_holder(sovra_address),
         {:ok, sig} <- Key.sign(holder.recovery_key_id, message_hash) do
      changeset = HolderRecord.status_changeset(holder, "active")

      case Repo.update(changeset) do
        {:ok, _updated} -> {:ok, %{signature: format_signature(sig)}}
        {:error, changeset} -> {:error, {:changeset, changeset}}
      end
    end
  end

  # Private helpers

  defp get_recovery_pending_holder(sovra_address) do
    case Repo.get_by(HolderRecord, sovra_address: sovra_address) do
      nil -> {:error, :holder_not_found}
      %{status: "recovery_pending"} = holder -> {:ok, holder}
      _ -> {:error, :not_in_recovery}
    end
  end

  defp get_active_holder(sovra_address) do
    case Repo.get_by(HolderRecord, sovra_address: sovra_address) do
      nil -> {:error, :holder_not_found}
      %{status: "active"} = holder -> {:ok, holder}
      %{status: "deactivated"} -> {:error, :holder_deactivated}
      %{status: "recovery_pending"} -> {:error, :recovery_pending}
    end
  end

  defp get_holder_by_oauth_subject(oauth_subject) do
    case Repo.get_by(HolderRecord, oauth_subject: oauth_subject) do
      nil -> {:error, :holder_not_found}
      holder -> {:ok, holder}
    end
  end

  defp check_address_available(sovra_address) do
    case Repo.get_by(HolderRecord, sovra_address: sovra_address) do
      nil -> :ok
      _exists -> {:error, :already_onboarded}
    end
  end

  defp verify_oauth_binding(%{oauth_subject: expected_sub}, actual_sub) do
    if expected_sub == actual_sub, do: :ok, else: {:error, :oauth_mismatch}
  end

  defp encode_state(sovra_address) do
    timestamp = System.system_time(:second) |> Integer.to_string()
    payload = sovra_address <> "|" <> timestamp
    mac = :crypto.mac(:hmac, :sha256, state_secret(), payload)
    Base.url_encode64(payload <> "|" <> Base.encode64(mac, padding: false), padding: false)
  end

  defp decode_state(state) do
    with {:ok, decoded} <- Base.url_decode64(state, padding: false),
         [address, timestamp_str, mac_b64] <- String.split(decoded, "|", parts: 3),
         {:ok, mac} <- Base.decode64(mac_b64, padding: false),
         payload <- address <> "|" <> timestamp_str,
         expected_mac <- :crypto.mac(:hmac, :sha256, state_secret(), payload),
         true <- Plug.Crypto.secure_compare(mac, expected_mac),
         {timestamp, ""} <- Integer.parse(timestamp_str),
         true <- System.system_time(:second) - timestamp < 600 do
      {:ok, address}
    else
      _ -> {:error, :invalid_state}
    end
  end

  defp state_secret do
    Application.fetch_env!(:sovra, :session_secret)
  end

  defp format_signature(%{r: r, s: s}) do
    %{r: "0x" <> Base.encode16(r, case: :lower), s: "0x" <> Base.encode16(s, case: :lower)}
  end

  defp auth_provider do
    Application.get_env(:sovra, :auth_provider, Sovra.Auth.GoogleAuthProvider)
  end
end
