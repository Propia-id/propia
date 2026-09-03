defmodule Sovra.Guardian do
  @moduledoc """
  Guardian server context. Orchestrates onboarding, authentication,
  blind hash co-signing, key rotation, and recovery.
  """

  use Sovra.Log

  alias Sovra.Auth.Session
  alias Sovra.Crypto.Key
  alias Sovra.Guardian.HolderRecord
  alias Sovra.Repo

  def onboard(sovra_address, oauth_token) do
    with {:ok, %{sub: sub, email: _email}} <- auth_provider().verify_id_token(oauth_token),
         :ok <- check_address_available(sovra_address) do
      case get_holder_by_oauth_subject(sub) do
        {:ok, existing_holder} ->
          # Same Google account on a different device — login instead of onboard
          {:ok, session_token} = Session.create(sovra_address)

          # `requested_sovra_address` is logged whenever it differs from the
          # holder's own: this branch mints the session for the *requested*
          # address while returning the *existing* one, so a mismatch means
          # the session is bound to an address with no holder record behind it.
          Log.event(:info, "guardian authenticated on a new device",
            event: "guardian.authenticated",
            via: :onboard,
            sovra_address: existing_holder.sovra_address,
            requested_sovra_address:
              if(existing_holder.sovra_address != sovra_address, do: sovra_address),
            oauth_subject: sub
          )

          {:ok,
           %{
             sovra_address: existing_holder.sovra_address,
             session_token: session_token
           }}

        {:error, :holder_not_found} ->
          create_new_holder(sovra_address, sub)
      end
    else
      {:error, reason} ->
        Log.event(:warning, "guardian onboarding rejected",
          event: "guardian.onboard.rejected",
          sovra_address: sovra_address,
          reason: Log.reason(reason)
        )

        {:error, reason}

      other ->
        other
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
        Log.event(:info, "guardian holder onboarded",
          event: "guardian.onboarded",
          sovra_address: sovra_address,
          recovery_key_id: key_id,
          oauth_subject: oauth_subject
        )

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
        # The recovery key was already generated and is NOT deleted on this
        # path, unlike rotate_recovery_key/1 — so the key id is recorded here
        # as the only trace of an orphaned key.
        Log.event(:error, "guardian onboarding failed after key generation",
          event: "guardian.onboard.rejected",
          sovra_address: sovra_address,
          orphaned_recovery_key_id: key_id,
          reason: Log.reason(changeset)
        )

        {:error, {:changeset, changeset}}
    end
  end

  def authenticate_with_token(oauth_token) do
    with {:ok, %{sub: sub}} <- auth_provider().verify_id_token(oauth_token),
         {:ok, holder} <- get_holder_by_oauth_subject(sub),
         {:ok, session_token} <- Session.create(holder.sovra_address) do
      Log.event(:info, "guardian authenticated",
        event: "guardian.authenticated",
        via: :id_token,
        sovra_address: holder.sovra_address,
        oauth_subject: sub
      )

      expires_at = System.system_time(:second) + 900

      {:ok, %{session_token: session_token, expires_at: expires_at}}
    else
      {:error, reason} ->
        Log.event(:warning, "guardian authentication rejected",
          event: "guardian.auth.rejected",
          reason: Log.reason(reason)
        )

        {:error, reason}

      other ->
        other
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
    # Split from the rest of the chain so the OAuth-binding check below can log
    # the address it was made against: a `with/else` cannot see the bindings
    # made inside its own chain.
    with {:ok, sovra_address} <- decode_state(state) do
      do_auth_callback(code, sovra_address)
    else
      {:error, reason} -> reject_oauth_callback(nil, reason)
      other -> other
    end
  end

  defp do_auth_callback(code, sovra_address) do
    with {:ok, %{sub: sub, provider: _provider}} <- auth_provider().handle_callback(code),
         {:ok, holder} <- get_active_holder(sovra_address) do
      case verify_oauth_binding(holder, sub) do
        :ok ->
          Log.event(:info, "guardian authenticated via OAuth callback",
            event: "guardian.oauth.authenticated",
            sovra_address: holder.sovra_address,
            oauth_subject: sub
          )

          Session.create(holder.sovra_address)

        {:error, :oauth_mismatch} ->
          # Someone authenticated as one Google account and asked to act on a
          # holder record bound to a different one. Both fingerprints are
          # recorded, so one identity probing many accounts is visible as a
          # repeated `presented_oauth_subject_fp`.
          Log.event(:error, "guardian OAuth binding mismatch",
            event: "guardian.oauth_binding.mismatch",
            sovra_address: sovra_address,
            expected_oauth_subject: holder.oauth_subject,
            presented_oauth_subject: sub
          )

          {:error, :oauth_mismatch}
      end
    else
      {:error, reason} -> reject_oauth_callback(sovra_address, reason)
      other -> other
    end
  end

  defp reject_oauth_callback(sovra_address, reason) do
    Log.event(:warning, "guardian OAuth callback rejected",
      event: "guardian.oauth.rejected",
      sovra_address: sovra_address,
      reason: Log.reason(reason)
    )

    {:error, reason}
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
          # A rotation is only half done here: the previous key still exists
          # and is destroyed by confirm_rotation/1. Both ids are recorded so a
          # rotation that never gets confirmed is traceable to its keys.
          Log.event(:info, "guardian recovery key rotation started",
            event: "guardian.recovery_key.rotation_started",
            sovra_address: sovra_address,
            recovery_key_id: new_key_id,
            previous_recovery_key_id: holder.recovery_key_id
          )

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

          Log.event(:error, "guardian recovery key rotation failed",
            event: "guardian.recovery_key.rotation_failed",
            stage: :persist_new_key,
            sovra_address: sovra_address,
            discarded_recovery_key_id: new_key_id,
            reason: Log.reason(changeset)
          )

          {:error, {:changeset, changeset}}
      end
    else
      {:error, reason} ->
        Log.event(:error, "guardian recovery key rotation failed",
          event: "guardian.recovery_key.rotation_failed",
          stage: :generate_or_sign,
          sovra_address: sovra_address,
          reason: Log.reason(reason)
        )

        {:error, reason}

      other ->
        other
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
        {:ok, _} ->
          # Destroys key material irreversibly, so this is the line that says
          # which key stopped existing and when.
          Log.event(:info, "guardian recovery key rotation confirmed",
            event: "guardian.recovery_key.rotation_confirmed",
            sovra_address: sovra_address,
            recovery_key_id: holder.recovery_key_id,
            destroyed_recovery_key_id: previous_key_id
          )

          :ok

        {:error, changeset} ->
          # The delete already happened: the record still points at a key that
          # no longer exists, and no retry can undo that.
          Log.event(:error, "guardian recovery key rotation left a dangling reference",
            event: "guardian.recovery_key.rotation_failed",
            stage: :clear_previous_key,
            sovra_address: sovra_address,
            destroyed_recovery_key_id: previous_key_id,
            reason: Log.reason(changeset)
          )

          {:error, {:changeset, changeset}}
      end
    else
      nil ->
        {:error, :no_pending_rotation}

      error ->
        error
    end
  end

  def initiate_recovery(sovra_address, %{
        new_key_x: new_key_x,
        new_key_y: new_key_y,
        key_to_replace: key_to_replace
      })
      when is_binary(new_key_x) and is_binary(new_key_y) and key_to_replace in [0, 1] do
    with {:ok, holder} <- get_active_holder(sovra_address),
         {:ok, message_hash} <-
           Sovra.Ethereum.WalletReader.build_initiate_recovery_hash(
             sovra_address,
             new_key_x,
             new_key_y,
             key_to_replace
           ),
         {:ok, sig} <- Key.sign(holder.recovery_key_id, message_hash) do
      hex_hash = "0x" <> Base.encode16(message_hash, case: :lower)

      # The backend does not enforce the timelock — Guardian.Policy.evaluate/1
      # is a stub and the timelock lives in the wallet contract. What it does is
      # co-sign, so `message_hash` is the link between our signature and the
      # on-chain operation it authorized: the one part of this audit trail that
      # survives outside our database.
      Log.event(:info, "guardian recovery initiated",
        event: "guardian.recovery.initiated",
        sovra_address: sovra_address,
        message_hash: hex_hash,
        key_to_replace: key_to_replace,
        recovery_key_id: holder.recovery_key_id
      )

      {:ok, %{signature: format_signature(sig), message_hash: hex_hash}}
    else
      {:error, reason} -> reject_recovery(:initiate, sovra_address, reason)
      other -> other
    end
  end

  def initiate_recovery(sovra_address, _params) do
    reject_recovery(:initiate, sovra_address, :invalid_params)
  end

  def finalize_recovery(sovra_address) do
    with {:ok, holder} <- get_active_holder(sovra_address),
         {:ok, message_hash} <-
           Sovra.Ethereum.WalletReader.build_finalize_recovery_hash(sovra_address),
         {:ok, sig} <- Key.sign(holder.recovery_key_id, message_hash) do
      hex_hash = "0x" <> Base.encode16(message_hash, case: :lower)

      # Pairs with guardian.recovery.initiated on `sovra_address`; the gap
      # between the two is the record of whether the contract's timelock was
      # honoured.
      Log.event(:info, "guardian recovery finalized",
        event: "guardian.recovery.finalized",
        sovra_address: sovra_address,
        message_hash: hex_hash,
        recovery_key_id: holder.recovery_key_id
      )

      {:ok, %{signature: format_signature(sig), message_hash: hex_hash}}
    else
      {:error, reason} -> reject_recovery(:finalize, sovra_address, reason)
      other -> other
    end
  end

  # A holder problem is the caller's (warning); anything else means the hash
  # build or the KMS signature failed, which is ours (error).
  @holder_reasons [:holder_not_found, :holder_deactivated, :invalid_params]

  defp reject_recovery(stage, sovra_address, reason) when reason in @holder_reasons do
    Log.event(:warning, "guardian recovery rejected",
      event: "guardian.recovery.rejected",
      stage: stage,
      sovra_address: sovra_address,
      reason: reason
    )

    {:error, reason}
  end

  defp reject_recovery(stage, sovra_address, reason) do
    Log.event(:error, "guardian recovery failed",
      event: "guardian.recovery.errored",
      stage: stage,
      sovra_address: sovra_address,
      reason: Log.reason(reason)
    )

    {:error, reason}
  end

  # Private helpers

  defp get_active_holder(sovra_address) do
    case Repo.get_by(HolderRecord, sovra_address: sovra_address) do
      nil -> {:error, :holder_not_found}
      %{status: "active"} = holder -> {:ok, holder}
      %{status: "deactivated"} -> {:error, :holder_deactivated}
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
    Sovra.Auth.KeyDerivation.derive_key(:oauth_state)
  end

  defp format_signature(%{r: r, s: s}) do
    %{r: "0x" <> Base.encode16(r, case: :lower), s: "0x" <> Base.encode16(s, case: :lower)}
  end

  defp auth_provider do
    Application.get_env(:sovra, :auth_provider, Sovra.Auth.GoogleAuthProvider)
  end
end
