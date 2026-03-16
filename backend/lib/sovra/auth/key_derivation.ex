defmodule Sovra.Auth.KeyDerivation do
  @moduledoc """
  Derives purpose-specific signing keys from a master secret using HMAC-SHA256.

  Instead of using the raw session_secret directly, each subsystem gets a
  distinct key: HMAC-SHA256(master, "sovra:<purpose>"). This ensures that
  a token signed for one purpose cannot be verified by another, even if
  scope/audience checks were weakened.
  """

  @type purpose :: :guardian_session | :issuer_session | :oauth_state

  @doc "Derives a 32-byte purpose-specific key via HMAC-SHA256(master, info)."
  @spec derive_key(purpose()) :: binary()
  def derive_key(purpose) when purpose in [:guardian_session, :issuer_session, :oauth_state] do
    master = Application.fetch_env!(:sovra, :session_secret)
    info = "sovra:" <> Atom.to_string(purpose)
    :crypto.mac(:hmac, :sha256, master, info)
  end
end
