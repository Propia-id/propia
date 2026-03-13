defmodule Sovra.GuardianHelpers do
  @moduledoc """
  Test helpers for guardian server tests.
  """

  alias Sovra.Guardian.HolderRecord
  alias Sovra.Crypto.Key
  alias Sovra.Repo

  @doc "Generates a valid Ethereum address from a seed string (for testing)"
  def test_address(seed) do
    hash = :crypto.hash(:sha256, seed) |> Base.encode16(case: :lower)
    "0x" <> String.slice(hash, 0, 40)
  end

  def create_test_holder(sovra_address \\ test_address("test123")) do
    {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} =
      Key.generate_key(sovra_address)

    {:ok, holder} =
      HolderRecord.create_changeset(%{
        sovra_address: sovra_address,
        recovery_key_id: key_id,
        recovery_public_key_x: x,
        recovery_public_key_y: y,
        oauth_provider: "google",
        oauth_subject: Sovra.Auth.MockAuthProvider.test_sub()
      })
      |> Repo.insert()

    holder
  end

  def valid_session_token(sovra_address) do
    {:ok, token} = Sovra.Auth.Session.create(sovra_address)
    token
  end

  def auth_conn(conn, sovra_address) do
    token = valid_session_token(sovra_address)
    Plug.Conn.put_req_header(conn, "authorization", "Bearer #{token}")
  end

  def random_hash do
    :crypto.strong_rand_bytes(32)
  end

  def hex_hash(hash) do
    "0x" <> Base.encode16(hash, case: :lower)
  end
end
