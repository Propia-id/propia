defmodule Sovra.Issuer.TokenHash do
  @moduledoc """
  Hashing utilities for bearer tokens (pre-authorized codes, access tokens).
  Tokens are hashed with SHA-256 before storage so plaintext never persists in the DB.
  """

  @doc """
  SHA-256 hash a plaintext token, returning a lowercase hex string.
  """
  def hash(token) when is_binary(token) do
    :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
  end

  @doc """
  Generate a random hex token of `bytes` length and return both plaintext and hash.
  """
  def generate_and_hash(bytes \\ 32) do
    plaintext = :crypto.strong_rand_bytes(bytes) |> Base.encode16(case: :lower)
    {plaintext, hash(plaintext)}
  end
end
