defmodule Sovra.Auth.MockAuthProvider do
  @moduledoc """
  Mock OAuth provider for tests. Returns deterministic values.
  """

  @behaviour Sovra.Auth.AuthProvider

  @valid_token "valid-google-token"
  @valid_token_2 "valid-google-token-2"
  @valid_code "valid-auth-code"
  @test_sub "google-user-123"
  @test_sub_2 "google-user-456"
  @test_email "test@example.com"
  @test_email_2 "test2@example.com"

  def valid_token, do: @valid_token
  def valid_token_2, do: @valid_token_2
  def valid_code, do: @valid_code
  def test_sub, do: @test_sub
  def test_sub_2, do: @test_sub_2
  def test_email, do: @test_email
  def test_email_2, do: @test_email_2

  @impl true
  def get_authorization_url(state) do
    {:ok, "https://mock-auth.example.com/authorize?state=#{state}"}
  end

  @impl true
  def handle_callback(@valid_code) do
    {:ok, %{sub: @test_sub, email: @test_email, provider: "google"}}
  end

  def handle_callback(_code) do
    {:error, :invalid_code}
  end

  @impl true
  def verify_id_token(@valid_token) do
    {:ok, %{sub: @test_sub, email: @test_email}}
  end

  def verify_id_token(@valid_token_2) do
    {:ok, %{sub: @test_sub_2, email: @test_email_2}}
  end

  def verify_id_token(_token) do
    {:error, :invalid_id_token}
  end
end
