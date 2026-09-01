defmodule SovraTest.Crypto.FailingKeyStore do
  @moduledoc """
  A key store that reports the signer as down, in the shape `KmsKeyStore`
  reports an HTTP failure. For asserting that callers answer 502 rather than
  crashing on an error shape they never listed.
  """

  @behaviour Sovra.Crypto.KeyStore

  @error {:error, {:signer_error, 503, %{"error" => "unavailable"}}}

  @impl true
  def generate_key(_holder_id), do: @error

  @impl true
  def sign(_key_id, _hash), do: @error

  @impl true
  def delete_key(_key_id), do: @error
end
