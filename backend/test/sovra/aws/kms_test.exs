# async: false — mutates AWS_* env vars and the :aws_credentials server state;
# sync modules run serially after all async modules, so nothing races this.
defmodule Sovra.AWS.KMSTest do
  use ExUnit.Case, async: false

  alias Sovra.AWS.KMS

  @digest :crypto.hash(:sha256, "payload")

  setup do
    System.put_env("AWS_ACCESS_KEY_ID", "test-access-key")
    System.put_env("AWS_SECRET_ACCESS_KEY", "test-secret-key")
    :aws_credentials.force_credentials_refresh()

    on_exit(fn ->
      System.delete_env("AWS_ACCESS_KEY_ID")
      System.delete_env("AWS_SECRET_ACCESS_KEY")
      :aws_credentials.force_credentials_refresh()
    end)
  end

  # Captures the awsjson1.1 request (target header + decoded body) into the
  # test mailbox and responds with `response`.
  defp stub_kms(response) do
    Req.Test.stub(:aws_kms, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      [target] = Plug.Conn.get_req_header(conn, "x-amz-target")
      send(self(), {:kms_request, target, Jason.decode!(body)})
      Req.Test.json(conn, response)
    end)
  end

  test "sign posts a base64 DIGEST to TrentService.Sign and returns the raw DER" do
    der = <<0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02>>
    stub_kms(%{"Signature" => Base.encode64(der)})

    assert {:ok, ^der} = KMS.sign("key-1", @digest)

    assert_received {:kms_request, "TrentService.Sign", body}

    assert body == %{
             "KeyId" => "key-1",
             "Message" => Base.encode64(@digest),
             "MessageType" => "DIGEST",
             "SigningAlgorithm" => "ECDSA_SHA_256"
           }
  end

  test "sign maps a 200 without a Signature to :unexpected_kms_response" do
    stub_kms(%{"Something" => "else"})

    assert {:error, {:unexpected_kms_response, %{"Something" => "else"}}} =
             KMS.sign("key-1", @digest)
  end

  test "sign maps an undecodable Signature to :bad_base64" do
    stub_kms(%{"Signature" => "not base64!"})

    assert {:error, :bad_base64} = KMS.sign("key-1", @digest)
  end

  test "a non-200 KMS response is an error tuple, not a crash" do
    Req.Test.stub(:aws_kms, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/x-amz-json-1.1")
      |> Plug.Conn.send_resp(400, ~s({"__type":"ThrottlingException"}))
    end)

    assert {:error, _} = KMS.sign("key-1", @digest)
  end

  test "get_public_key returns the base64-decoded DER SPKI" do
    spki = :crypto.strong_rand_bytes(91)
    stub_kms(%{"PublicKey" => Base.encode64(spki)})

    assert {:ok, ^spki} = KMS.get_public_key("key-1")
    assert_received {:kms_request, "TrentService.GetPublicKey", %{"KeyId" => "key-1"}}
  end

  test "create_key sends spec/usage/tags and returns the key id" do
    stub_kms(%{"KeyMetadata" => %{"KeyId" => "key-new"}})

    assert {:ok, %{key_id: "key-new"}} = KMS.create_key([{"sovra:kind", "workspace-signer"}])

    assert_received {:kms_request, "TrentService.CreateKey", body}

    assert body == %{
             "KeySpec" => "ECC_NIST_P256",
             "KeyUsage" => "SIGN_VERIFY",
             "Tags" => [%{"TagKey" => "sovra:kind", "TagValue" => "workspace-signer"}]
           }
  end

  test "schedule_key_deletion sends the pending window and returns :ok" do
    stub_kms(%{"KeyId" => "key-1", "DeletionDate" => 0})

    assert :ok = KMS.schedule_key_deletion("key-1")

    assert_received {:kms_request, "TrentService.ScheduleKeyDeletion",
                     %{"KeyId" => "key-1", "PendingWindowInDays" => 7}}
  end

  test "without credentials every call returns :no_aws_credentials" do
    System.delete_env("AWS_ACCESS_KEY_ID")
    System.delete_env("AWS_SECRET_ACCESS_KEY")
    :aws_credentials.force_credentials_refresh()

    assert {:error, :no_aws_credentials} = KMS.sign("key-1", @digest)
    assert {:error, :no_aws_credentials} = KMS.get_public_key("key-1")
  end

  test "without a region every call returns :aws_region_missing" do
    original = Application.get_env(:sovra, :signer_service, [])
    Application.put_env(:sovra, :signer_service, Keyword.delete(original, :region))
    prev_region = System.get_env("AWS_REGION")
    System.delete_env("AWS_REGION")

    on_exit(fn ->
      Application.put_env(:sovra, :signer_service, original)
      if prev_region, do: System.put_env("AWS_REGION", prev_region)
    end)

    assert {:error, :aws_region_missing} = KMS.sign("key-1", @digest)
  end
end
