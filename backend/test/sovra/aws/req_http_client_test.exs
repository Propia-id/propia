defmodule Sovra.AWS.ReqHTTPClientTest do
  use ExUnit.Case, async: true

  alias Sovra.AWS.ReqHTTPClient

  # config/test.exs injects `plug: {Req.Test, :aws_kms}` via :aws_req_options,
  # so requests never leave the VM.

  test "forwards method/body/headers and returns flat headers with the raw body" do
    Req.Test.stub(:aws_kms, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert conn.method == "POST"
      assert Plug.Conn.get_req_header(conn, "x-amz-target") == ["TrentService.Sign"]
      assert body == ~s({"KeyId":"k"})

      conn
      |> Plug.Conn.put_resp_header("x-custom", "v")
      |> Plug.Conn.send_resp(200, ~s({"ok":true}))
    end)

    assert {:ok, %{status_code: 200, headers: headers, body: body}} =
             ReqHTTPClient.request(
               :post,
               "https://kms.us-east-1.amazonaws.com/",
               ~s({"KeyId":"k"}),
               [{"x-amz-target", "TrentService.Sign"}],
               []
             )

    # decode_body: false — aws-elixir parses the JSON itself.
    assert body == ~s({"ok":true})

    # Req's header map is flattened to the {name, value} list aws-elixir expects.
    assert is_list(headers)
    assert {"x-custom", "v"} in headers
  end

  test "maps transport errors to {:error, reason}" do
    Req.Test.stub(:aws_kms, fn conn -> Req.Test.transport_error(conn, :econnrefused) end)

    assert {:error, %Req.TransportError{reason: :econnrefused}} =
             ReqHTTPClient.request(:post, "https://kms.test/", "{}", [], [])
  end
end
