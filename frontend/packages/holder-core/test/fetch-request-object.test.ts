/**
 * The `request_uri` and the `response_uri` in a QR are both attacker-chosen, so
 * the client has to decide where it is willing to send the wallet before it
 * sends it — and, more to the point, where it is willing to send the citizen's
 * disclosed claims before it sends those.
 */

import { describe, it, expect } from "vitest";
import { ApiClient } from "../src/api/index";

const L2 = "http://localhost:8545";

describe("fetchRequestObject — where it will fetch from", () => {
  it("refuses plain http", async () => {
    const api = new ApiClient({ l2RpcUrl: L2 });

    await expect(
      api.fetchRequestObject("http://10.0.0.1:8080/admin"),
    ).rejects.toThrow(/Refusing to fetch/);
  });

  it("refuses a non-http scheme", async () => {
    const api = new ApiClient({ l2RpcUrl: L2 });

    await expect(api.fetchRequestObject("file:///etc/passwd")).rejects.toThrow(
      /Refusing to fetch/,
    );
  });

  it("allows http on the Sovra issuer, for dev", async () => {
    // Port 1 refuses at once, so this gets past the guard and dies on connect.
    const api = new ApiClient({ l2RpcUrl: L2, sovraIssuerUrl: "http://127.0.0.1:1/" });

    await expect(
      api.fetchRequestObject("http://127.0.0.1:1/wallet/verifier/request/s-1"),
    ).rejects.not.toThrow(/Refusing to fetch/);
  });

  it("still refuses another http host when an issuer is configured", async () => {
    const api = new ApiClient({ l2RpcUrl: L2, sovraIssuerUrl: "http://127.0.0.1:1/" });

    await expect(
      api.fetchRequestObject("http://10.0.0.1:8080/admin"),
    ).rejects.toThrow(/Refusing to fetch/);
  });

  // The Aligned wallet API sits on another port of the same LAN address in
  // dev, so naming it here would exempt an origin no QR can come from. What is
  // allowed is an origin, and a port is part of one.
  it("refuses another port on the configured host", async () => {
    const api = new ApiClient({ l2RpcUrl: L2, sovraIssuerUrl: "http://127.0.0.1:1/" });

    await expect(
      api.fetchRequestObject("http://127.0.0.1:2/wallet/verifier/request/s-1"),
    ).rejects.toThrow(/Refusing to fetch/);
  });
});

describe("directPost — where it will send the vp_token", () => {
  it("refuses plain http: the vp_token carries the disclosed claims", async () => {
    const api = new ApiClient({ l2RpcUrl: L2 });

    await expect(
      api.directPost("http://evil.example/collect", "{}", "state-1"),
    ).rejects.toThrow(/Refusing to submit a credential/);
  });

  it("refuses a non-http scheme", async () => {
    const api = new ApiClient({ l2RpcUrl: L2 });

    await expect(
      api.directPost("file:///tmp/steal", "{}", "state-1"),
    ).rejects.toThrow(/Refusing to submit a credential/);
  });

  it("allows http on the Sovra issuer, for dev", async () => {
    // Port 1 refuses at once, so this gets past the guard and dies on connect.
    const api = new ApiClient({ l2RpcUrl: L2, sovraIssuerUrl: "http://127.0.0.1:1/" });

    await expect(
      api.directPost(
        "http://127.0.0.1:1/wallet/verifier/direct_post/s-1",
        "{}",
        "state-1",
      ),
    ).rejects.not.toThrow(/Refusing to submit/);
  });

  it("still refuses another http host when an issuer is configured", async () => {
    const api = new ApiClient({ l2RpcUrl: L2, sovraIssuerUrl: "http://127.0.0.1:1/" });

    await expect(
      api.directPost("http://evil.example/collect", "{}", "state-1"),
    ).rejects.toThrow(/Refusing to submit a credential/);
  });
});
