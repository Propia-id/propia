/**
 * Cross-repo contract: the backend publishes `background_color` / `text_color`
 * per credential configuration (Sovra.Issuer.OID4VCI.display_for/3) and the
 * wallet draws the card from whatever is captured here. Worth pinning because
 * dropping it is invisible — the credential still arrives, just in a derived
 * colour instead of the issuer's.
 */

import { describe, it, expect } from "vitest";
import { pickCredentialDisplay, toStoredDisplay } from "../src/protocols";
import type { CredentialDisplay } from "../src/api";

const EN: CredentialDisplay = {
  name: "Employee Badge",
  locale: "en-US",
  background_color: "#1a365d",
  text_color: "#ffffff",
};
const ES: CredentialDisplay = {
  name: "Credencial de empleado",
  locale: "es-AR",
  background_color: "#7a1020",
  text_color: "#fff8f0",
};

describe("pickCredentialDisplay", () => {
  it("returns undefined when the issuer publishes no display", () => {
    expect(pickCredentialDisplay(undefined)).toBeUndefined();
    expect(pickCredentialDisplay([])).toBeUndefined();
  });

  it("falls back to the first entry with no preferred locale", () => {
    expect(pickCredentialDisplay([EN, ES])).toBe(EN);
  });

  it("prefers an exact locale match over entry order", () => {
    expect(pickCredentialDisplay([EN, ES], "es-AR")).toBe(ES);
  });

  it("matches on language when no region matches", () => {
    expect(pickCredentialDisplay([EN, ES], "es-MX")).toBe(ES);
    // The wallet passes i18next's bare language codes ("es"), not BCP-47 tags.
    expect(pickCredentialDisplay([EN, ES], "es")).toBe(ES);
  });

  it("is case-insensitive on both sides", () => {
    expect(pickCredentialDisplay([EN, ES], "ES-ar")).toBe(ES);
  });

  it("falls back to the first entry when the language is not published", () => {
    expect(pickCredentialDisplay([EN, ES], "pt-BR")).toBe(EN);
  });

  it("falls back to the first entry when entries carry no locale", () => {
    const untagged: CredentialDisplay[] = [{ name: "Badge" }];
    expect(pickCredentialDisplay(untagged, "es")).toBe(untagged[0]);
  });
});

describe("toStoredDisplay", () => {
  it("maps the OID4VCI snake_case fields onto the stored shape", () => {
    expect(toStoredDisplay(ES)).toEqual({
      name: "Credencial de empleado",
      locale: "es-AR",
      backgroundColor: "#7a1020",
      textColor: "#fff8f0",
    });
  });

  it("keeps a description when the issuer sets one", () => {
    expect(toStoredDisplay({ ...EN, description: "Issued by ACME" })?.description).toBe(
      "Issued by ACME",
    );
  });

  it("returns undefined for no entry at all", () => {
    expect(toStoredDisplay(undefined)).toBeUndefined();
  });

  it("returns undefined rather than an empty object when nothing is usable", () => {
    expect(toStoredDisplay({ name: "" })).toBeUndefined();
  });

  it("omits absent fields instead of writing undefined values", () => {
    const stored = toStoredDisplay({ name: "Badge", text_color: "#000000" });
    expect(stored).toEqual({ name: "Badge", textColor: "#000000" });
    expect(Object.keys(stored ?? {})).not.toContain("backgroundColor");
  });

  it("drops logo and background_image so image data never reaches the index", () => {
    const stored = toStoredDisplay({
      ...EN,
      logo: { uri: "data:image/png;base64,AAAA", alt_text: "logo" },
      background_image: { uri: "data:image/png;base64,BBBB" },
    });
    expect(JSON.stringify(stored)).not.toContain("data:image");
  });
});
