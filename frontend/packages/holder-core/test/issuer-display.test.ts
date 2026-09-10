/**
 * Cross-repo contract: the backend publishes `background_color` / `text_color`
 * per credential configuration (Sovra.Issuer.OID4VCI.display_for/3) and the
 * wallet draws the card from whatever is captured here. Worth pinning because
 * dropping it is invisible — the credential still arrives, just in a derived
 * colour instead of the issuer's.
 */

import { describe, it, expect } from "vitest";
import {
  credentialMetadataFor,
  pickCredentialDisplay,
  pickClaimLabels,
  toStoredDisplay,
} from "../src/protocols";
import type { CredentialDisplay, ClaimDescription } from "../src/api";

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

/**
 * The same contract for claim labels: the backend publishes one claims
 * description per schema claim (Sovra.Issuer.OID4VCI.claims_for/1) and the
 * wallet labels rows from whatever is captured here. Dropping it is invisible
 * too — the row still renders, just under a key-derived label instead of the
 * issuer's own wording.
 */
describe("pickClaimLabels", () => {
  const labelled: ClaimDescription[] = [
    {
      path: ["fullName"],
      mandatory: true,
      display: [
        { name: "Full name", locale: "en-US" },
        { name: "Nombre completo", locale: "es-AR" },
      ],
    },
    { path: ["age"], display: [{ name: "Age", locale: "en-US" }] },
  ];

  it("returns undefined when the issuer describes no claims", () => {
    expect(pickClaimLabels(undefined)).toBeUndefined();
    expect(pickClaimLabels([])).toBeUndefined();
  });

  it("maps each single-segment path onto its label", () => {
    expect(pickClaimLabels(labelled)).toEqual({ fullName: "Full name", age: "Age" });
  });

  it("resolves each claim's label in the preferred locale", () => {
    expect(pickClaimLabels(labelled, "es-AR")).toEqual({
      fullName: "Nombre completo",
      // Only an en-US entry exists, so it falls back rather than dropping the row.
      age: "Age",
    });
  });

  it("matches on language when no region matches", () => {
    expect(pickClaimLabels(labelled, "es")?.fullName).toBe("Nombre completo");
  });

  it("skips a claim described without any display", () => {
    expect(pickClaimLabels([{ path: ["age"], mandatory: true }])).toBeUndefined();
  });

  it("skips a blank label so the wallet derives one instead", () => {
    expect(pickClaimLabels([{ path: ["age"], display: [{ name: "   " }] }])).toBeUndefined();
  });

  it("trims surrounding whitespace off a label", () => {
    expect(pickClaimLabels([{ path: ["age"], display: [{ name: "  Age  " }] }])).toEqual({
      age: "Age",
    });
  });

  it("ignores pointers into nested structures — stored claims are flat", () => {
    const nested: ClaimDescription[] = [
      { path: ["address", "city"], display: [{ name: "City" }] },
      { path: ["degrees", 0], display: [{ name: "First degree" }] },
      { path: [null], display: [{ name: "Every element" }] },
    ];
    expect(pickClaimLabels(nested)).toBeUndefined();
  });

  it("ignores an empty path segment", () => {
    expect(pickClaimLabels([{ path: [""], display: [{ name: "Nameless" }] }])).toBeUndefined();
  });

  it("keeps the labels it can resolve when a sibling is unusable", () => {
    expect(
      pickClaimLabels([
        { path: ["address", "city"], display: [{ name: "City" }] },
        { path: ["age"], display: [{ name: "Age" }] },
      ]),
    ).toEqual({ age: "Age" });
  });
});


/**
 * Where the issuer puts `display` — the bug that made every credential fall
 * back to the wallet's own card colour. The helpers above were always correct;
 * nothing tested the LOOKUP that feeds them, so reading only the OID4VCI 1.0
 * location went unnoticed against an issuer publishing the earlier shape.
 */
describe("credentialMetadataFor", () => {
  const base = {
    credential_issuer: "https://api.example",
    credential_endpoint: "https://api.example/credential",
    credential_configurations_supported: {},
  };

  it("reads the OID4VCI 1.0 location", () => {
    const md = {
      ...base,
      credential_configurations_supported: {
        UniversityDegree: {
          format: "vc+sd-jwt",
          credential_definition: { type: ["VerifiableCredential", "UniversityDegree"] },
          credential_metadata: {
            display: [{ name: "Degree", background_color: "#123456" }],
            claims: [{ path: ["age"], display: [{ name: "Age" }] }],
          },
        },
      },
    };
    const m = credentialMetadataFor(md as never, "UniversityDegree");
    expect(m?.display?.[0]?.background_color).toBe("#123456");
    expect(m?.claims?.[0]?.path).toEqual(["age"]);
  });

  it("falls back to display placed directly on the configuration", () => {
    // Verbatim shape published by the Sovra issuer (api.sovra.io, 2026-08-31):
    // `display` sits on the configuration, with no `credential_metadata`.
    const md = {
      ...base,
      credential_configurations_supported: {
        UniversityDegree: {
          credential_definition: { type: ["VerifiableCredential", "UniversityDegree"] },
          display: [
            {
              background_color: "#000000",
              locale: "en-US",
              name: "University Degree",
              text_color: "#ffffff",
            },
          ],
          format: "vc+sd-jwt",
        },
      },
    };
    const m = credentialMetadataFor(md as never, "UniversityDegree");
    expect(m?.display?.[0]?.background_color).toBe("#000000");
    expect(m?.display?.[0]?.text_color).toBe("#ffffff");
    // End to end: the colours must survive into what gets persisted.
    expect(toStoredDisplay(pickCredentialDisplay(m?.display, "en-US"))).toEqual({
      name: "University Degree",
      locale: "en-US",
      backgroundColor: "#000000",
      textColor: "#ffffff",
    });
  });

  it("prefers the 1.0 location when an issuer publishes both", () => {
    const md = {
      ...base,
      credential_configurations_supported: {
        X: {
          format: "vc+sd-jwt",
          credential_definition: { type: ["X"] },
          credential_metadata: { display: [{ name: "New", background_color: "#111111" }] },
          display: [{ name: "Legacy", background_color: "#222222" }],
        },
      },
    };
    expect(credentialMetadataFor(md as never, "X")?.display?.[0]?.background_color).toBe(
      "#111111",
    );
  });

  it("returns undefined for a configuration the issuer does not offer", () => {
    expect(credentialMetadataFor(base as never, "Nope")).toBeUndefined();
  });
});
