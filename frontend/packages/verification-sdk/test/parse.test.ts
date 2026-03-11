import { describe, it, expect } from "vitest";
import { parsePresentation, VerificationError } from "../src/parse";
import { ErrorCode } from "../src/types";
import { generateKeys, buildPresentation } from "./fixtures";

describe("parsePresentation", () => {
  const keys = generateKeys();

  it("parses a valid SD-JWT presentation", () => {
    const fixture = buildPresentation(keys);
    const result = parsePresentation(fixture.presentation);

    expect(result.issuerJwtRaw).toBe(fixture.issuerJwt);
    expect(result.kbJwtRaw).toBe(fixture.kbJwt);
    expect(result.issuerHeader.alg).toBe("ES256");
    expect(result.issuerHeader.typ).toBe("vc+sd-jwt");
    expect(result.issuerPayload.iss).toBe(`did:sovra:${fixture.issuerAddress}`);
    expect(result.issuerPayload.vct).toBe(fixture.vct);
    expect(result.kbHeader.typ).toBe("kb+jwt");
    expect(result.kbPayload.nonce).toBe(fixture.nonce);
    expect(result.kbPayload.aud).toBe(fixture.audience);
    expect(result.disclosures).toHaveLength(3);
    expect(result.disclosures.map((d) => d.key).sort()).toEqual(
      ["birth_date", "family_name", "given_name"],
    );
  });

  it("throws PARSE_ERROR for empty string", () => {
    expect(() => parsePresentation("")).toThrow(VerificationError);
    try {
      parsePresentation("");
    } catch (e) {
      expect((e as VerificationError).code).toBe(ErrorCode.PARSE_ERROR);
    }
  });

  it("throws KB_JWT_MISSING when no KB-JWT present", () => {
    const fixture = buildPresentation(keys);
    // Just the issuer JWT with trailing ~
    const noKb = `${fixture.issuerJwt}~`;
    expect(() => parsePresentation(noKb)).toThrow(VerificationError);
    try {
      parsePresentation(noKb);
    } catch (e) {
      expect((e as VerificationError).code).toBe(ErrorCode.KB_JWT_MISSING);
    }
  });

  it("throws PARSE_ERROR for malformed issuer JWT", () => {
    expect(() => parsePresentation("notajwt~fakekbjwt")).toThrow(VerificationError);
  });

  it("decodes disclosure values correctly", () => {
    const fixture = buildPresentation(keys, {
      disclosableClaims: { age: 33, name: "Test" },
    });
    const result = parsePresentation(fixture.presentation);

    const ageDisc = result.disclosures.find((d) => d.key === "age");
    expect(ageDisc?.value).toBe(33);

    const nameDisc = result.disclosures.find((d) => d.key === "name");
    expect(nameDisc?.value).toBe("Test");
  });
});
