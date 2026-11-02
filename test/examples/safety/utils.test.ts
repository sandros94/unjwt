import { describe, expect, it } from "vitest";
import { generateJWK } from "unjwt/jwk";
import {
  base64Parse,
  base64Stringify,
  base64UrlParse,
  base64UrlStringify,
  isUnsecureError,
} from "unjwt/utils";
import { createState, publishableKeys, readState } from "../../../examples/safety/utils.ts";

describe("examples/safety/utils", () => {
  it("round-trips a state value", () => {
    const state = createState();
    expect(state).toMatch(/^[\w-]{43}$/);
    expect(readState(state)).toHaveLength(32);
  });

  it.each([null, "", `${createState()}=`, "a+b/", createState().slice(0, 42), " x"])(
    "refuses %j",
    (text) => {
      expect(readState(text)).toBeNull();
    },
  );

  it("rethrows an input that is no text", () => {
    expect(() => readState(42 as unknown as string)).toThrow(
      expect.objectContaining({ code: "INVALID_TYPE" }),
    );
  });

  it("keeps only public keys", async () => {
    const signing = await generateJWK("ES256");
    const secret = await generateJWK("HS256");
    const body = publishableKeys({ keys: [signing.privateKey, signing.publicKey, secret] });
    expect(body.keys).toEqual([signing.publicKey]);
    expect(() => publishableKeys({ kty: "oct" })).toThrow(TypeError);
  });

  it("behaves as the page shows", () => {
    expect(base64UrlStringify("hello")).toBe("aGVsbG8");
    expect(base64UrlStringify(new Uint8Array([255, 255]))).toBe("__8");
    expect(base64Stringify("hello")).toBe("aGVsbG8=");
    expect(base64UrlParse("aGVsbG8")).toBe("hello");
    expect(base64Parse("aGVsbG8=")).toBe("hello");
    expect(Array.from(base64UrlParse("__8", { returnAs: "bytes" }))).toEqual([255, 255]);
    for (const bad of ["aGVsbG8=", "aGVs bG8", "a+Vs", "aGVsbG9", "__8"]) {
      expect(() => base64UrlParse(bad)).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    }
    const error = (() => {
      try {
        return base64Parse("aGVsbG8");
      } catch (caught) {
        return caught;
      }
    })();
    expect(isUnsecureError(error, "MALFORMED")).toBe(true);
  });
});
