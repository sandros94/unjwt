import { describe, it, expect } from "vitest";
import {
  JWTError,
  UnsecureError,
  isJWTError,
  isUnsecureError,
  type UnsecureErrorCode,
} from "../src/error.ts";
import { base64UrlParse } from "../src/utils/base64.ts";

describe.concurrent("isUnsecureError", () => {
  it("the re-exported class is the one the bundled codecs throw", () => {
    expect(thrownByCodec()).toBeInstanceOf(UnsecureError);
  });

  it("narrows without a code", () => {
    expect(isUnsecureError(thrownByCodec())).toBe(true);
  });

  it("narrows with a matching code and rejects a different one", () => {
    const error = thrownByCodec();
    expect(isUnsecureError(error, "MALFORMED")).toBe(true);
    expect(isUnsecureError(error, "INVALID_TYPE")).toBe(false);
  });

  it("the narrowed code is statically the requested literal", () => {
    const error = thrownByCodec();
    if (!isUnsecureError(error, "MALFORMED")) throw new Error("expected a MALFORMED error");
    const code: "MALFORMED" = error.code;
    expect(code).toBe("MALFORMED");
    const widened: UnsecureErrorCode = code;
    expect(widened).toBe("MALFORMED");
  });

  it("rejects plain errors and JWTErrors", () => {
    expect(isUnsecureError(new Error("nope"))).toBe(false);
    expect(isUnsecureError(new JWTError("nope", "ERR_JWS_INVALID"))).toBe(false);
    expect(isUnsecureError(undefined)).toBe(false);
  });

  it("is disjoint from isJWTError", () => {
    const error = thrownByCodec();
    expect(isJWTError(error)).toBe(false);
  });
});

/** What the bundled base64url codec throws on a padded segment. */
function thrownByCodec(): unknown {
  try {
    base64UrlParse("aGVsbG8=", { returnAs: "uint8array" });
    return undefined;
  } catch (error) {
    return error;
  }
}
