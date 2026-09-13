import { describe, it, expect } from "vitest";
import * as root from "../src/index";
import { base64UrlParse, validateJwtClaims, isJWK } from "../src/core/utils";
import { generateKey } from "../src/core/jwk";

describe("root barrel (unjwt)", () => {
  // The root entry point is a flat set of named exports, not a namespace
  // re-export: every name the docs promise must actually be on it.
  const CORE = [
    "sign",
    "verify",
    "signMulti",
    "verifyMulti",
    "verifyMultiAll",
    "encrypt",
    "decrypt",
    "encryptMulti",
    "decryptMulti",
    "generateKey",
    "generateJWK",
    "thumbprint",
    "importKey",
    "exportKey",
    "wrapKey",
    "unwrapKey",
    "deriveKeyFromPassword",
    "deriveJWKFromPassword",
    "deriveSharedSecret",
    "importPEM",
    "exportPEM",
    "DEFAULT_JOSE_LIMITS",
    "JWTError",
    "isJWTError",
    "UnsecureError",
    "isUnsecureError",
  ];

  const UTILS = [
    "base64UrlStringify",
    "base64UrlParse",
    "base64Stringify",
    "base64Parse",
    "base64UrlEncode",
    "base64UrlDecode",
    "base64Encode",
    "base64Decode",
    "secureRandomBytes",
    "concatUint8Arrays",
    "maybeArray",
    "textEncoder",
    "textDecoder",
    "sanitizeObject",
    "sanitizeObjectCopy",
    "safeJsonParse",
    "inferJWSAllowedAlgorithms",
    "inferJWEAllowedAlgorithms",
    "validateJwtClaims",
    "computeDurationInSeconds",
    "computeExpiresInSeconds",
    "computeMaxTokenAgeSeconds",
    "isJWK",
    "isJWKSet",
    "isCryptoKey",
    "isCryptoKeyPair",
    "assertCryptoKey",
    "isSymmetricJWK",
    "isAsymmetricJWK",
    "isPrivateJWK",
    "isPublicJWK",
  ];

  it("exports the documented surface as flat named exports", () => {
    expect(Object.keys(root)).toEqual(expect.arrayContaining([...CORE, ...UTILS]));
  });

  it("exports no namespace objects", () => {
    for (const name of ["jws", "jwe", "jwk", "utils"]) {
      expect(root).not.toHaveProperty(name);
    }
  });

  it("re-exports the same bindings as the subpaths", () => {
    expect(root.base64UrlParse).toBe(base64UrlParse);
    expect(root.validateJwtClaims).toBe(validateJwtClaims);
    expect(root.isJWK).toBe(isJWK);
    expect(root.generateKey).toBe(generateKey);
  });
});

/** Run `fn` and return whatever it throws (or `undefined` when it does not throw). */
