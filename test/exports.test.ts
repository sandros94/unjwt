import { describe, it, expect, expectTypeOf } from "vitest";
import * as root from "../src/index.ts";
import * as utils from "../src/utils/index.ts";
import * as internal from "../src/core/internal.ts";
import * as dpop from "../src/dpop/index.ts";
import type * as jws from "../src/core/jws/index.ts";
import type * as jwe from "../src/core/jwe/index.ts";
import type * as jwk from "../src/core/jwk/index.ts";
import { base64UrlParse, validateJwtClaims, isJWK } from "../src/utils/index.ts";
import { generateKey } from "../src/core/jwk/index.ts";

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
    "exportJWK",
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
    "secureRandomBytes",
    "digestUrl",
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

  it("drops the renamed aliases", () => {
    for (const name of [
      "exportKey",
      "base64UrlEncode",
      "base64UrlDecode",
      "base64Encode",
      "base64Decode",
    ]) {
      expect(root).not.toHaveProperty(name);
      expect(utils).not.toHaveProperty(name);
    }
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

describe("internal plumbing (unjwt/internal)", () => {
  const INTERNAL = [
    "applyTypDefault",
    "assertCritShape",
    "computeJwtTimeClaims",
    "expiredClaimMessage",
    "getPlaintextBytes",
    "parsePayloadBytes",
    "parsePayloadSegment",
    "parsePayloadText",
    "validateCriticalHeadersJWE",
    "validateCriticalHeadersJWS",
  ];

  it("exports exactly the JOSE plumbing", () => {
    expect(Object.keys(internal).toSorted()).toEqual(INTERNAL);
  });

  it("keeps the new names off unjwt/utils and the root entry point", () => {
    for (const name of [
      "parsePayloadBytes",
      "parsePayloadSegment",
      "parsePayloadText",
      "expiredClaimMessage",
    ]) {
      expect(utils).not.toHaveProperty(name);
      expect(root).not.toHaveProperty(name);
    }
    expect(utils).not.toHaveProperty("decodePayloadText");
  });

  it.each([
    "applyTypCtyDefaults",
    "decodePayloadFromBytes",
    "decodePayloadFromB64UrlSegment",
    "getPlaintextBytes",
    "computeJwtTimeClaims",
    "validateCriticalHeadersJWS",
    "validateCriticalHeadersJWE",
    "assertCritShape",
  ])("exports %s from unjwt/internal alone", (name) => {
    expect(utils).not.toHaveProperty(name);
    expect(root).not.toHaveProperty(name);
  });
});

describe("optional DPoP module (unjwt/dpop)", () => {
  it("exposes proof helpers only through its own entry", () => {
    for (const name of ["createDPoPProof", "verifyDPoPProof"]) {
      expect(dpop).toHaveProperty(name);
      expect(root).not.toHaveProperty(name);
      expect(utils).not.toHaveProperty(name);
    }
  });

  it("shares the core error identity", () => {
    expect(dpop.JWTError).toBe(root.JWTError);
    expect(dpop.isJWTError).toBe(root.isJWTError);
  });
});

describe("types", () => {
  it("exports the payload-mode types from the root, unjwt/jws and unjwt/jwe alike", () => {
    expectTypeOf<root.PayloadOf<"bytes">>().toEqualTypeOf<jws.PayloadOf<"bytes">>();
    expectTypeOf<root.PayloadOf<"bytes">>().toEqualTypeOf<jwe.PayloadOf<"bytes">>();
    expectTypeOf<root.JOSEPayloadTypeMap>().toEqualTypeOf<jws.JOSEPayloadTypeMap>();
    expectTypeOf<root.JOSEPayloadTypeMap>().toEqualTypeOf<jwe.JOSEPayloadTypeMap>();
    expectTypeOf<root.JOSEPayloadMode>().toEqualTypeOf<jws.JOSEPayloadMode>();
    expectTypeOf<root.JOSEPayloadMode>().toEqualTypeOf<jwe.JOSEPayloadMode>();
  });

  it("exports the key-shape maps from the root and unjwt/jwk alike", () => {
    expectTypeOf<root.GeneratedKeyMap>().toEqualTypeOf<jwk.GeneratedKeyMap>();
    expectTypeOf<root.GeneratedJWKMap>().toEqualTypeOf<jwk.GeneratedJWKMap>();
    expectTypeOf<root.ImportedKeyMap>().toEqualTypeOf<jwk.ImportedKeyMap>();
    expectTypeOf<root.ImportedKey<CryptoKey>>().toEqualTypeOf<jwk.ImportedKey<CryptoKey>>();
  });
});
