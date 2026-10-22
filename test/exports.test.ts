import { describe, it, expect, expectTypeOf } from "vitest";
import * as root from "../src/index.ts";
import * as utils from "../src/core/utils/index.ts";
import * as internal from "../src/core/internal.ts";
import type * as jws from "../src/core/jws.ts";
import type * as jwe from "../src/core/jwe.ts";
import type * as jwk from "../src/core/jwk.ts";
import { base64UrlParse, validateJwtClaims, isJWK } from "../src/core/utils/index.ts";
import { generateKey } from "../src/core/jwk.ts";

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

  // Deprecated in 0.8, removed in 0.9: each old `unjwt/utils` name is the
  // `unjwt/internal` binding under its previous spelling.
  it.each([
    ["applyTypCtyDefaults", internal.applyTypDefault],
    ["decodePayloadFromBytes", internal.parsePayloadBytes],
    ["decodePayloadFromB64UrlSegment", internal.parsePayloadSegment],
    ["getPlaintextBytes", internal.getPlaintextBytes],
    ["computeJwtTimeClaims", internal.computeJwtTimeClaims],
    ["validateCriticalHeadersJWS", internal.validateCriticalHeadersJWS],
    ["validateCriticalHeadersJWE", internal.validateCriticalHeadersJWE],
    ["assertCritShape", internal.assertCritShape],
  ] as const)("still exports %s from unjwt/utils as an alias", (name, binding) => {
    expect(Reflect.get(utils, name)).toBe(binding);
    expect(Reflect.get(root, name)).toBe(binding);
  });
});

describe("types", () => {
  it("gives each deprecated unjwt/utils alias the type of its unjwt/internal original", () => {
    expectTypeOf(utils.applyTypCtyDefaults).toEqualTypeOf(internal.applyTypDefault);
    expectTypeOf(utils.decodePayloadFromBytes).toEqualTypeOf(internal.parsePayloadBytes);
    expectTypeOf(utils.decodePayloadFromB64UrlSegment).toEqualTypeOf(internal.parsePayloadSegment);
    expectTypeOf(utils.getPlaintextBytes).toEqualTypeOf(internal.getPlaintextBytes);
    expectTypeOf(utils.computeJwtTimeClaims).toEqualTypeOf(internal.computeJwtTimeClaims);
    expectTypeOf(utils.validateCriticalHeadersJWS).toEqualTypeOf(
      internal.validateCriticalHeadersJWS,
    );
    expectTypeOf(utils.validateCriticalHeadersJWE).toEqualTypeOf(
      internal.validateCriticalHeadersJWE,
    );
    expectTypeOf(utils.assertCritShape).toEqualTypeOf(internal.assertCritShape);
    expectTypeOf<utils.DecodePayloadOptions>().toEqualTypeOf<internal.ParsePayloadOptions>();
    expectTypeOf<utils.ComputeJwtTimeClaimsOptions>().toEqualTypeOf<internal.ComputeJwtTimeClaimsOptions>();
  });

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
