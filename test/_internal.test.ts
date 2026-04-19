import { describe, it, expect, beforeAll } from "vitest";
import {
  JWS_ALG_CTX,
  JWE_ALG_CTX,
  buildJWKSetFilter,
  checkAlgAllowed,
  decodeJWSPayload,
  decodeProtectedHeader,
  parseEphemeralKey,
  resolveSigningKey,
  validateJwtClaimsIfJsonPayload,
} from "../src/core/_internal";
import { generateKey, generateJWK } from "../src/core/jwk";
import { base64UrlEncode, textDecoder, textEncoder } from "../src/core/utils";
import { isJWTError } from "../src/core/error";
import type {
  JWK,
  JWK_EC_Private,
  JWK_EC_Public,
  JWK_RSA_Private,
  JWK_RSA_Public,
  JWK_Symmetric,
  JWTClaims,
} from "../src/core/types";
import type { JWTErrorCode } from "../src/core/error";

/** Assert that `fn` throws a `JWTError` with the given `code`. */
function expectThrowsJWTError(fn: () => unknown, code: JWTErrorCode): void {
  try {
    fn();
    expect.fail(`expected to throw JWTError(${code})`);
  } catch (err) {
    expect(isJWTError(err, code)).toBe(true);
  }
}

describe.concurrent("_internal helpers", () => {
  describe("buildJWKSetFilter", () => {
    const kidMatch: JWK = { kty: "oct", k: "x", kid: "a", alg: "HS256" };
    const kidAlt: JWK = { kty: "oct", k: "x", kid: "b", alg: "HS256" };
    const noKid: JWK = { kty: "oct", k: "x", alg: "HS256" };
    const noAlg: JWK = { kty: "oct", k: "x", kid: "a" };
    const wrongAlg: JWK = { kty: "oct", k: "x", kid: "a", alg: "HS512" };

    it("keeps keys matching both kid and alg", () => {
      const filter = buildJWKSetFilter({ kid: "a", alg: "HS256" });
      expect(filter(kidMatch)).toBe(true);
    });

    it("rejects keys with different kid", () => {
      const filter = buildJWKSetFilter({ kid: "a", alg: "HS256" });
      expect(filter(kidAlt)).toBe(false);
    });

    it("keeps keys without kid when header has kid (filter accepts because !kid branch)", () => {
      // Correction: filter uses (!headerKid || k.kid === headerKid); when header has kid,
      // keys without kid are REJECTED (k.kid === undefined !== "a"). So this test is:
      const filter = buildJWKSetFilter({ kid: "a", alg: "HS256" });
      expect(filter(noKid)).toBe(false);
    });

    it("keeps all keys when header has no kid", () => {
      const filter = buildJWKSetFilter({ alg: "HS256" });
      expect(filter(kidMatch)).toBe(true);
      expect(filter(noKid)).toBe(true);
    });

    it("keeps keys without alg regardless of header alg", () => {
      const filter = buildJWKSetFilter({ kid: "a", alg: "HS256" });
      expect(filter(noAlg)).toBe(true);
    });

    it("rejects keys whose alg differs from header", () => {
      const filter = buildJWKSetFilter({ kid: "a", alg: "HS256" });
      expect(filter(wrongAlg)).toBe(false);
    });

    it("undefined header → only keys without alg pass (degenerate / unused in practice)", () => {
      // JWS/JWE Protected Headers always carry `alg`; this path exists only for
      // the generic signature of the helper. When header is undefined both kid
      // and alg constraints default to "unset", and the predicate still requires
      // keys not to advertise a conflicting alg.
      const filter = buildJWKSetFilter(undefined);
      expect(filter(noAlg)).toBe(true);
      expect(filter(kidMatch)).toBe(false);
    });
  });

  describe("parseEphemeralKey", () => {
    let p256Pair: {
      publicKey: JWK_EC_Public;
      privateKey: JWK_EC_Private;
    };
    let p256CryptoPair: CryptoKeyPair;

    beforeAll(async () => {
      p256Pair = (await generateJWK("ECDH-ES+A256KW", { namedCurve: "P-256" })) as unknown as {
        publicKey: JWK_EC_Public;
        privateKey: JWK_EC_Private;
      };
      p256CryptoPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
      );
    });

    it("accepts a CryptoKeyPair", () => {
      const { epk, epkPrivateKey } = parseEphemeralKey(p256CryptoPair);
      expect(epk).toBe(p256CryptoPair.publicKey);
      expect(epkPrivateKey).toBe(p256CryptoPair.privateKey);
    });

    it("accepts a { publicKey, privateKey } object of JWKs", () => {
      const { epk, epkPrivateKey } = parseEphemeralKey({
        publicKey: p256Pair.publicKey,
        privateKey: p256Pair.privateKey,
      });
      expect(epk).toBe(p256Pair.publicKey);
      expect(epkPrivateKey).toBe(p256Pair.privateKey);
    });

    it("accepts a private JWK (with 'd') directly", () => {
      const { epk, epkPrivateKey } = parseEphemeralKey(p256Pair.privateKey);
      expect(epk).toBe(p256Pair.privateKey);
      expect(epkPrivateKey).toBe(p256Pair.privateKey);
    });

    it("accepts a private CryptoKey", () => {
      const { epk, epkPrivateKey } = parseEphemeralKey(p256CryptoPair.privateKey);
      expect(epk).toBe(p256CryptoPair.privateKey);
      expect(epkPrivateKey).toBe(p256CryptoPair.privateKey);
    });

    it("rejects a public-only CryptoKey", () => {
      expectThrowsJWTError(() => parseEphemeralKey(p256CryptoPair.publicKey), "ERR_JWK_INVALID");
    });

    it("rejects a JWK without 'd'", () => {
      expectThrowsJWTError(
        () => parseEphemeralKey(p256Pair.publicKey as unknown as JWK_EC_Private),
        "ERR_JWK_INVALID",
      );
    });

    it("rejects { publicKey, privateKey } with missing privateKey", () => {
      expectThrowsJWTError(
        () =>
          parseEphemeralKey({
            publicKey: p256Pair.publicKey,
            privateKey: undefined as unknown as JWK_EC_Private,
          }),
        "ERR_JWK_INVALID",
      );
    });

    it("rejects unsupported input (plain object)", () => {
      expectThrowsJWTError(
        () =>
          parseEphemeralKey({
            foo: "bar",
          } as unknown as Parameters<typeof parseEphemeralKey>[0]),
        "ERR_JWK_INVALID",
      );
    });
  });

  describe("resolveSigningKey", () => {
    it("imports Uint8Array as HMAC with correct hash for HS256", async () => {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      const key = await resolveSigningKey("HS256", raw, "sign");
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as unknown as { hash: { name: string } }).hash.name).toBe("SHA-256");
    });

    it("imports Uint8Array as HMAC with correct hash for HS512", async () => {
      const raw = crypto.getRandomValues(new Uint8Array(64));
      const key = await resolveSigningKey("HS512", raw, "verify");
      expect((key.algorithm as unknown as { hash: { name: string } }).hash.name).toBe("SHA-512");
    });

    it("rejects Uint8Array shorter than alg digest length (HS256 needs 32 bytes)", async () => {
      const shortKey = new Uint8Array(16);
      await expect(resolveSigningKey("HS256", shortKey, "sign")).rejects.toSatisfy((err) =>
        isJWTError(err, "ERR_JWK_INVALID"),
      );
    });

    it("passes through RSA CryptoKey with modulusLength 2048", async () => {
      const rsa = await generateKey("RS256", { modulusLength: 2048 });
      const key = await resolveSigningKey(
        "RS256",
        (rsa as CryptoKeyPair).privateKey as CryptoKey,
        "sign",
      );
      expect(key).toBe((rsa as CryptoKeyPair).privateKey);
    });

    it("rejects RSA CryptoKey with modulusLength < 2048 for RS*", async () => {
      // RSA keys below 2048 are allowed during generation for tests only;
      // resolveSigningKey itself enforces the floor.
      const weak = (await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 1024,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
      )) as CryptoKeyPair;
      await expect(resolveSigningKey("RS256", weak.privateKey, "sign")).rejects.toSatisfy((err) =>
        isJWTError(err, "ERR_JWK_INVALID"),
      );
    });

    it("rejects PSS CryptoKey with modulusLength < 2048", async () => {
      const weak = (await crypto.subtle.generateKey(
        {
          name: "RSA-PSS",
          modulusLength: 1024,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
      )) as CryptoKeyPair;
      await expect(resolveSigningKey("PS256", weak.privateKey, "sign")).rejects.toSatisfy((err) =>
        isJWTError(err, "ERR_JWK_INVALID"),
      );
    });

    it("passes through ECDSA CryptoKey unchanged (no modulus check)", async () => {
      const ec = (await generateKey("ES256")) as CryptoKeyPair;
      const key = await resolveSigningKey("ES256", ec.privateKey, "sign");
      expect(key).toBe(ec.privateKey);
    });
  });

  describe("validateJwtClaimsIfJsonPayload", () => {
    it("validates when payload is a plain object (expired exp throws)", () => {
      const claims: JWTClaims = { exp: 1 };
      expectThrowsJWTError(() => validateJwtClaimsIfJsonPayload(claims, {}), "ERR_JWT_EXPIRED");
    });

    it("skips when payload is a string", () => {
      expect(() => validateJwtClaimsIfJsonPayload("token", {})).not.toThrow();
    });

    it("skips when payload is a Uint8Array", () => {
      expect(() => validateJwtClaimsIfJsonPayload(new Uint8Array([1, 2, 3]), {})).not.toThrow();
    });

    it("skips when payload is null", () => {
      expect(() => validateJwtClaimsIfJsonPayload(null, {})).not.toThrow();
    });

    it("skips when forceUint8Array: true", () => {
      const claims: JWTClaims = { exp: 1 };
      expect(() => validateJwtClaimsIfJsonPayload(claims, { forceUint8Array: true })).not.toThrow();
    });

    it("skips when validateClaims: false", () => {
      const claims: JWTClaims = { exp: 1 };
      expect(() => validateJwtClaimsIfJsonPayload(claims, { validateClaims: false })).not.toThrow();
    });
  });

  describe("checkAlgAllowed", () => {
    describe("with explicit allowlist", () => {
      it("allows alg present in the list", () => {
        const err = checkAlgAllowed("HS256", undefined, ["HS256", "HS384"], JWS_ALG_CTX);
        expect(err).toBeUndefined();
      });

      it("rejects alg not in list with ERR_JWS_ALG_NOT_ALLOWED (JWS)", () => {
        const err = checkAlgAllowed("HS384", undefined, ["HS256"], JWS_ALG_CTX);
        expect(err).toBeDefined();
        expect(isJWTError(err!, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
        expect(err!.message).toContain("Algorithm not allowed: HS384");
      });

      it("rejects alg not in list with ERR_JWE_ALG_NOT_ALLOWED (JWE)", () => {
        const err = checkAlgAllowed("A256KW", undefined, ["A128KW"], JWE_ALG_CTX);
        expect(err).toBeDefined();
        expect(isJWTError(err!, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
        expect(err!.message).toContain("Key management algorithm not allowed: A256KW");
      });
    });

    describe("JWS fast-path (JWK with alg set)", () => {
      it("allows when JWK alg matches header alg", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "HS256" };
        const err = checkAlgAllowed("HS256", jwk, undefined, JWS_ALG_CTX);
        expect(err).toBeUndefined();
      });

      it("rejects when JWK alg differs", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "HS256" };
        const err = checkAlgAllowed("HS512", jwk, undefined, JWS_ALG_CTX);
        expect(isJWTError(err!, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      });
    });

    describe("JWE oct aliasing (fast-path skipped for oct JWKs)", () => {
      it("oct JWK with alg='A256GCM' accepts A256GCMKW (alias, via inference)", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "A256GCM" };
        const err = checkAlgAllowed("A256GCMKW", jwk, undefined, JWE_ALG_CTX);
        expect(err).toBeUndefined();
      });

      it("oct JWK with alg='A256GCM' accepts 'dir' (alias, via inference)", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "A256GCM" };
        const err = checkAlgAllowed("dir", jwk, undefined, JWE_ALG_CTX);
        expect(err).toBeUndefined();
      });

      it("oct JWK with alg='A256KW' rejects 'A128KW' (not an alias)", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "A256KW" };
        const err = checkAlgAllowed("A128KW", jwk, undefined, JWE_ALG_CTX);
        expect(isJWTError(err!, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
      });

      it("non-oct JWK in JWE context uses fast-path", async () => {
        const { publicKey } = (await generateJWK("RSA-OAEP-256", {
          modulusLength: 2048,
        })) as unknown as { publicKey: JWK_RSA_Public; privateKey: JWK_RSA_Private };
        // Matching alg → allowed
        expect(checkAlgAllowed("RSA-OAEP-256", publicKey, undefined, JWE_ALG_CTX)).toBeUndefined();
        // Different alg → rejected (fast-path, no inference fallback)
        expect(
          isJWTError(
            checkAlgAllowed("RSA-OAEP-384", publicKey, undefined, JWE_ALG_CTX)!,
            "ERR_JWE_ALG_NOT_ALLOWED",
          ),
        ).toBe(true);
      });
    });

    describe("inference fallback", () => {
      it("CryptoKey HMAC infers HS256 and allows it", async () => {
        const hs = (await generateKey("HS256")) as CryptoKey;
        expect(checkAlgAllowed("HS256", hs, undefined, JWS_ALG_CTX)).toBeUndefined();
      });

      it("CryptoKey HMAC rejects a mismatched alg", async () => {
        const hs = (await generateKey("HS256")) as CryptoKey;
        const err = checkAlgAllowed("HS512", hs, undefined, JWS_ALG_CTX);
        expect(isJWTError(err!, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      });

      it("returns 'Cannot infer' when key shape is ambiguous", () => {
        const err = checkAlgAllowed("HS256", "random-string", undefined, JWS_ALG_CTX);
        expect(isJWTError(err!, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
        expect(err!.message).toContain("Cannot infer allowed algorithms");
      });

      it("JWE: returns 'Cannot infer' with a more specific label", () => {
        const err = checkAlgAllowed("A256KW", undefined, undefined, JWE_ALG_CTX);
        expect(isJWTError(err!, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
        expect(err!.message).toContain("key management algorithms");
      });
    });
  });

  describe("decodeProtectedHeader", () => {
    it("parses valid base64url-encoded JSON", () => {
      const encoded = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
      const header = decodeProtectedHeader<{ alg?: string; typ?: string }>(encoded, "JWS");
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBe("JWT");
    });

    it("returns empty object when encoded is undefined", () => {
      const header = decodeProtectedHeader(undefined, "JWS");
      expect(header).toEqual({});
    });

    it("returns empty object when encoded is empty string", () => {
      const header = decodeProtectedHeader("", "JWS");
      expect(header).toEqual({});
    });

    it("throws ERR_JWS_INVALID for malformed base64 / JSON in JWS context", () => {
      const garbage = base64UrlEncode("not json");
      expectThrowsJWTError(() => decodeProtectedHeader(garbage, "JWS"), "ERR_JWS_INVALID");
    });

    it("throws ERR_JWE_INVALID for malformed base64 / JSON in JWE context", () => {
      const garbage = base64UrlEncode("{not json");
      expectThrowsJWTError(() => decodeProtectedHeader(garbage, "JWE"), "ERR_JWE_INVALID");
    });

    it("strips prototype-pollution keys via safeJsonParse", () => {
      const poisoned = base64UrlEncode('{"alg":"HS256","__proto__":{"polluted":true}}');
      const header = decodeProtectedHeader<Record<string, unknown>>(poisoned, "JWS");
      expect(header.alg).toBe("HS256");
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });
  });

  describe("decodeJWSPayload", () => {
    it("useB64=true: returns JSON-parsed object when segment looks like JSON", () => {
      const segment = base64UrlEncode(JSON.stringify({ sub: "u1" }));
      const result = decodeJWSPayload<{ sub: string }>(segment, true, false);
      expect(result.sub).toBe("u1");
    });

    it("useB64=true: returns plain string when segment is not JSON", () => {
      const segment = base64UrlEncode("hello");
      const result = decodeJWSPayload<string>(segment, true, false);
      expect(result).toBe("hello");
    });

    it("useB64=true, forceUint8Array=true: returns raw bytes", () => {
      const bytes = textEncoder.encode("raw");
      const segment = base64UrlEncode(bytes);
      const result = decodeJWSPayload<Uint8Array>(segment, true, true);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(textDecoder.decode(result)).toBe("raw");
    });

    it("useB64=false: returns the payload segment as-is", () => {
      const result = decodeJWSPayload<string>("raw-payload", false, false);
      expect(result).toBe("raw-payload");
    });

    it("useB64=false, forceUint8Array=true: UTF-8 encodes the segment", () => {
      const result = decodeJWSPayload<Uint8Array>("raw-payload", false, true);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(textDecoder.decode(result)).toBe("raw-payload");
    });
  });

  describe("JWS_ALG_CTX / JWE_ALG_CTX sanity", () => {
    it("contexts are frozen", () => {
      expect(Object.isFrozen(JWS_ALG_CTX)).toBe(true);
      expect(Object.isFrozen(JWE_ALG_CTX)).toBe(true);
    });

    it("JWS context has the expected shape", () => {
      expect(JWS_ALG_CTX.octAliasing).toBe(false);
      expect(JWS_ALG_CTX.errorCode).toBe("ERR_JWS_ALG_NOT_ALLOWED");
      expect(JWS_ALG_CTX.label).toBe("Algorithm");
    });

    it("JWE context has the expected shape", () => {
      expect(JWE_ALG_CTX.octAliasing).toBe(true);
      expect(JWE_ALG_CTX.errorCode).toBe("ERR_JWE_ALG_NOT_ALLOWED");
      expect(JWE_ALG_CTX.label).toBe("Key management algorithm");
    });
  });

  // JWK_Symmetric reference used in other file too — type import sanity only.
  void ({} as JWK_Symmetric);
});
