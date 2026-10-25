import { describe, it, expect, beforeAll } from "vitest";
import { textDecoder, textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "../src/utils/base64.ts";

import { JWS_ALG_CTX, checkAlgAllowed } from "../src/core/_internal/algorithms.ts";
import { JWE_ALG_CTX } from "../src/core/jwe/_internal/algorithms.ts";
import { asJWTError } from "../src/core/_internal/errors.ts";
import { buildJWKSetFilter, parseEphemeralKey } from "../src/core/_internal/keys.ts";
import { decodeJWSPayload } from "../src/core/jws/_internal/b64.ts";
import { decodeProtectedHeader } from "../src/core/_internal/headers.ts";
import { resolveSigningKey } from "../src/core/jws/_internal/keys.ts";
import { validateClaimsIfJson, resolvePayloadMode } from "../src/core/_internal/payload.ts";
import { generateKey, generateJWK } from "../src/core/jwk/index.ts";
import { isJWTError, JWTError } from "../src/error.ts";
import type {
  JWK,
  JWK_EC_Private,
  JWK_EC_Public,
  JWK_RSA_Private,
  JWK_RSA_Public,
  JWK_Symmetric,
  JWTClaims,
} from "../src/core/types/index.ts";
import type { JWTErrorCode, KnownJWTErrorCode } from "../src/error.ts";

/** Assert that `fn` throws a `JWTError` with the given `code`. */
function expectThrowsJWTError(fn: () => unknown, code: KnownJWTErrorCode): void {
  let err: unknown;
  let threw = false;
  try {
    fn();
  } catch (e) {
    threw = true;
    err = e;
  }
  expect(threw, `expected to throw JWTError(${code})`).toBe(true);
  expect(isJWTError(err, code)).toBe(true);
}

describe.concurrent("_internal helpers", () => {
  describe("buildJWKSetFilter", () => {
    const kidMatch: JWK = { kty: "RSA", n: "x", e: "AQAB", kid: "a", alg: "RS256" };
    const kidAlt: JWK = { kty: "RSA", n: "x", e: "AQAB", kid: "b", alg: "RS256" };
    const noKid: JWK = { kty: "RSA", n: "x", e: "AQAB", alg: "RS256" };
    const noAlg: JWK = { kty: "RSA", n: "x", e: "AQAB", kid: "a" };
    const wrongAlg: JWK = { kty: "RSA", n: "x", e: "AQAB", kid: "a", alg: "RS512" };
    // @ts-expect-error an oct key claiming a signing alg, as a hostile JWK Set could carry
    const octKey: JWK = { kty: "oct", k: "x", kid: "a", alg: "RS256" };

    it("keeps keys matching both kid and alg", () => {
      const filter = buildJWKSetFilter({ kid: "a", alg: "RS256" }, { op: "sig" });
      expect(filter(kidMatch)).toBe(true);
    });

    it("rejects keys with different kid", () => {
      const filter = buildJWKSetFilter({ kid: "a", alg: "RS256" }, { op: "sig" });
      expect(filter(kidAlt)).toBe(false);
    });

    it("rejects keys without kid when the header carries one", () => {
      const filter = buildJWKSetFilter({ kid: "a", alg: "RS256" }, { op: "sig" });
      expect(filter(noKid)).toBe(false);
    });

    it("keeps all keys when header has no kid", () => {
      const filter = buildJWKSetFilter({ alg: "RS256" }, { op: "sig" });
      expect(filter(kidMatch)).toBe(true);
      expect(filter(noKid)).toBe(true);
    });

    it("keeps keys without alg regardless of header alg", () => {
      const filter = buildJWKSetFilter({ kid: "a", alg: "RS256" }, { op: "sig" });
      expect(filter(noAlg)).toBe(true);
    });

    it("rejects keys whose alg differs from header", () => {
      const filter = buildJWKSetFilter({ kid: "a", alg: "RS256" }, { op: "sig" });
      expect(filter(wrongAlg)).toBe(false);
    });

    it("keeps oct entries like any other", () => {
      const header = { kid: "a", alg: "RS256" } as const;
      expect(buildJWKSetFilter(header, { op: "sig" })(octKey)).toBe(true);
    });

    it('drops a non-oct entry carrying "k" as malformed', () => {
      const disguised = { kty: "EC", crv: "P-256", x: "x", y: "y", k: "x" } as unknown as JWK;
      expect(buildJWKSetFilter({ alg: "ES256" }, { op: "sig" })(disguised)).toBe(false);
    });

    it("drops entries that are not JWKs", () => {
      const filter = buildJWKSetFilter({ alg: "RS256" }, { op: "sig" });
      for (const junk of [null, "x", 1, [], {}, { kty: "unknown" }]) {
        expect(filter(junk as unknown as JWK)).toBe(false);
      }
    });

    it('honours "use" against the operation', () => {
      const sigFilter = buildJWKSetFilter({ alg: "RS256" }, { op: "sig" });
      expect(sigFilter({ ...noKid, use: "sig" })).toBe(true);
      expect(sigFilter({ ...noKid, use: "enc" })).toBe(false);

      const encFilter = buildJWKSetFilter({ alg: "RSA-OAEP-256" }, { op: "enc" });
      const encKey: JWK = { kty: "RSA", n: "x", e: "AQAB", alg: "RSA-OAEP-256" };
      expect(encFilter({ ...encKey, use: "enc" })).toBe(true);
      expect(encFilter({ ...encKey, use: "sig" })).toBe(false);
    });

    it('honours "key_ops" against the operation', () => {
      const sigFilter = buildJWKSetFilter({ alg: "RS256" }, { op: "sig" });
      expect(sigFilter({ ...noKid, key_ops: ["verify"] })).toBe(true);
      expect(sigFilter({ ...noKid, key_ops: ["sign"] })).toBe(false);

      const encKey: JWK = { kty: "RSA", n: "x", e: "AQAB", alg: "RSA-OAEP-256" };
      const encFilter = buildJWKSetFilter({ alg: "RSA-OAEP-256" }, { op: "enc" });
      for (const op of ["unwrapKey", "decrypt", "deriveBits", "deriveKey"]) {
        expect(encFilter({ ...encKey, key_ops: [op] } as JWK)).toBe(true);
      }
      expect(encFilter({ ...encKey, key_ops: ["verify"] })).toBe(false);
    });

    it("undefined header → only keys without alg pass (degenerate / unused in practice)", () => {
      const filter = buildJWKSetFilter(undefined, { op: "sig" });
      expect(filter(noAlg)).toBe(true);
      expect(filter(kidMatch)).toBe(false);
    });
  });

  describe("asJWTError", () => {
    it("passes a JWTError through unchanged", () => {
      const original = new JWTError("Specific verdict.", "ERR_JWS_INVALID");
      expect(asJWTError(original, { code: "ERR_JWK_INVALID", message: "Other." })).toBe(original);
    });

    it("reports anything else under the library message, never the thrown text", () => {
      const raw = new TypeError("internal runtime detail");
      const error = asJWTError(raw, { code: "ERR_JWS_INVALID", message: "Invalid JWS." });
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWS.");
      expect(error.cause).toBe(raw);
      const fromString = asJWTError("thrown string", {
        code: "ERR_JWS_INVALID",
        message: "Invalid JWS.",
      });
      expect(fromString.message).toBe("Invalid JWS.");
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

    it("rejects raw bytes under an algorithm that is not HMAC", async () => {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      for (const alg of ["RS256", "ES256", "EdDSA", "PS512"] as const) {
        const error = await resolveSigningKey(alg, raw, "verify").catch((e) => e);
        expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
        expect(error.message).toContain(alg);
      }
    });

    it("passes through RSA CryptoKey with modulusLength 2048", async () => {
      const rsa = await generateKey("RS256", { modulusLength: 2048 });
      const key = await resolveSigningKey("RS256", rsa.privateKey, "sign");
      expect(key).toBe(rsa.privateKey);
    });

    it("rejects RSA CryptoKey with modulusLength < 2048 for RS*", async () => {
      // RSA keys below 2048 are allowed during generation for tests only;
      // resolveSigningKey itself enforces the floor.
      const weak = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 1024,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
      );
      await expect(resolveSigningKey("RS256", weak.privateKey, "sign")).rejects.toSatisfy((err) =>
        isJWTError(err, "ERR_JWK_INVALID"),
      );
    });

    it("rejects PSS CryptoKey with modulusLength < 2048", async () => {
      const weak = await crypto.subtle.generateKey(
        {
          name: "RSA-PSS",
          modulusLength: 1024,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
      );
      await expect(resolveSigningKey("PS256", weak.privateKey, "sign")).rejects.toSatisfy((err) =>
        isJWTError(err, "ERR_JWK_INVALID"),
      );
    });

    it("passes through ECDSA CryptoKey unchanged (no modulus check)", async () => {
      const ec = await generateKey("ES256");
      const key = await resolveSigningKey("ES256", ec.privateKey, "sign");
      expect(key).toBe(ec.privateKey);
    });
  });

  describe("validateClaimsIfJson", () => {
    it('validates under payload mode "json" (expired exp throws)', () => {
      const claims: JWTClaims = { exp: 1 };
      expectThrowsJWTError(() => validateClaimsIfJson(claims, "json", {}), "ERR_JWT_EXPIRED");
    });

    it('skips under payload mode "string"', () => {
      expect(() => validateClaimsIfJson("token", "string", {})).not.toThrow();
    });

    it('skips under payload mode "bytes"', () => {
      expect(() => validateClaimsIfJson(new Uint8Array([1, 2, 3]), "bytes", {})).not.toThrow();
    });

    it("skips when validateClaims: false", () => {
      const claims: JWTClaims = { exp: 1 };
      expect(() => validateClaimsIfJson(claims, "json", { validateClaims: false })).not.toThrow();
    });
  });

  describe("resolvePayloadMode", () => {
    it('defaults to "json"', () => {
      expect(resolvePayloadMode({})).toBe("json");
    });

    it("reads the payload option", () => {
      expect(resolvePayloadMode({ payload: "bytes" })).toBe("bytes");
      expect(resolvePayloadMode({ payload: "string" })).toBe("string");
    });

    it("maps forceUint8Array onto the matching mode", () => {
      expect(resolvePayloadMode({ forceUint8Array: true })).toBe("bytes");
      expect(resolvePayloadMode({ forceUint8Array: false })).toBe("json");
    });

    it("accepts forceUint8Array that agrees with payload", () => {
      expect(resolvePayloadMode({ forceUint8Array: true, payload: "bytes" })).toBe("bytes");
      expect(resolvePayloadMode({ forceUint8Array: false, payload: "string" })).toBe("string");
    });

    it.each([
      [true, "json"],
      [true, "string"],
      [false, "bytes"],
    ] as const)("rejects forceUint8Array: %s with payload: %s", (forceUint8Array, payload) => {
      expectThrowsJWTError(
        () => resolvePayloadMode({ forceUint8Array, payload }),
        "ERR_INVALID_OPTION",
      );
    });

    it("rejects an unknown mode", () => {
      expectThrowsJWTError(
        () => resolvePayloadMode({ payload: "utf8" as never }),
        "ERR_INVALID_OPTION",
      );
    });

    it.each(["string", "bytes"] as const)(
      'rejects validateClaims: true with payload: "%s"',
      (payload) => {
        expectThrowsJWTError(
          () => resolvePayloadMode({ payload, validateClaims: true }),
          "ERR_INVALID_OPTION",
        );
      },
    );
  });

  describe("checkAlgAllowed", () => {
    describe("with explicit allowlist", () => {
      it("allows alg present in the list", () => {
        const err = checkAlgAllowed("HS256", undefined, {
          ctx: JWS_ALG_CTX,
          algorithms: ["HS256", "HS384"],
        });
        expect(err).toBeUndefined();
      });

      it("rejects alg not in list with ERR_JWS_ALG_NOT_ALLOWED (JWS)", () => {
        const err = checkAlgAllowed("HS384", undefined, {
          ctx: JWS_ALG_CTX,
          algorithms: ["HS256"],
        });
        expect(err).toBeDefined();
        expect(isJWTError(err!, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
        expect(err!.message).toContain("Algorithm not allowed: HS384");
      });

      it("rejects alg not in list with ERR_JWE_ALG_NOT_ALLOWED (JWE)", () => {
        const err = checkAlgAllowed("A256KW", undefined, {
          ctx: JWE_ALG_CTX,
          algorithms: ["A128KW"],
        });
        expect(err).toBeDefined();
        expect(isJWTError(err!, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
        expect(err!.message).toContain("Key management algorithm not allowed: A256KW");
      });
    });

    describe("JWS fast-path (JWK with alg set)", () => {
      it("allows when JWK alg matches header alg", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "HS256" };
        const err = checkAlgAllowed("HS256", jwk, { ctx: JWS_ALG_CTX });
        expect(err).toBeUndefined();
      });

      it("rejects when JWK alg differs", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "HS256" };
        const err = checkAlgAllowed("HS512", jwk, { ctx: JWS_ALG_CTX });
        expect(isJWTError(err!, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      });
    });

    describe("JWE symmetric roles (fast-path skipped for oct JWKs)", () => {
      it("oct JWK with alg='A256GCM' is a CEK for dir, never a wrapping key", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "A256GCM" };
        expect(checkAlgAllowed("dir", jwk, { ctx: JWE_ALG_CTX })).toBeUndefined();
        expect(
          isJWTError(
            checkAlgAllowed("A256GCMKW", jwk, { ctx: JWE_ALG_CTX })!,
            "ERR_JWE_ALG_NOT_ALLOWED",
          ),
        ).toBe(true);
      });

      it("oct JWK with alg='A256GCMKW' wraps only, never serves as a CEK", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "A256GCMKW" };
        expect(checkAlgAllowed("A256GCMKW", jwk, { ctx: JWE_ALG_CTX })).toBeUndefined();
        expect(
          isJWTError(checkAlgAllowed("dir", jwk, { ctx: JWE_ALG_CTX })!, "ERR_JWE_ALG_NOT_ALLOWED"),
        ).toBe(true);
      });

      it("oct JWK with alg='A256KW' wraps only, never serves as a CEK", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "A256KW" };
        expect(checkAlgAllowed("A256KW", jwk, { ctx: JWE_ALG_CTX })).toBeUndefined();
        expect(
          isJWTError(checkAlgAllowed("dir", jwk, { ctx: JWE_ALG_CTX })!, "ERR_JWE_ALG_NOT_ALLOWED"),
        ).toBe(true);
      });

      it("oct JWK with alg='A256KW' rejects 'A128KW'", () => {
        const jwk: JWK = { kty: "oct", k: "x", alg: "A256KW" };
        const err = checkAlgAllowed("A128KW", jwk, { ctx: JWE_ALG_CTX });
        expect(isJWTError(err!, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
      });

      it("non-oct JWK in JWE context uses fast-path", async () => {
        const { publicKey } = (await generateJWK("RSA-OAEP-256", {
          modulusLength: 2048,
        })) as unknown as { publicKey: JWK_RSA_Public; privateKey: JWK_RSA_Private };
        // Matching alg → allowed
        expect(checkAlgAllowed("RSA-OAEP-256", publicKey, { ctx: JWE_ALG_CTX })).toBeUndefined();
        // Different alg → rejected (fast-path, no inference fallback)
        expect(
          isJWTError(
            checkAlgAllowed("RSA-OAEP-384", publicKey, { ctx: JWE_ALG_CTX })!,
            "ERR_JWE_ALG_NOT_ALLOWED",
          ),
        ).toBe(true);
      });
    });

    describe("JWK Set inference", () => {
      const rsaEntry: JWK = { kty: "RSA", n: "x", e: "AQAB", alg: "RS256" };

      it("counts oct entries toward inference", () => {
        const set = { keys: [rsaEntry, { kty: "oct", k: "x", alg: "HS256" } as JWK] };
        expect(checkAlgAllowed("HS256", set, { ctx: JWS_ALG_CTX })).toBeUndefined();
      });

      it("skips entries it cannot infer instead of failing the whole set", () => {
        const set = { keys: [{ kty: "RSA", n: "x", e: "AQAB" } as JWK, rsaEntry] };
        expect(checkAlgAllowed("RS256", set, { ctx: JWS_ALG_CTX })).toBeUndefined();
      });
    });

    describe("inference fallback", () => {
      it("CryptoKey HMAC infers HS256 and allows it", async () => {
        const hs = await generateKey("HS256");
        expect(checkAlgAllowed("HS256", hs, { ctx: JWS_ALG_CTX })).toBeUndefined();
      });

      it("CryptoKey HMAC rejects a mismatched alg", async () => {
        const hs = await generateKey("HS256");
        const err = checkAlgAllowed("HS512", hs, { ctx: JWS_ALG_CTX });
        expect(isJWTError(err!, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
      });

      it("returns 'Cannot infer' when key shape is ambiguous", () => {
        const err = checkAlgAllowed("HS256", "random-string", { ctx: JWS_ALG_CTX });
        expect(isJWTError(err!, "ERR_JWS_ALG_NOT_ALLOWED")).toBe(true);
        expect(err!.message).toContain("Cannot infer allowed algorithms");
      });

      it("JWE: returns 'Cannot infer' with a more specific label", () => {
        const err = checkAlgAllowed("A256KW", undefined, { ctx: JWE_ALG_CTX });
        expect(isJWTError(err!, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
        expect(err!.message).toContain("Cannot infer allowed algorithms");
      });

      it("JWE: raw bytes carry no role and must be named by the caller", () => {
        const err = checkAlgAllowed("A256KW", new Uint8Array(32), { ctx: JWE_ALG_CTX });
        expect(isJWTError(err!, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
        expect(err!.message).toContain("Cannot infer");
        expect(
          checkAlgAllowed("A256KW", new Uint8Array(32), {
            ctx: JWE_ALG_CTX,
            algorithms: ["A256KW"],
          }),
        ).toBeUndefined();
      });
    });
  });

  describe("decodeProtectedHeader", () => {
    it("parses valid base64url-encoded JSON", () => {
      const encoded = base64UrlStringify(JSON.stringify({ alg: "HS256", typ: "JWT" }));
      const header = decodeProtectedHeader(encoded, "JWS");
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
      const garbage = base64UrlStringify("not json");
      expectThrowsJWTError(() => decodeProtectedHeader(garbage, "JWS"), "ERR_JWS_INVALID");
    });

    it("throws ERR_JWE_INVALID for malformed base64 / JSON in JWE context", () => {
      const garbage = base64UrlStringify("{not json");
      expectThrowsJWTError(() => decodeProtectedHeader(garbage, "JWE"), "ERR_JWE_INVALID");
    });

    it("strips prototype-pollution keys via safeJsonParse", () => {
      const poisoned = base64UrlStringify('{"alg":"HS256","__proto__":{"polluted":true}}');
      const header = decodeProtectedHeader(poisoned, "JWS");
      expect(header.alg).toBe("HS256");
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });
  });

  describe("decodeJWSPayload", () => {
    it('useB64=true, "json": parses the segment into an object', () => {
      const segment = base64UrlStringify(JSON.stringify({ sub: "u1" }));
      const result = decodeJWSPayload(segment, true, "json");
      expect(result).toEqual({ sub: "u1" });
    });

    it('useB64=true, "json": rejects a segment that is not a JSON object', () => {
      const segment = base64UrlStringify("hello");
      expectThrowsJWTError(() => decodeJWSPayload(segment, true, "json"), "ERR_JWS_INVALID");
    });

    it('useB64=true, "string": returns the decoded text', () => {
      const segment = base64UrlStringify("hello");
      const result = decodeJWSPayload(segment, true, "string");
      expect(result).toBe("hello");
    });

    it('useB64=true, "bytes": returns raw bytes', () => {
      const bytes = textEncoder.encode("raw");
      const segment = base64UrlStringify(bytes);
      const result = decodeJWSPayload(segment, true, "bytes");
      expect(result).toBeInstanceOf(Uint8Array);
      expect(textDecoder.decode(result as Uint8Array<ArrayBuffer>)).toBe("raw");
    });

    it("useB64=true: reports an undecodable segment", () => {
      expectThrowsJWTError(
        () => decodeJWSPayload("not base64url!", true, "bytes"),
        "ERR_JWS_INVALID",
      );
    });

    it('useB64=false, "string": returns the payload segment as-is', () => {
      const result = decodeJWSPayload("raw-payload", false, "string");
      expect(result).toBe("raw-payload");
    });

    it('useB64=false, "bytes": UTF-8 encodes the segment', () => {
      const result = decodeJWSPayload("raw-payload", false, "bytes");
      expect(result).toBeInstanceOf(Uint8Array);
      expect(textDecoder.decode(result as Uint8Array<ArrayBuffer>)).toBe("raw-payload");
    });

    it('useB64=false, "json": parses the segment', () => {
      const result = decodeJWSPayload('{"sub":"u1"}', false, "json");
      expect(result).toEqual({ sub: "u1" });
    });
  });

  describe("JWS_ALG_CTX / JWE_ALG_CTX sanity", () => {
    it("contexts are frozen", () => {
      expect(Object.isFrozen(JWS_ALG_CTX)).toBe(true);
      expect(Object.isFrozen(JWE_ALG_CTX)).toBe(true);
    });

    it("JWS context has the expected shape", () => {
      expect(JWS_ALG_CTX.octRoles).toBe(false);
      expect(JWS_ALG_CTX.errorCode).toBe("ERR_JWS_ALG_NOT_ALLOWED");
      expect(JWS_ALG_CTX.label).toBe("Algorithm");
    });

    it("JWE context has the expected shape", () => {
      expect(JWE_ALG_CTX.octRoles).toBe(true);
      expect(JWE_ALG_CTX.errorCode).toBe("ERR_JWE_ALG_NOT_ALLOWED");
      expect(JWE_ALG_CTX.label).toBe("Key management algorithm");
    });
  });

  // JWK_Symmetric reference used in other file too — type import sanity only.
  void ({} as JWK_Symmetric);
});

describe.concurrent("decodeProtectedHeader shape", () => {
  it.each(["null", "[]", "123", '"str"', "true"])(
    "rejects a header segment encoding %s",
    (json) => {
      expectThrowsJWTError(
        () => decodeProtectedHeader(base64UrlStringify(json), "JWS"),
        "ERR_JWS_INVALID",
      );
    },
  );

  it("reports the family in the message and carries no cause", () => {
    let error: unknown;
    try {
      decodeProtectedHeader(base64UrlStringify("null"), "JWE");
    } catch (e) {
      error = e;
    }
    expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    expect((error as JWTError).message).toBe(
      "Invalid JWE: Protected header must be a JSON object.",
    );
    expect((error as JWTError).cause).toBeUndefined();
  });

  it("still accepts an absent segment and a plain object", () => {
    expect(decodeProtectedHeader(undefined, "JWS")).toEqual({});
    expect(decodeProtectedHeader(base64UrlStringify('{"alg":"HS256"}'), "JWS")).toEqual({
      alg: "HS256",
    });
  });
});

describe.concurrent("error code typing", () => {
  it("narrows on a known code and rejects a typo at the type level", () => {
    const error = new JWTError("boom", "ERR_JWS_INVALID");
    expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    // @ts-expect-error a misspelled code must not type-check
    expect(isJWTError(error, "ERR_JWS_INVALD")).toBe(false);

    const known: KnownJWTErrorCode = "ERR_JWT_EXPIRED";
    expect(known).toBe("ERR_JWT_EXPIRED");
    // @ts-expect-error KnownJWTErrorCode is the closed literal union
    const typo: KnownJWTErrorCode = "ERR_JWT_EXPIRD";
    expect(typo).toBe("ERR_JWT_EXPIRD");

    // `JWTErrorCode` stays open for forward compatibility.
    const custom: JWTErrorCode = "ERR_SOMETHING_NEW";
    expect(new JWTError("x", custom).code).toBe("ERR_SOMETHING_NEW");
  });
});
