import { describe, it, expect } from "vitest";
import { secureRandomBytes, textEncoder } from "unsecure";
import {
  concatUint8Arrays,
  maybeArray,
  isPublicJWK,
  isPrivateJWK,
  isSymmetricJWK,
  assertCryptoKey,
  isCryptoKeyPair,
  computeDurationInSeconds,
  computeJwtTimeClaims,
  validateJwtClaims,
  validateCriticalHeadersJWE,
  inferJWSAllowedAlgorithms,
  inferJWEAllowedAlgorithms,
} from "../src/core/utils";
import { generateKey } from "../src/core/jwk";
import type {
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JWK_RSA_Public,
} from "../src/core/types";

describe.concurrent("Utility Functions", () => {
  describe("concatUint8Arrays", () => {
    it("should ganarate random bytes and successfully concatenate them", () => {
      const base = new Uint8Array([1, 2, 3]);
      const random = secureRandomBytes(3);
      const concatenated = concatUint8Arrays(base, random);

      expect(concatenated).toBeInstanceOf(Uint8Array);
      expect(concatenated.length).toBe(6);
      expect(concatenated).toEqual(new Uint8Array([1, 2, 3, ...random]));
    });
  });

  describe("computeDurationInSeconds", () => {
    it("should compute expiresIn correctly", () => {
      expect(computeDurationInSeconds("1s")).toBe(1);
      expect(computeDurationInSeconds("1m")).toBe(60);
      expect(computeDurationInSeconds("1h")).toBe(3600);
      expect(computeDurationInSeconds("1D")).toBe(86_400);
      expect(computeDurationInSeconds("2D")).toBe(172_800);
      expect(computeDurationInSeconds(10)).toBe(10);
    });

    it("should throw on invalid input", () => {
      // @ts-expect-error intentional invalid input
      expect(() => computeDurationInSeconds("")).toThrow();
      // @ts-expect-error intentional invalid input
      expect(() => computeDurationInSeconds("5x")).toThrow();
      expect(() => computeDurationInSeconds(-10)).toThrow();
      expect(() => computeDurationInSeconds(0)).toThrow();
      expect(() => computeDurationInSeconds(Number.NaN)).toThrow();
    });
  });

  describe("maybeArray", () => {
    it("wraps a scalar in an array", () => {
      expect(maybeArray("hello")).toEqual(["hello"]);
      expect(maybeArray(42)).toEqual([42]);
    });

    it("returns an array as-is", () => {
      expect(maybeArray(["a", "b"])).toEqual(["a", "b"]);
    });
  });

  describe("computeJwtTimeClaims", () => {
    it("should compute iat and exp claims correctly", () => {
      const date = new Date(0); // epoch
      const now = date.getTime(); // 0 seconds

      let claims = computeJwtTimeClaims({}, { expiresIn: "1m", currentDate: date })!;
      expect(claims).toHaveProperty("iat");
      expect(claims.iat).toBe(now);
      expect(claims).toHaveProperty("exp");
      expect(claims.exp).toBe(now + 60);

      claims = computeJwtTimeClaims({ iat: 1000 }, { expiresIn: "1m", currentDate: date })!;
      expect(claims).toHaveProperty("iat");
      expect(claims.iat).toBe(1000);
      expect(claims).toHaveProperty("exp");
      expect(claims.exp).toBe(1060);
    });

    it("should set exp from expiresAt (absolute)", () => {
      const at = new Date("2030-01-01T00:00:00Z");
      const claims = computeJwtTimeClaims({}, { expiresAt: at, currentDate: new Date(0) })!;
      expect(claims.exp).toBe(Math.floor(at.getTime() / 1000));
      expect(claims.iat).toBe(0);
    });

    it("should set nbf from notBeforeAt", () => {
      const nbfDate = new Date("2030-01-01T00:00:00Z");
      const claims = computeJwtTimeClaims({}, { notBeforeAt: nbfDate, currentDate: new Date(0) })!;
      expect(claims.nbf).toBe(Math.floor(nbfDate.getTime() / 1000));
      expect(claims.iat).toBe(0);
      expect(claims.exp).toBeUndefined();
    });

    it("should set nbf from notBeforeIn (relative)", () => {
      const claims = computeJwtTimeClaims({}, { notBeforeIn: "5m", currentDate: new Date(0) })!;
      expect(claims.nbf).toBe(300);
      expect(claims.iat).toBe(0);
      expect(claims.exp).toBeUndefined();
    });

    it("should accept notBeforeIn: 0 (nbf = iat)", () => {
      const claims = computeJwtTimeClaims({}, { notBeforeIn: 0, currentDate: new Date(0) })!;
      expect(claims.nbf).toBe(0);
      expect(claims.iat).toBe(0);
    });

    it("throws when both notBeforeIn and notBeforeAt are provided", () => {
      expect(() => computeJwtTimeClaims({}, { notBeforeIn: 60, notBeforeAt: new Date() })).toThrow(
        /mutually exclusive/i,
      );
    });

    it("throws on negative notBeforeIn", () => {
      expect(() => computeJwtTimeClaims({}, { notBeforeIn: -60 })).toThrow(/zero or a positive/i);
    });

    it("should return undefined for invalid inputs", () => {
      const date = new Date(0);

      expect(computeJwtTimeClaims({}, { currentDate: date })).toBeUndefined();
      expect(
        computeJwtTimeClaims({ exp: 2000 }, { expiresIn: "1m", currentDate: date }),
      ).toBeUndefined();
      expect(
        computeJwtTimeClaims(textEncoder.encode("bytes"), {
          expiresIn: "1m",
          currentDate: date,
        }),
      ).toBeUndefined();
    });

    it("throws when both expiresIn and expiresAt are provided", () => {
      expect(() => computeJwtTimeClaims({}, { expiresIn: "1m", expiresAt: new Date() })).toThrow(
        /mutually exclusive/i,
      );
    });

    it("throws on invalid expiresAt / notBeforeAt Dates", () => {
      expect(() => computeJwtTimeClaims({}, { expiresAt: new Date("not-a-date") })).toThrow(
        /valid Date/i,
      );
      expect(() => computeJwtTimeClaims({}, { notBeforeAt: new Date("not-a-date") })).toThrow(
        /valid Date/i,
      );
    });
  });
});

describe("type guards", () => {
  describe("isPublicJWK", () => {
    it("returns true for EC public JWK (x, y, no d)", () => {
      const key: JWK_EC_Public = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
      expect(isPublicJWK(key)).toBe(true);
    });

    it("returns false for EC private JWK (has d)", () => {
      const key: JWK_EC_Private = { kty: "EC", crv: "P-256", x: "abc", y: "def", d: "priv" };
      expect(isPublicJWK(key)).toBe(false);
    });

    it("returns true for OKP public JWK (x, no d)", () => {
      const key: JWK_OKP_Public = { kty: "OKP", crv: "Ed25519", x: "abc" };
      expect(isPublicJWK(key)).toBe(true);
    });

    it("returns false for OKP private JWK (has d)", () => {
      const key: JWK_OKP_Private = { kty: "OKP", crv: "Ed25519", x: "abc", d: "priv" };
      expect(isPublicJWK(key)).toBe(false);
    });

    it("returns false for unknown kty", () => {
      expect(isPublicJWK({ kty: "DH", n: "abc" } as any)).toBe(false);
    });

    it("returns false for non-JWK values", () => {
      expect(isPublicJWK(null)).toBe(false);
      expect(isPublicJWK("string")).toBe(false);
      expect(isPublicJWK(42)).toBe(false);
    });
  });

  describe("isPrivateJWK", () => {
    it("returns true for EC private JWK (has d)", () => {
      const key: JWK_EC_Private = { kty: "EC", crv: "P-256", x: "abc", y: "def", d: "priv" };
      expect(isPrivateJWK(key)).toBe(true);
    });

    it("returns false for EC public JWK (no d)", () => {
      const key: JWK_EC_Public = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
      expect(isPrivateJWK(key)).toBe(false);
    });

    it("returns true for OKP private JWK (has d)", () => {
      const key: JWK_OKP_Private = { kty: "OKP", crv: "Ed25519", x: "abc", d: "priv" };
      expect(isPrivateJWK(key)).toBe(true);
    });

    it("returns false for OKP public JWK (no d)", () => {
      const key: JWK_OKP_Public = { kty: "OKP", crv: "Ed25519", x: "abc" };
      expect(isPrivateJWK(key)).toBe(false);
    });

    it("returns false for RSA public JWK", () => {
      const key: JWK_RSA_Public = { kty: "RSA", n: "abc", e: "AQAB" };
      expect(isPrivateJWK(key)).toBe(false);
    });

    it("returns false for oct JWK", () => {
      expect(isPrivateJWK({ kty: "oct", k: "abc" })).toBe(false);
    });

    it("returns false for non-JWK values", () => {
      expect(isPrivateJWK(null)).toBe(false);
      expect(isPrivateJWK("string")).toBe(false);
    });
  });

  describe("isSymmetricJWK", () => {
    it("returns true for oct JWK with k", () => {
      expect(isSymmetricJWK({ kty: "oct", k: "abc" })).toBe(true);
    });

    it("returns false for EC JWK", () => {
      expect(isSymmetricJWK({ kty: "EC", crv: "P-256", x: "a", y: "b" })).toBe(false);
    });
  });

  describe("assertCryptoKey", () => {
    it("passes for a CryptoKey", async () => {
      const key = await generateKey("HS256");
      expect(() => assertCryptoKey(key)).not.toThrow();
    });

    it("throws for a non-CryptoKey", () => {
      expect(() => assertCryptoKey({ type: "fake" })).toThrow("CryptoKey instance expected");
      expect(() => assertCryptoKey(null)).toThrow("CryptoKey instance expected");
    });
  });

  describe("isCryptoKeyPair", () => {
    it("returns true for a CryptoKeyPair", async () => {
      const pair = await generateKey("ES256");
      expect(isCryptoKeyPair(pair)).toBe(true);
    });

    it("returns false for a single CryptoKey", async () => {
      const key = await generateKey("HS256");
      expect(isCryptoKeyPair(key)).toBe(false);
    });

    it("returns false for non-key values", () => {
      expect(isCryptoKeyPair(null)).toBeFalsy();
      expect(isCryptoKeyPair({ publicKey: "nope", privateKey: "nope" })).toBeFalsy();
    });
  });
});

describe("validateCriticalHeadersJWE (direct)", () => {
  it("throws when crit is present but understoodFromOptions is undefined", () => {
    expect(() => validateCriticalHeadersJWE({ crit: ["someParam"], someParam: "value" })).toThrow(
      "Unprocessed critical header parameters: someParam",
    );
  });

  it("throws when a crit param is listed but not present in the header", () => {
    expect(() => validateCriticalHeadersJWE({ crit: ["missingParam"] }, ["missingParam"])).toThrow(
      'Critical header parameter "missingParam" listed in "crit" but not present',
    );
  });

  it("does not throw when all crit params are understood and present", () => {
    expect(() =>
      validateCriticalHeadersJWE({ crit: ["enc", "p2c"], enc: "A128GCM", p2c: 2048 }, []),
    ).not.toThrow();
  });

  it("does not throw when crit is absent", () => {
    expect(() => validateCriticalHeadersJWE({ enc: "A128GCM" }, [])).not.toThrow();
  });
});

describe("computeDurationInSeconds additional cases", () => {
  it("throws when expiresIn is neither number nor string", () => {
    // @ts-expect-error intentional invalid type
    expect(() => computeDurationInSeconds(true)).toThrow("Duration must be a number or a string");
  });

  it("throws on zero and negative expiresIn (must be positive)", () => {
    expect(() => computeDurationInSeconds(0)).toThrow(/positive integer/);
    expect(() => computeDurationInSeconds(-5)).toThrow(/positive integer/);
  });
});

describe("validateJwtClaims additional cases", () => {
  it("throws when iat is in the future beyond clock tolerance (maxTokenAge)", () => {
    const futureIat = Math.floor(Date.now() / 1000) + 100; // 100 seconds in the future
    expect(() =>
      validateJwtClaims(
        { iat: futureIat },
        { maxTokenAge: 60, clockTolerance: 10 }, // tolerance only 10s, iat is 100s in future
      ),
    ).toThrow("Token was issued in the future");
  });

  it("throws 'Token is too old' for maxTokenAge violation", () => {
    const oldIat = Math.floor(Date.now() / 1000) - 300; // 300s ago
    expect(() => validateJwtClaims({ iat: oldIat }, { maxTokenAge: 60 })).toThrow(
      "Token is too old",
    );
  });

  it("throws when maxTokenAge is set but iat is not a number", () => {
    // `iat` must be present — otherwise the missing-claim check fires first and
    // this branch never runs.
    expect(() =>
      // @ts-expect-error intentional non-number iat
      validateJwtClaims({ iat: "not-a-number" }, { maxTokenAge: 60 }),
    ).toThrow('"iat" (Issued At) Claim must be a number');
  });

  // RFC 7519 §4.1: exp/nbf/iat are NumericDate and must be finite numbers.
  it("throws on non-finite exp / nbf", () => {
    // @ts-expect-error intentional non-number exp
    expect(() => validateJwtClaims({ exp: "never" })).toThrow(
      '"exp" (Expiration Time) Claim must be a number',
    );
    // @ts-expect-error intentional non-number nbf
    expect(() => validateJwtClaims({ nbf: "later" })).toThrow(
      '"nbf" (Not Before) Claim must be a number',
    );
    expect(() => validateJwtClaims({ exp: Number.NaN })).toThrow(
      '"exp" (Expiration Time) Claim must be a number',
    );
  });

  it("throws for subject mismatch", () => {
    expect(() =>
      validateJwtClaims({ sub: "actual-subject" }, { subject: "expected-subject" }),
    ).toThrow('"sub" (Subject) Claim');
  });
});

describe("inferJWSAllowedAlgorithms", () => {
  it("returns undefined for raw bytes and lookup functions", () => {
    expect(inferJWSAllowedAlgorithms(new Uint8Array(32))).toBeUndefined();
    expect(inferJWSAllowedAlgorithms("password")).toBeUndefined();
    expect(inferJWSAllowedAlgorithms(() => undefined)).toBeUndefined();
    expect(inferJWSAllowedAlgorithms(null)).toBeUndefined();
    expect(inferJWSAllowedAlgorithms(42)).toBeUndefined();
  });

  it("infers from EC / OKP JWKs that lack alg (WebCrypto export case)", () => {
    expect(inferJWSAllowedAlgorithms({ kty: "EC", crv: "P-256", x: "", y: "" })).toEqual(["ES256"]);
    expect(inferJWSAllowedAlgorithms({ kty: "EC", crv: "P-384", x: "", y: "" })).toEqual(["ES384"]);
    expect(inferJWSAllowedAlgorithms({ kty: "EC", crv: "P-521", x: "", y: "" })).toEqual(["ES512"]);
    expect(inferJWSAllowedAlgorithms({ kty: "OKP", crv: "Ed25519", x: "" })).toEqual([
      "Ed25519",
      "EdDSA",
    ]);
    expect(inferJWSAllowedAlgorithms({ kty: "OKP", crv: "Ed448", x: "" })).toEqual(["EdDSA"]);
  });

  it("infers from CryptoKeys across JWS alg families", async () => {
    const hmac = (await generateKey("HS384")) as CryptoKey;
    expect(inferJWSAllowedAlgorithms(hmac)).toEqual(["HS384"]);

    const rsa = await generateKey("RS512", { modulusLength: 2048 });
    expect(inferJWSAllowedAlgorithms(rsa.publicKey)).toEqual(["RS512"]);
    expect(inferJWSAllowedAlgorithms(rsa)).toEqual(["RS512"]);

    const pss = await generateKey("PS256", { modulusLength: 2048 });
    expect(inferJWSAllowedAlgorithms(pss.publicKey)).toEqual(["PS256"]);

    const ec = await generateKey("ES384");
    expect(inferJWSAllowedAlgorithms(ec.publicKey)).toEqual(["ES384"]);

    const ed = await generateKey("Ed25519");
    expect(inferJWSAllowedAlgorithms(ed.publicKey)).toEqual(["Ed25519", "EdDSA"]);
  });

  it("returns undefined for a JWKSet where any key lacks alg and kty-based inference fails", () => {
    const incomplete = { keys: [{ kty: "oct", k: "abc" }] };
    expect(inferJWSAllowedAlgorithms(incomplete)).toBeUndefined();
  });
});

describe("inferJWEAllowedAlgorithms", () => {
  it("infers password-like material to PBES2 + dir", () => {
    expect(inferJWEAllowedAlgorithms("pw")).toEqual([
      "PBES2-HS256+A128KW",
      "PBES2-HS384+A192KW",
      "PBES2-HS512+A256KW",
      "dir",
    ]);
    expect(inferJWEAllowedAlgorithms(new Uint8Array(16))).toHaveLength(4);
  });

  it("returns undefined for lookup functions and non-object primitives", () => {
    expect(inferJWEAllowedAlgorithms(() => undefined)).toBeUndefined();
    expect(inferJWEAllowedAlgorithms(null)).toBeUndefined();
    expect(inferJWEAllowedAlgorithms(true)).toBeUndefined();
  });

  it("infers from EC / OKP ECDH-capable JWKs without alg", () => {
    expect(inferJWEAllowedAlgorithms({ kty: "EC", crv: "P-256", x: "", y: "" })).toContain(
      "ECDH-ES+A128KW",
    );
    expect(inferJWEAllowedAlgorithms({ kty: "OKP", crv: "X25519", x: "" })).toContain("ECDH-ES");
  });

  it("infers from oct JWK alg variants", () => {
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "A128GCM" })).toEqual([
      "A128GCMKW",
      "dir",
    ]);
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "A256KW" })).toEqual([
      "A256KW",
      "dir",
    ]);
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "A256CBC-HS512" })).toEqual([
      "dir",
    ]);
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "dir" })).toEqual(["dir"]);
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x" })).toBeUndefined();
  });

  it("infers from CryptoKeys across JWE alg families (delegates to privateKey on pairs)", async () => {
    const kw = (await generateKey("A128KW")) as CryptoKey;
    expect(inferJWEAllowedAlgorithms(kw)).toEqual(["A128KW", "dir"]);

    const gcm = (await generateKey("A192GCM")) as CryptoKey;
    expect(inferJWEAllowedAlgorithms(gcm)).toEqual(["A192GCMKW", "dir"]);

    const rsaOaep = await generateKey("RSA-OAEP-384", { modulusLength: 2048 });
    expect(inferJWEAllowedAlgorithms(rsaOaep.privateKey)).toEqual(["RSA-OAEP-384"]);
    expect(inferJWEAllowedAlgorithms(rsaOaep)).toEqual(["RSA-OAEP-384"]);

    // A bare ECDH CryptoKey carries no wrap-variant hint, so inference returns the
    // full ECDH-ES family and the caller selects the specific wrap alg.
    const ecdh = await generateKey("ECDH-ES+A128KW", { namedCurve: "P-256" });
    expect(inferJWEAllowedAlgorithms(ecdh.privateKey)).toContain("ECDH-ES");
    expect(inferJWEAllowedAlgorithms(ecdh.privateKey)).toContain("ECDH-ES+A128KW");
  });
});
