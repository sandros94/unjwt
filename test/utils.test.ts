import { describe, it, expect, expectTypeOf } from "vitest";
import { secureRandomBytes, textEncoder } from "unsecure";
import {
  base64UrlStringify,
  base64UrlParse,
  base64Stringify,
  base64Parse,
  base64UrlEncode,
  base64UrlDecode,
  base64Encode,
  base64Decode,
  concatUint8Arrays,
  digestUrl,
  maybeArray,
  isJWK,
  isPublicJWK,
  isPrivateJWK,
  isSymmetricJWK,
  isAsymmetricJWK,
  assertCryptoKey,
  isCryptoKeyPair,
  computeDurationInSeconds,
  isJWTContent,
  validateJwtClaims,
  inferJWSAllowedAlgorithms,
  inferJWEAllowedAlgorithms,
} from "../src/core/utils/index.ts";
import {
  computeJwtTimeClaims,
  parsePayloadBytes,
  parsePayloadSegment,
  parsePayloadText,
  validateCriticalHeadersJWE,
  validateCriticalHeadersJWS,
} from "../src/core/internal.ts";
import { generateJWK, generateKey, thumbprint } from "../src/core/jwk.ts";
import { sign, verify } from "../src/core/jws.ts";
import { isJWTError, type JWTError } from "../src/core/error.ts";
import type {
  JOSEPayloadMode,
  JWTClaims,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_oct,
  JWK_Public,
  JWK_Private,
  JWK,
  JWK_OKP_Public,
  JWK_OKP_Private,
  JWK_RSA_Public,
} from "../src/core/types/index.ts";

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

    it("should throw ERR_INVALID_OPTION on invalid input", () => {
      const optionError = expect.objectContaining({
        name: "JWTError",
        code: "ERR_INVALID_OPTION",
      });
      // @ts-expect-error intentional invalid input
      expect(() => computeDurationInSeconds("")).toThrow(optionError);
      // @ts-expect-error intentional invalid input
      expect(() => computeDurationInSeconds("5x")).toThrow(optionError);
      expect(() => computeDurationInSeconds(-10)).toThrow(optionError);
      expect(() => computeDurationInSeconds(0)).toThrow(optionError);
      expect(() => computeDurationInSeconds(Number.NaN)).toThrow(optionError);
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
      expect(claims.exp).toBe(now + 60);
    });

    it("writes the clock as whole seconds rounded down", () => {
      const currentDate = new Date(1792065600_999);
      expect(computeJwtTimeClaims({}, { expiresIn: 60, notBeforeIn: 0, currentDate })).toEqual({
        iat: 1792065600,
        nbf: 1792065600,
        exp: 1792065660,
      });
      expect(
        computeJwtTimeClaims({}, { issuedAt: true, currentDate: new Date(1792065600_500) }),
      ).toEqual({ iat: 1792065600 });
    });

    it("writes iat alone from issuedAt", () => {
      const date = new Date("2030-01-01T00:00:00Z");
      const at = Math.floor(date.getTime() / 1000);

      expect(computeJwtTimeClaims({ sub: "u" }, { issuedAt: true, currentDate: date })).toEqual({
        sub: "u",
        iat: at,
      });
      expect(computeJwtTimeClaims({}, { issuedAt: date, currentDate: new Date(0) })).toEqual({
        iat: at,
      });
      expect(
        computeJwtTimeClaims({}, { issuedAt: date, expiresIn: "1m", currentDate: new Date(0) }),
      ).toEqual({ iat: at, exp: 60 });
      expect(
        computeJwtTimeClaims({}, { issuedAt: date, notBeforeIn: 0, currentDate: new Date(0) }),
      ).toEqual({ iat: at, nbf: 0 });
      expect(computeJwtTimeClaims({ iat: 1000 }, { issuedAt: date })).toBeUndefined();
      expect(computeJwtTimeClaims({}, { issuedAt: false })).toBeUndefined();
      expect(
        computeJwtTimeClaims({}, { issuedAt: false, expiresIn: "1m", currentDate: date }),
      ).toEqual({
        iat: at,
        exp: at + 60,
      });
      expect(computeJwtTimeClaims("text", { issuedAt: true })).toBeUndefined();
    });

    it("refuses an issuedAt that is neither a boolean nor a valid Date", () => {
      for (const issuedAt of ["now", 0, new Date("nope")]) {
        const error = (() => {
          try {
            // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- probing a runtime refusal
            computeJwtTimeClaims({}, { issuedAt: issuedAt as never });
            return undefined;
          } catch (caught) {
            return caught;
          }
        })();
        expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      }
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
      for (const options of [
        { expiresAt: new Date("not-a-date") },
        { notBeforeAt: new Date("not-a-date") },
      ]) {
        const error = catchError(() => computeJwtTimeClaims({}, options));
        expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
        expect((error as Error).message).toMatch(/valid Date/i);
      }
    });

    it.each([
      ["a number", 1_900_000_000],
      ["a string", "2030-01-01T00:00:00Z"],
      ["null", null],
    ])("throws when expiresAt / notBeforeAt is %s", (_label, value) => {
      for (const name of ["expiresAt", "notBeforeAt"] as const) {
        const error = catchError(() => computeJwtTimeClaims({}, { [name]: value }));
        expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
        expect((error as Error).message).toContain(name);
      }
    });
  });
});

describe("digestUrl", () => {
  it("digests text as UTF-8 and bytes as given, base64url, SHA-256 by default", async () => {
    const text = await digestUrl("abc");
    expect(text).toBe("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
    expect(await digestUrl(textEncoder.encode("abc"))).toBe(text);
    expect(await digestUrl("abc", "SHA-256")).toBe(text);
    expect(await digestUrl("abc", "SHA-384")).toBe(
      "ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP_W-2AhgcroefMI1i67KE0yCWn",
    );
    expect(await digestUrl("abc", "SHA-512")).toBe(
      "3a81oZNherrMQXNJriBBMRLm-k6JqX6iCp7u5ktV05ohkpkqJ0_BqDa6PCOj_uu9RU1EI2Q86A4qmslPpUyknw",
    );
    expectTypeOf(digestUrl).returns.resolves.toEqualTypeOf<string>();
  });

  it("is the last step of a JWK thumbprint", async () => {
    const { publicKey } = await generateKey("ES256", { toJWK: true, kid: false });
    const canonical = `{"crv":"P-256","kty":"EC","x":"${publicKey.x}","y":"${publicKey.y}"}`;
    expect(await digestUrl(canonical)).toBe(await thumbprint(publicKey));
  });

  it("binds a DPoP proof to its access token (RFC 9449)", async () => {
    const [{ publicKey, privateKey }, serverKey] = await Promise.all([
      generateJWK("ES256", { kid: false }),
      generateJWK("ES256"),
    ]);
    const accessToken = await sign(
      { sub: "user_42", cnf: { jkt: await thumbprint(publicKey) } },
      serverKey.privateKey,
      { expiresIn: "10m", protectedHeader: { typ: "at+jwt" } },
    );
    const proof = await sign(
      {
        jti: crypto.randomUUID(),
        htm: "GET",
        htu: "https://api.example.com/orders",
        ath: await digestUrl(accessToken),
      },
      privateKey,
      { issuedAt: true, protectedHeader: { typ: "dpop+jwt", jwk: publicKey } },
    );

    const { payload, protectedHeader } = await verify<{ ath: string }>(
      proof,
      (header) => header.jwk,
      { algorithms: ["ES256"], typ: "dpop+jwt", maxTokenAge: "60s" },
    );
    const access = await verify(accessToken, serverKey.publicKey, { typ: "at+jwt" });
    expect(payload.ath).toBe(await digestUrl(accessToken));
    expect(await thumbprint(protectedHeader.jwk!)).toBe(access.payload.cnf?.jkt);
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

    it('returns false for EC JWK carrying "k"', () => {
      const key = { kty: "EC", crv: "P-256", x: "abc", y: "def", k: "secret" } as JWK_EC_Public;
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
      expect(isPublicJWK({ kty: "DH", n: "abc" })).toBe(false);
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

  describe("isJWK", () => {
    it("returns true for each modelled kty", () => {
      expect(isJWK({ kty: "oct", k: "abc" })).toBe(true);
      expect(isJWK({ kty: "RSA", n: "abc", e: "AQAB" })).toBe(true);
      expect(isJWK({ kty: "EC", crv: "P-256", x: "a", y: "b" })).toBe(true);
      expect(isJWK({ kty: "OKP", crv: "Ed25519", x: "a" })).toBe(true);
    });

    it("returns false for an unmodelled kty", () => {
      expect(isJWK({ kty: "AKP", pub: "..." })).toBe(false);
    });

    it("returns false for missing kty and non-JWK values", () => {
      expect(isJWK({ k: "abc" })).toBe(false);
      expect(isJWK({ kty: 42 })).toBe(false);
      expect(isJWK(null)).toBe(false);
      expect(isJWK("string")).toBe(false);
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
      'Unprocessed critical header parameters: "someParam"',
    );
  });

  it("throws when a crit param is listed but not present in the header", () => {
    expect(() => validateCriticalHeadersJWE({ crit: ["missingParam"] }, ["missingParam"])).toThrow(
      'Critical header parameter "missingParam" is missing from the protected header',
    );
  });

  it("does not throw when all crit params are understood and present", () => {
    // Registered parameters (`enc`, `p2c`, …) may never appear in `crit`; extensions can.
    expect(() =>
      validateCriticalHeadersJWE({ crit: ["app", "tenant"], app: "web", tenant: "acme" }, [
        "app",
        "tenant",
      ]),
    ).not.toThrow();
  });

  it("does not throw when crit is absent", () => {
    expect(() => validateCriticalHeadersJWE({ enc: "A128GCM" }, [])).not.toThrow();
  });
});

describe("isJWTContent", () => {
  it("recognises a JWT typ and a JSON cty", () => {
    expect(isJWTContent({ typ: "at+jwt" })).toBe(true);
    expect(isJWTContent({ cty: "application/json" })).toBe(true);
    expect(isJWTContent({ cty: "application/ld+json" })).toBe(true);
    expect(isJWTContent({ typ: "text", cty: "text/plain" })).toBe(false);
    expect(isJWTContent(undefined)).toBe(false);
  });

  it.each([42, null, {}, ["jwt"]])("returns false for a non-string typ (%j)", (typ) => {
    expect(isJWTContent({ typ: typ as never })).toBe(false);
  });

  it("returns false for a non-string cty", () => {
    expect(isJWTContent({ cty: 42 as never })).toBe(false);
  });

  it("still reads a JSON cty beside a non-string typ", () => {
    expect(isJWTContent({ typ: 42 as never, cty: "application/json" })).toBe(true);
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
    ).toThrow('JWT "iat" is in the future');
  });

  it("throws 'Token is too old' for maxTokenAge violation", () => {
    const oldIat = Math.floor(Date.now() / 1000) - 300; // 300s ago
    expect(() => validateJwtClaims({ iat: oldIat }, { maxTokenAge: 60 })).toThrow(
      "is older than maxTokenAge",
    );
  });

  it("throws when maxTokenAge is set but iat is not a number", () => {
    // `iat` must be present — otherwise the missing-claim check fires first and
    // this branch never runs.
    expect(() =>
      // @ts-expect-error intentional non-number iat
      validateJwtClaims({ iat: "not-a-number" }, { maxTokenAge: 60 }),
    ).toThrow('JWT "iat" must be a number');
  });

  // RFC 7519 §4.1: exp/nbf/iat are NumericDate and must be finite numbers.
  it("throws on non-finite exp / nbf", () => {
    // @ts-expect-error intentional non-number exp
    expect(() => validateJwtClaims({ exp: "never" })).toThrow('JWT "exp" must be a number');
    // @ts-expect-error intentional non-number nbf
    expect(() => validateJwtClaims({ nbf: "later" })).toThrow('JWT "nbf" must be a number');
    expect(() => validateJwtClaims({ exp: Number.NaN })).toThrow('JWT "exp" must be a number');
  });

  it("throws for subject mismatch", () => {
    expect(() =>
      validateJwtClaims({ sub: "actual-subject" }, { subject: "expected-subject" }),
    ).toThrow('Invalid JWT "sub"');
  });

  it.each([
    ["an empty audience", { audience: "" }],
    ["an audience list with an empty entry", { audience: [""] }],
    ["an audience that is not a string", { audience: 1 }],
    ["an empty issuer", { issuer: "" }],
    ["an issuer list with a non-string entry", { issuer: ["i", 2] }],
    ["an empty subject", { subject: "" }],
    ["a subject that is not a string", { subject: 1 }],
    ["maxTokenAge: 0", { maxTokenAge: 0 }],
    ["requiredClaims that is a string", { requiredClaims: "exp" }],
    ["requiredClaims with a non-string entry", { requiredClaims: ["exp", 1] }],
  ])("refuses %s instead of skipping the check", (_label, options) => {
    const claims = { sub: "u", iss: "i", aud: "a", iat: Math.floor(Date.now() / 1000) };
    expect(() => validateJwtClaims(claims, options as never)).toThrow(
      expect.objectContaining({ code: "ERR_INVALID_OPTION" }),
    );
  });

  it("keeps an empty audience or issuer list as a check nothing satisfies", () => {
    expect(() => validateJwtClaims({ aud: "a" }, { audience: [] })).toThrow(
      expect.objectContaining({ code: "ERR_JWT_CLAIM_INVALID" }),
    );
    expect(() => validateJwtClaims({ iss: "i" }, { issuer: [] })).toThrow(
      expect.objectContaining({ code: "ERR_JWT_CLAIM_INVALID" }),
    );
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
      "EdDSA",
      "Ed25519",
    ]);
  });

  it("infers nothing for an OKP JWK on an unsupported curve", () => {
    expect(inferJWSAllowedAlgorithms({ kty: "OKP", crv: "Ed448", x: "" })).toBeUndefined();
    expect(inferJWEAllowedAlgorithms({ kty: "OKP", crv: "X448", x: "" })).toBeUndefined();
  });

  it("infers from CryptoKeys across JWS alg families", async () => {
    const [hmac, rsa, pss, ec, ed] = await Promise.all([
      generateKey("HS384"),
      generateKey("RS512", { modulusLength: 2048 }),
      generateKey("PS256", { modulusLength: 2048 }),
      generateKey("ES384"),
      generateKey("Ed25519"),
    ]);
    expect(inferJWSAllowedAlgorithms(hmac)).toEqual(["HS384"]);
    expect(inferJWSAllowedAlgorithms(rsa.publicKey)).toEqual(["RS512"]);
    expect(inferJWSAllowedAlgorithms(rsa)).toEqual(["RS512"]);
    expect(inferJWSAllowedAlgorithms(pss.publicKey)).toEqual(["PS256"]);
    expect(inferJWSAllowedAlgorithms(ec.publicKey)).toEqual(["ES384"]);
    expect(inferJWSAllowedAlgorithms(ed.publicKey)).toEqual(["EdDSA", "Ed25519"]);
  });

  it("infers nothing from a CryptoKey whose hash is not SHA-256/384/512", async () => {
    const usages: KeyUsage[] = ["sign", "verify"];
    const rsa = { modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" };
    const [hmac, pkcs1, pss] = await Promise.all([
      crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-1" }, false, usages),
      crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", ...rsa }, false, usages),
      crypto.subtle.generateKey({ name: "RSA-PSS", ...rsa }, false, usages),
    ]);
    expect(inferJWSAllowedAlgorithms(hmac)).toBeUndefined();
    expect(inferJWSAllowedAlgorithms(pkcs1.publicKey)).toBeUndefined();
    expect(inferJWSAllowedAlgorithms(pss)).toBeUndefined();
  });

  it("returns undefined for a JWKSet where no key contributes", () => {
    const incomplete = { keys: [{ kty: "oct", k: "abc" }] };
    expect(inferJWSAllowedAlgorithms(incomplete)).toBeUndefined();
  });

  it("skips JWKSet entries it cannot infer instead of failing the whole set", () => {
    const set = {
      keys: [
        { kty: "RSA", n: "x", e: "AQAB" },
        { kty: "EC", crv: "P-256", x: "", y: "" },
        null,
        "junk",
      ],
    };
    expect(inferJWSAllowedAlgorithms(set)).toEqual(["ES256"]);
  });

  it("ignores oct entries of a JWKSet unless symmetric material is admitted", () => {
    const set = {
      keys: [
        { kty: "EC", crv: "P-256", x: "", y: "" },
        { kty: "oct", k: "x", alg: "HS256" },
      ],
    };
    expect(inferJWSAllowedAlgorithms(set)).toEqual(["ES256"]);
    expect(inferJWSAllowedAlgorithms(set, { allowSymmetric: true })).toEqual(["ES256", "HS256"]);
  });
});

describe("inferJWEAllowedAlgorithms", () => {
  it("infers a password string to the PBES2 family alone", () => {
    expect(inferJWEAllowedAlgorithms("pw")).toEqual([
      "PBES2-HS256+A128KW",
      "PBES2-HS384+A192KW",
      "PBES2-HS512+A256KW",
    ]);
  });

  it("returns undefined for raw bytes — they carry no role of their own", () => {
    expect(inferJWEAllowedAlgorithms(new Uint8Array(16))).toBeUndefined();
    expect(inferJWEAllowedAlgorithms(new Uint8Array(32))).toBeUndefined();
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

  it("maps an oct JWK alg to the single role it declares", () => {
    // Content encryption algs name a CEK, which only `dir` consumes.
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "A128GCM" })).toEqual(["dir"]);
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "A256CBC-HS512" })).toEqual([
      "dir",
    ]);
    // Key management algs name a wrapping key, and nothing else.
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "A256KW" })).toEqual(["A256KW"]);
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "A256GCMKW" })).toEqual([
      "A256GCMKW",
    ]);
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "PBES2-HS256+A128KW" })).toEqual([
      "PBES2-HS256+A128KW",
    ]);
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x", alg: "dir" })).toEqual(["dir"]);
    expect(inferJWEAllowedAlgorithms({ kty: "oct", k: "x" })).toBeUndefined();
  });

  it("ignores oct entries of a JWKSet unless symmetric material is admitted", () => {
    const set = { keys: [{ kty: "oct", k: "x", alg: "A256KW" }] };
    expect(inferJWEAllowedAlgorithms(set)).toBeUndefined();
    expect(inferJWEAllowedAlgorithms(set, { allowSymmetric: true })).toEqual(["A256KW"]);
  });

  it("infers from CryptoKeys across JWE alg families (delegates to privateKey on pairs)", async () => {
    const kw = await generateKey("A128KW");
    expect(inferJWEAllowedAlgorithms(kw)).toEqual(["A128KW", "dir"]);

    const gcm = await generateKey("A192GCM");
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

describe("base64 tooling", () => {
  const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);

  describe("base64url (RFC 7515 §2)", () => {
    it("stringifies without padding on the URL-safe alphabet", () => {
      expect(base64UrlStringify(bytes)).toBe("-__-");
      expect(base64UrlStringify("hello")).toBe("aGVsbG8");
      expect(base64UrlStringify(new Uint8Array(0))).toBe("");
    });

    it("parses canonical unpadded input, mirroring the input type", () => {
      expect(base64UrlParse("aGVsbG8")).toBe("hello");
      expect(base64UrlParse("-__-", { returnAs: "uint8array" })).toEqual(bytes);
      expect(base64UrlParse(textEncoder.encode("aGVsbG8"))).toEqual(textEncoder.encode("hello"));
      expect(base64UrlParse(textEncoder.encode("aGVsbG8"), { returnAs: "string" })).toBe("hello");
    });

    it("rejects padding, the standard alphabet, whitespace and stray bits", () => {
      for (const bad of ["aGVsbG8=", "+__+", "aGVs bG8", "aGVsbG9", "aGVsb"]) {
        expect(() => base64UrlParse(bad)).toThrow(
          expect.objectContaining({ name: "UnsecureError", code: "MALFORMED" }),
        );
      }
    });

    it("loose drops what it cannot use", () => {
      expect(base64UrlParse("aGVs bG8=", { loose: true })).toBe("hello");
      expect(base64UrlParse("+__+", { loose: true, returnAs: "bytes" })).toEqual(bytes);
    });
  });

  describe("standard base64 (RFC 4648 §4)", () => {
    it("stringifies padded on the standard alphabet", () => {
      expect(base64Stringify(bytes)).toBe("+//+");
      expect(base64Stringify("hello")).toBe("aGVsbG8=");
    });

    it("parses only padded canonical input", () => {
      expect(base64Parse("aGVsbG8=")).toBe("hello");
      expect(base64Parse("+//+", { returnAs: "uint8array" })).toEqual(bytes);
      for (const bad of ["aGVsbG8", "-__-", "aGVsbG8=="]) {
        expect(() => base64Parse(bad)).toThrow(
          expect.objectContaining({ name: "UnsecureError", code: "MALFORMED" }),
        );
      }
      expect(base64Parse("aGVsbG8", { loose: true })).toBe("hello");
    });
  });

  it("keeps the deprecated aliases pointing at the new functions", () => {
    expect(base64UrlEncode).toBe(base64UrlStringify);
    expect(base64UrlDecode).toBe(base64UrlParse);
    expect(base64Encode).toBe(base64Stringify);
    expect(base64Decode).toBe(base64Parse);
  });
});

describe.concurrent('"crit" shape validation (RFC 7515 §4.1.11 / RFC 7516 §4.1.13)', () => {
  const shapeCases: [string, unknown][] = [
    ["empty array", []],
    ["non-array", "b64"],
    ["array with a non-string entry", ["app", 1]],
  ];

  it.each(shapeCases)("JWS rejects a crit that is an %s", (_label, crit) => {
    const error = catchError(() =>
      validateCriticalHeadersJWS({ crit } as { crit?: string[] }, ["app"]),
    );
    expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    expect((error as Error).message).toBe(
      'Invalid JWS: "crit" must be a non-empty array of strings.',
    );
  });

  it.each(shapeCases)("JWE rejects a crit that is an %s", (_label, crit) => {
    const error = catchError(() =>
      validateCriticalHeadersJWE({ crit } as { crit?: string[] }, ["app"]),
    );
    expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    expect((error as Error).message).toBe(
      'Invalid JWE: "crit" must be a non-empty array of strings.',
    );
  });

  it.each(["alg", "typ", "cty", "kid", "crit", "jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256"])(
    'JWS rejects the registered header parameter "%s" in crit',
    (param) => {
      const error = catchError(() =>
        validateCriticalHeadersJWS({ [param]: "x", crit: [param] }, [param]),
      );
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
      expect((error as Error).message).toBe(
        'Invalid JWS: "crit" must not list registered header parameters.',
      );
    },
  );

  it.each(["alg", "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c"])(
    'JWE rejects the registered header parameter "%s" in crit',
    (param) => {
      const error = catchError(() =>
        validateCriticalHeadersJWE({ [param]: "x", crit: [param] }, [param]),
      );
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect((error as Error).message).toBe(
        'Invalid JWE: "crit" must not list registered header parameters.',
      );
    },
  );

  it.each([
    [{ crit: ["app"] }, 'Critical header parameter "app" is missing from the protected header'],
    [{ crit: ["app"], app: "web" }, 'Unprocessed critical header parameters: "app"'],
  ])("reports the same crit violation for JWS and JWE (%j)", (header, message) => {
    expect(() => validateCriticalHeadersJWS(header)).toThrow(message);
    expect(() => validateCriticalHeadersJWE(header)).toThrow(message);
  });

  it('allows "b64" (RFC 7797) in a JWS crit', () => {
    expect(() => validateCriticalHeadersJWS({ crit: ["b64"], b64: false })).not.toThrow();
  });

  it("keeps the recognized / missing semantics for extension parameters", () => {
    expect(() => validateCriticalHeadersJWS({ crit: ["app"], app: "web" }, ["app"])).not.toThrow();
    expect(() => validateCriticalHeadersJWS({ crit: ["app"], app: "web" })).toThrow(
      'Unprocessed critical header parameters: "app"',
    );
    expect(() => validateCriticalHeadersJWE({ crit: ["app"], app: "web" }, ["app"])).not.toThrow();
    expect(() => validateCriticalHeadersJWE({ crit: ["app"] }, ["app"])).toThrow(
      'Critical header parameter "app" is missing from the protected header',
    );
  });

  it("quotes and bounds a crit name in both messages", () => {
    const param = `x\r\nInjected: ${"a".repeat(200)}`;
    for (const header of [{ crit: [param] }, { crit: [param], [param]: 1 }]) {
      for (const validate of [validateCriticalHeadersJWS, validateCriticalHeadersJWE]) {
        const error = catchError(() => validate(header)) as Error;
        expect(isJWTError(error)).toBe(true);
        expect(error.message).not.toMatch(/[\r\n]/);
        expect(error.message).toContain(JSON.stringify(`${param.slice(0, 64)}…`));
        expect(error.message).not.toContain("a".repeat(65));
      }
    }
  });
});

describe.concurrent("validateJwtClaims option and NumericDate hygiene", () => {
  const now = Math.floor(Date.now() / 1000);

  describe("error text and cause", () => {
    it("carries a non-string jti as undefined in the ERR_JWT_EXPIRED cause", () => {
      const jti = { id: "t-1" } as unknown as string;
      const expired = catchError(() => validateJwtClaims({ jti, iat: now - 120, exp: now - 60 }));
      expect(isJWTError(expired, "ERR_JWT_EXPIRED")).toBe(true);
      expect((expired as JWTError).cause).toStrictEqual({
        jti: undefined,
        iat: now - 120,
        exp: now - 60,
      });

      const aged = catchError(() =>
        validateJwtClaims({ jti, iat: now - 3600 }, { maxTokenAge: 60 }),
      );
      expect(isJWTError(aged, "ERR_JWT_EXPIRED")).toBe(true);
      expect((aged as JWTError).cause).toHaveProperty("jti", undefined);

      const named = catchError(() => validateJwtClaims({ jti: "t-1", exp: now - 60 }));
      expect((named as JWTError).cause).toHaveProperty("jti", "t-1");
    });

    it("prints a NumericDate beyond the Date range as a number", () => {
      const nbf = catchError(() => validateJwtClaims({ nbf: 1e300 }));
      expect(isJWTError(nbf, "ERR_JWT_NBF")).toBe(true);
      expect((nbf as Error).message).toBe('JWT "nbf" is in the future (1e+300).');

      const iat = catchError(() => validateJwtClaims({ iat: 1e300 }, { maxTokenAge: 60 }));
      expect(isJWTError(iat, "ERR_JWT_CLAIM_INVALID")).toBe(true);
      expect((iat as Error).message).toBe('JWT "iat" is in the future (1e+300).');

      expect(catchError(() => validateJwtClaims({ nbf: 0 }))).toBeUndefined();
      const inRange = catchError(() => validateJwtClaims({ nbf: 4102444800 })) as Error;
      expect(inRange.message).toBe('JWT "nbf" is in the future (2100-01-01T00:00:00.000Z).');
    });
  });

  describe("clockTolerance", () => {
    it("accepts a Duration string and normalizes it to seconds", () => {
      expect(() => validateJwtClaims({ nbf: now + 120 }, { clockTolerance: "5m" })).not.toThrow();
      expect(() => validateJwtClaims({ nbf: now + 120 }, { clockTolerance: "1m" })).toThrow(
        'JWT "nbf" is in the future',
      );
    });

    it("accepts a numeric-string Duration as seconds, not as concatenation", () => {
      expect(() => validateJwtClaims({ nbf: now + 120 }, { clockTolerance: "300" })).not.toThrow();
      expect(() => validateJwtClaims({ nbf: now + 600 }, { clockTolerance: "300" })).toThrow(
        'JWT "nbf" is in the future',
      );
    });

    it.each([
      ["NaN", Number.NaN],
      ["negative", -5],
      ["Infinity", Number.POSITIVE_INFINITY],
      ["garbage string", "soon"],
      ["boolean", true],
    ])("rejects a %s clockTolerance", (_label, value) => {
      const error = catchError(() =>
        validateJwtClaims({ exp: now - 10 }, { clockTolerance: value as number }),
      );
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect((error as Error).message).toBe(
        "clockTolerance must be a non-negative number of seconds or a Duration.",
      );
    });
  });

  describe("required claims", () => {
    it("does not accept an inherited property as a present claim", () => {
      const claims = Object.create({ iss: "inherited" }) as { iss?: string };
      const error = catchError(() => validateJwtClaims(claims, { requiredClaims: ["iss"] }));
      expect(isJWTError(error, "ERR_JWT_CLAIM_MISSING")).toBe(true);
    });

    it("accepts an own claim that is explicitly undefined as present", () => {
      expect(() =>
        validateJwtClaims({ jti: undefined }, { requiredClaims: ["jti"] }),
      ).not.toThrow();
    });
  });

  describe("NumericDate", () => {
    it.each(["exp", "nbf", "iat"])("rejects a negative %s", (claim) => {
      const error = catchError(() => validateJwtClaims({ [claim]: -1 }));
      expect(isJWTError(error, "ERR_JWT_CLAIM_INVALID")).toBe(true);
    });

    it("keeps fractional NumericDate values valid (RFC 7519 §2)", () => {
      expect(() => validateJwtClaims({ exp: now + 60.5, nbf: now - 60.5 })).not.toThrow();
    });
  });

  describe("exact clock", () => {
    const T = 1792065600;
    const at = (seconds: number) => ({ currentDate: new Date(seconds * 1000), clockTolerance: 0 });
    const codeOf = (claims: JWTClaims, seconds: number) => {
      const error = catchError(() => validateJwtClaims(claims, at(seconds)));
      return isJWTError(error) ? error.code : undefined;
    };

    it("expires an integer exp at its second, not half a second early", () => {
      expect(codeOf({ exp: T }, T - 0.5)).toBeUndefined();
      expect(codeOf({ exp: T }, T - 0.001)).toBeUndefined();
      expect(codeOf({ exp: T }, T)).toBe("ERR_JWT_EXPIRED");
      expect(codeOf({ exp: T }, T + 0.499)).toBe("ERR_JWT_EXPIRED");
    });

    it("expires a fractional exp at its exact instant", () => {
      expect(codeOf({ exp: T + 0.4 }, T + 0.399)).toBeUndefined();
      expect(codeOf({ exp: T + 0.4 }, T + 0.4)).toBe("ERR_JWT_EXPIRED");
      expect(codeOf({ exp: T + 0.4 }, T + 0.499)).toBe("ERR_JWT_EXPIRED");
      expect(codeOf({ exp: T + 0.5 }, T + 0.499)).toBeUndefined();
      expect(codeOf({ exp: T + 0.5 }, T + 0.5)).toBe("ERR_JWT_EXPIRED");
    });

    it("refuses an integer nbf until its second, not half a second early", () => {
      expect(codeOf({ nbf: T }, T - 0.5)).toBe("ERR_JWT_NBF");
      expect(codeOf({ nbf: T }, T - 0.001)).toBe("ERR_JWT_NBF");
      expect(codeOf({ nbf: T }, T)).toBeUndefined();
    });

    it("refuses a fractional nbf until its exact instant", () => {
      expect(codeOf({ nbf: T + 0.5 }, T + 0.499)).toBe("ERR_JWT_NBF");
      expect(codeOf({ nbf: T + 0.5 }, T + 0.5)).toBeUndefined();
    });
  });

  it("renders maxTokenAge in the error message exactly as it was passed", () => {
    const error = catchError(() =>
      validateJwtClaims({ iat: now - 3600 }, { maxTokenAge: "5m" }),
    ) as Error;
    expect(error.message).toContain("maxTokenAge 5m");
    expect(error.message).not.toContain("5ms");
  });
});

describe("payload parsing", () => {
  const claimsBytes = textEncoder.encode('{"sub":"u1"}');

  it('parses a JSON object by default and under "json"', () => {
    expect(parsePayloadBytes(claimsBytes)).toEqual({ sub: "u1" });
    expect(parsePayloadBytes(claimsBytes, { payload: "json" })).toEqual({ sub: "u1" });
  });

  it.each(["[1]", "12", '"s"', "null", "nonsense"])('rejects %s under "json"', (raw) => {
    const error = catchError(() => parsePayloadBytes(textEncoder.encode(raw)));
    expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    expect((error as Error).message).toBe("Invalid JWS: Payload is not a JSON object.");
  });

  it("reports the JWE family when asked", () => {
    const error = catchError(() =>
      parsePayloadBytes(textEncoder.encode("nonsense"), { family: "JWE" }),
    );
    expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    expect((error as Error).message).toBe("Invalid JWE: Payload is not a JSON object.");
  });

  it('returns text under "string" and bytes under "bytes"', () => {
    expect(parsePayloadBytes(claimsBytes, { payload: "string" })).toBe('{"sub":"u1"}');
    expect(parsePayloadBytes(claimsBytes, { payload: "bytes" })).toBe(claimsBytes);
  });

  it("rejects invalid UTF-8 for the text-bearing modes", () => {
    const invalid = new Uint8Array([0xff, 0xfe]);
    for (const payload of ["json", "string"] as const) {
      const error = catchError(() => parsePayloadBytes(invalid, { payload }));
      expect(isJWTError(error, "ERR_JWS_INVALID")).toBe(true);
    }
    expect(parsePayloadBytes(invalid, { payload: "bytes" })).toBe(invalid);
  });

  it("reads UTF-8 text and reports invalid bytes under the requested family", () => {
    expect(parsePayloadText(claimsBytes)).toBe('{"sub":"u1"}');
    const invalid = new Uint8Array([0xff, 0xfe]);
    expect(
      isJWTError(
        catchError(() => parsePayloadText(invalid)),
        "ERR_JWS_INVALID",
      ),
    ).toBe(true);
    expect(
      isJWTError(
        catchError(() => parsePayloadText(invalid, { family: "JWE" })),
        "ERR_JWE_INVALID",
      ),
    ).toBe(true);
  });

  it("parses a Base64URL segment under the same modes", () => {
    const segment = base64UrlStringify('{"sub":"u1"}');
    expect(parsePayloadSegment(segment)).toEqual({ sub: "u1" });
    expect(parsePayloadSegment(segment, { payload: "string" })).toBe('{"sub":"u1"}');
    expect(parsePayloadSegment(segment, { payload: "bytes" })).toBeInstanceOf(Uint8Array);
  });
});

function catchError(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

describe("types", () => {
  interface MyClaims extends JWTClaims {
    role: string;
  }
  const bytes = new Uint8Array(0);
  const anyMode = (mode: JOSEPayloadMode) => parsePayloadBytes(bytes, { payload: mode });

  it("parsePayloadBytes and parsePayloadSegment type their result by payload mode", () => {
    expectTypeOf(() => parsePayloadBytes(bytes)).returns.toEqualTypeOf<JWTClaims>();
    expectTypeOf(() => parsePayloadBytes<MyClaims>(bytes)).returns.toEqualTypeOf<MyClaims>();
    expectTypeOf(() =>
      parsePayloadBytes<MyClaims>(bytes, { payload: "json" }),
    ).returns.toEqualTypeOf<MyClaims>();
    expectTypeOf(() =>
      parsePayloadBytes(bytes, { payload: "string" }),
    ).returns.toEqualTypeOf<string>();
    expectTypeOf(() => parsePayloadBytes(bytes, { payload: "bytes" })).returns.toEqualTypeOf<
      Uint8Array<ArrayBuffer>
    >();
    expectTypeOf(anyMode).returns.toEqualTypeOf<JWTClaims | string | Uint8Array<ArrayBuffer>>();
    expectTypeOf(() => parsePayloadSegment<MyClaims>("")).returns.toEqualTypeOf<MyClaims>();
    expectTypeOf(() => parsePayloadSegment("", { payload: "bytes" })).returns.toEqualTypeOf<
      Uint8Array<ArrayBuffer>
    >();
    // @ts-expect-error a claims type only applies to the JSON mode
    expectTypeOf(() => parsePayloadBytes<MyClaims>(bytes, { payload: "bytes" }));
  });
});

describe("guards on unknown input", () => {
  const oct = { kty: "oct", k: "c2VjcmV0", alg: "HS256" };
  const ec: JWK_EC_Public = { kty: "EC", crv: "P-256", x: "x", y: "y" };

  it("isAsymmetricJWK is false for anything that is not an asymmetric JWK", () => {
    expect(isAsymmetricJWK(ec)).toBe(true);
    expect(isAsymmetricJWK(oct)).toBe(false);
    expect(isAsymmetricJWK("x")).toBe(false);
    expect(isAsymmetricJWK(null)).toBe(false);
    expect(isAsymmetricJWK({ kty: "foo" })).toBe(false);
  });

  it("narrows an unknown value to the key type it checks for", () => {
    const value = JSON.parse("{}") as unknown;
    if (isSymmetricJWK(value)) expectTypeOf(value).toEqualTypeOf<JWK_oct>();
    if (isAsymmetricJWK(value)) expectTypeOf(value).toEqualTypeOf<Exclude<JWK, JWK_oct>>();
    if (isPrivateJWK(value)) expectTypeOf(value).toEqualTypeOf<JWK_Private>();
    if (isPublicJWK(value)) expectTypeOf(value).toEqualTypeOf<JWK_Public>();
    const either = JSON.parse("{}") as JWK_oct | JWK_EC_Public;
    if (isSymmetricJWK(either)) expectTypeOf(either).toEqualTypeOf<JWK_oct>();
    else expectTypeOf(either).toEqualTypeOf<JWK_EC_Public>();
  });
});
