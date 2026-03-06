import { describe, it, expect } from "vitest";
import {
  base64UrlEncode,
  base64UrlDecode,
  base64Encode,
  base64Decode,
  randomBytes,
  concatUint8Arrays,
  maybeArray,
  textEncoder,
  textDecoder,
  isPublicJWK,
  isPrivateJWK,
  isSymmetricJWK,
  assertCryptoKey,
  isCryptoKeyPair,
  sanitizeObject,
  computeExpiresInSeconds,
  computeJwtTimeClaims,
  validateJwtClaims,
  validateCriticalHeadersJWE,
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
  describe("textEncoder and textDecoder", () => {
    it("should be defined", () => {
      expect(textEncoder).toBeDefined();
      expect(textDecoder).toBeDefined();
    });

    it("should encode strings correctly", () => {
      const str = "hello world";
      const encoded = textEncoder.encode(str);

      expect(encoded).toBeInstanceOf(Uint8Array);
      expect(encoded).toEqual(new TextEncoder().encode(str));
    });

    it("should decode Uint8Array correctly", () => {
      const uint8Array = new Uint8Array([104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]);
      const decoded = textDecoder.decode(uint8Array);

      expect(decoded).toBe("hello world");
      expect(decoded).toEqual(new TextDecoder().decode(uint8Array));
    });
  });

  describe("randomBytes and concatUint8Arrays", () => {
    it("should ganarate random bytes and successfully concatenate them", () => {
      const base = new Uint8Array([1, 2, 3]);
      const random = randomBytes(3);
      const concatenated = concatUint8Arrays(base, random);

      expect(concatenated).toBeInstanceOf(Uint8Array);
      expect(concatenated.length).toBe(6);
      expect(concatenated).toEqual(new Uint8Array([1, 2, 3, ...random]));
    });
  });

  describe("base64UrlEncode and base64UrlDecode", () => {
    const vectors: string[] = [
      "",
      "f",
      "fo",
      "foo",
      "foob",
      "fooba",
      "foobar",
      "a Ā 𐀀 文 🦄",
      "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.",
    ];

    for (const input of vectors) {
      it(`should correctly encode and decode: "${input.slice(0, 10)}..."`, () => {
        const uint8Array = new TextEncoder().encode(input);

        const encoded = base64UrlEncode(uint8Array);
        expect(encoded).toBeTypeOf("string");
        const localEncoded = b64Encode(uint8Array);
        expect(encoded).toEqual(localEncoded);

        const decodedUint8Array = base64UrlDecode(encoded, false);
        expect(decodedUint8Array).toBeInstanceOf(Uint8Array);
        expect(decodedUint8Array).toEqual(b64Decode(localEncoded));

        const decodedString = base64UrlDecode(encoded);
        expect(decodedString).toBeTypeOf("string");
        expect(decodedString).toEqual(input);
      });
    }
  });

  describe("computeExpiresInSeconds", () => {
    it("should compute expiresIn correctly", () => {
      expect(computeExpiresInSeconds("1s")).toBe(1);
      expect(computeExpiresInSeconds("1m")).toBe(60);
      expect(computeExpiresInSeconds("1h")).toBe(3600);
      expect(computeExpiresInSeconds("1D")).toBe(86_400);
      expect(computeExpiresInSeconds("2D")).toBe(172_800);
      expect(computeExpiresInSeconds(10)).toBe(10);
    });

    it("should throw on invalid input", () => {
      // @ts-expect-error intentional invalid input
      expect(() => computeExpiresInSeconds("")).toThrow();
      // @ts-expect-error intentional invalid input
      expect(() => computeExpiresInSeconds("5x")).toThrow();
      expect(() => computeExpiresInSeconds(-10)).toThrow();
      expect(() => computeExpiresInSeconds(0)).toThrow();
      expect(() => computeExpiresInSeconds(Number.NaN)).toThrow();
    });
  });

  describe("base64Encode and base64Decode", () => {
    it("should correctly encode and decode binary data", () => {
      const data = new Uint8Array([0, 1, 2, 3, 255, 254]);
      const encoded = base64Encode(data);
      expect(encoded).toBeTypeOf("string");
      const decoded = base64Decode(encoded, false);
      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded).toEqual(data);
    });

    it("should return empty string/Uint8Array for undefined input", () => {
      expect(base64Decode(undefined)).toBe("");
      expect(base64Decode(undefined, false)).toEqual(new Uint8Array(0));
    });

    it("should encode/decode a string", () => {
      const str = "Hello, World!";
      const encoded = base64Encode(str);
      const decoded = base64Decode(encoded);
      expect(decoded).toBe(str);
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

      let claims = computeJwtTimeClaims({}, "JWT", "1m", date)!;
      expect(claims).toHaveProperty("iat");
      expect(claims.iat).toBe(now);
      expect(claims).toHaveProperty("exp");
      expect(claims.exp).toBe(now + 60);

      claims = computeJwtTimeClaims({ iat: 1000 }, "JWT", "1m", date)!;
      expect(claims).toHaveProperty("iat");
      expect(claims.iat).toBe(1000);
      expect(claims).toHaveProperty("exp");
      expect(claims.exp).toBe(1060);
    });

    it("should return undefined for invalid inputs", () => {
      const date = new Date(0); // epoch

      // no expiresIn
      let claims = computeJwtTimeClaims({}, "JWT", undefined, date);
      expect(claims).toBeUndefined();

      // `exp` already present
      claims = computeJwtTimeClaims({ exp: 2000 }, "JWT", "1m", date);
      expect(claims).toBeUndefined();

      // invalid `typ`
      claims = computeJwtTimeClaims({}, "invalid", "1m", date);
      expect(claims).toBeUndefined();
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

describe("sanitizeObject", () => {
  it("removes __proto__ own-property", () => {
    // JSON.parse creates an object with __proto__ as a plain own-property
    const obj = JSON.parse('{"__proto__": {"polluted": true}, "safe": 1}');
    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(obj, "__proto__")).toBe(false);
    expect((obj as any).safe).toBe(1);
  });

  it("removes prototype own-property", () => {
    const obj = JSON.parse('{"prototype": "danger", "ok": true}');
    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(obj, "prototype")).toBe(false);
  });

  it("removes constructor own-property", () => {
    const obj = JSON.parse('{"constructor": {"name": "pwned"}, "value": 42}');
    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(obj, "constructor")).toBe(false);
    expect((obj as any).value).toBe(42);
  });

  it("sanitizes nested dangerous objects (triggers seen WeakSet branch)", () => {
    const inner = JSON.parse('{"__proto__": "bad", "normal": "good"}');
    const outer: any = { nested: inner };
    sanitizeObject(outer);
    expect(Object.prototype.hasOwnProperty.call(inner, "__proto__")).toBe(false);
    expect(inner.normal).toBe("good");
  });

  it("handles non-object values (fast-path)", () => {
    expect(sanitizeObject(undefined as any)).toBeUndefined();
    expect(sanitizeObject(null as any)).toBeNull();
    expect(sanitizeObject("string" as any)).toBe("string");
  });

  it("skips already-seen nested objects (WeakSet seen.has() === true branch)", () => {
    const shared = { val: "ok" };
    const obj: any = { a: shared, b: shared }; // same object referenced twice
    sanitizeObject(obj);
    // No infinite loop and the shared object is untouched
    expect(obj.a).toBe(shared);
    expect(obj.b).toBe(shared);
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

describe("computeExpiresInSeconds additional cases", () => {
  it("throws when expiresIn is neither number nor string", () => {
    // @ts-expect-error intentional invalid type
    expect(() => computeExpiresInSeconds(true)).toThrow("'expiresIn' must be a number or a string");
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
    expect(
      () => validateJwtClaims({ iat: oldIat }, { maxTokenAge: 60 }), // max age 60s
    ).toThrow("Token is too old");
  });

  it("throws when maxTokenAge is set but iat is not a number", () => {
    // iat must be present (otherwise line 189 fires first); here it's a string
    expect(() =>
      // @ts-expect-error intentional non-number iat
      validateJwtClaims({ iat: "not-a-number" }, { maxTokenAge: 60 }),
    ).toThrow('"iat" (Issued At) Claim must be a number');
  });

  it("throws for subject mismatch", () => {
    expect(() =>
      validateJwtClaims({ sub: "actual-subject" }, { subject: "expected-subject" }),
    ).toThrow('"sub" (Subject) Claim');
  });
});

function b64Encode(data: Uint8Array<ArrayBuffer>): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function b64Decode(str: string): Uint8Array<ArrayBuffer> {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";

  const { buffer, byteLength, byteOffset } = Buffer.from(str, "base64");

  return new Uint8Array(buffer, byteOffset, byteLength);
}
