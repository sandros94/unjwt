import { describe, it, expect } from "vitest";
import {
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
  concatUint8Arrays,
  textEncoder,
  textDecoder,
  computeExpiresInSeconds,
  computeJwtTimeClaims,
} from "../src/core/utils";

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
      const uint8Array = new Uint8Array([
        104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100,
      ]);
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
