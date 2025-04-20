import { describe, it, expect } from "vitest";
import {
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
  concatUint8Arrays,
  textEncoder,
  textDecoder,
} from "../src/utils";

describe("Utility Functions", () => {
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

        const decoded = base64UrlDecode(encoded);
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(b64Decode(localEncoded));
      });
    }
  });
});

function b64Encode(data: Uint8Array): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function b64Decode(str: string): Uint8Array {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";

  const { buffer, byteLength, byteOffset } = Buffer.from(str, "base64");

  return new Uint8Array(buffer, byteOffset, byteLength);
}
