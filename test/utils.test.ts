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
    it("should encode correctly", () => {
      const uint8Array = new TextEncoder().encode("hello world");
      const encoded = base64UrlEncode(uint8Array);

      expect(encoded).toBeTypeOf("string");
      expect(encoded).toEqual(b64Encode(uint8Array));
    });

    it("should decode correctly", () => {
      const encoded = "aGVsbG8gd29ybGQ";
      const decoded = base64UrlDecode(encoded);

      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded).toEqual(b64Decode(encoded));
    });

    it("should support empty strings", () => {
      const decoded = base64UrlDecode("");

      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded.length).toBe(0);
    });

    it("should handle non-UTF-8 characters", () => {
      const str = "hello \uD83D\uDE00";
      const uint8Array = textEncoder.encode(str);
      const encoded = base64UrlEncode(uint8Array);
      const decoded = base64UrlDecode(encoded);

      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded.length).toBe(uint8Array.length);
      expect(decoded).toEqual(uint8Array);
    });
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
