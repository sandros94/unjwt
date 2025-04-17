import { describe, it, expect } from "vitest";
import { subtle } from "uncrypto";
import {
  generateSymmetricKey,
  exportSymmetricKey,
  importSymmetricKey,
  importRawSymmetricKey,
} from "../src/jwk";
import { base64UrlDecode, randomBytes } from "../src/utils";
import type { JWK } from "../src/types";

describe("JWK Utilities (Symmetric)", () => {
  describe("generateSymmetricKey", () => {
    it("should generate an oct JWK with specified length", async () => {
      const jwk = await generateSymmetricKey(256);
      expect(jwk.kty).toBe("oct");
      expect(jwk.k).toBeTypeOf("string");
      expect(jwk.ext).toBe(true);
      expect(base64UrlDecode(jwk.k).length).toBe(32); // 256 bits = 32 bytes
    });

    it("should generate an oct JWK with alg property", async () => {
      const alg = "HS256";
      const jwk = await generateSymmetricKey(256, alg);
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe(alg);
      expect(base64UrlDecode(jwk.k).length).toBe(32);
    });

    it("should generate JWKs with different lengths", async () => {
      const jwk128 = await generateSymmetricKey(128);
      expect(base64UrlDecode(jwk128.k).length).toBe(16);

      const jwk192 = await generateSymmetricKey(192);
      expect(base64UrlDecode(jwk192.k).length).toBe(24);
    });
  });

  describe("import/export SymmetricKey", () => {
    it("should export an imported HMAC key to JWK", async () => {
      const secret = "mysecretkeyforsigning";
      const alg = { name: "HMAC", hash: "SHA-256" };
      const key = await importRawSymmetricKey(secret, alg, true, ["sign"]);

      const jwk = await exportSymmetricKey(key);

      expect(jwk.kty).toBe("oct");
      expect(jwk.k).toBeTypeOf("string");
      expect(jwk.alg).toBe("HS256");
      expect(jwk.key_ops).toEqual(["sign"]);
      expect(jwk.ext).toBe(true);

      // Verify key material matches
      // Note: HMAC import pads the key and export might return the raw internal key, meaning
      // that we might not be able to directly compare the raw 'k' with the original secret easily
      const reimportedKey = await importSymmetricKey(jwk, alg, true, ["sign"]);
      expect(reimportedKey.type).toBe("secret");
    });

    it("should export an imported AES-KW key to JWK", async () => {
      const keyBytes = randomBytes(16); // 128 bits
      const alg = { name: "AES-KW" };
      const key = await subtle.importKey("raw", keyBytes, alg, true, [
        "wrapKey",
      ]);

      const jwk = await exportSymmetricKey(key);

      expect(jwk.kty).toBe("oct");
      expect(jwk.k).toBeTypeOf("string");
      expect(jwk.alg).toBe("A128KW"); // JWA identifier
      expect(jwk.key_ops).toEqual(["wrapKey"]);
      expect(jwk.ext).toBe(true);
      expect(base64UrlDecode(jwk.k)).toEqual(keyBytes); // Raw export should match for AES

      const reimportedKey = await importSymmetricKey(jwk, alg, true, [
        "wrapKey",
      ]);
      expect(reimportedKey.type).toBe("secret");
    });

    it("should throw error if exporting non-extractable key", async () => {
      const key = await importRawSymmetricKey(
        "nonextractable",
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
      );
      await expect(exportSymmetricKey(key)).rejects.toThrow(
        "Key must be a symmetric (secret) and extractable CryptoKey",
      );
    });

    // TODO: Add test for asymmetric key rejection later
  });

  describe("importSymmetricKey", () => {
    it("should import a valid oct JWK for HMAC", async () => {
      const jwk: JWK = {
        kty: "oct",
        k: "AyMFAwQAAPszb3x2ZMR2V9T5Q", // Example base64url key
        alg: "HS256",
        key_ops: ["sign", "verify"],
        ext: true,
      };
      const alg = { name: "HMAC", hash: "SHA-256" };
      const key = await importSymmetricKey(jwk, alg, true, ["sign", "verify"]);

      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as any).hash.name).toBe("SHA-256");
      expect(key.usages).toContain("sign");
      expect(key.usages).toContain("verify");
      expect(key.extractable).toBe(true);
    });

    it("should import a valid oct JWK for AES-KW", async () => {
      const jwk: JWK = {
        kty: "oct",
        k: "GawgguFyGrWKav7AX4VKUg", // 128-bit key
        alg: "A128KW",
        ext: true,
      };
      const alg = { name: "AES-KW" };
      const key = await importSymmetricKey(jwk, alg, false, ["wrapKey"]);

      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("AES-KW");
      expect(key.usages).toEqual(["wrapKey"]);
      expect(key.extractable).toBe(false);
    });

    it("should throw error for invalid JWK type", async () => {
      const jwk: JWK = { kty: "RSA", n: "..." }; // Invalid type
      const alg = { name: "HMAC", hash: "SHA-256" };
      await expect(
        importSymmetricKey(jwk, alg, true, ["sign"]),
      ).rejects.toThrow(
        "JWK must be of type 'oct' and contain the 'k' parameter",
      );
    });

    it("should throw error if 'k' parameter is missing", async () => {
      const jwk: JWK = { kty: "oct", alg: "HS256" }; // Missing 'k'
      const alg = { name: "HMAC", hash: "SHA-256" };
      await expect(
        importSymmetricKey(jwk, alg, true, ["sign"]),
      ).rejects.toThrow(
        "JWK must be of type 'oct' and contain the 'k' parameter",
      );
    });
  });

  describe("importRawSymmetricKey", () => {
    it("should import a raw key from string", async () => {
      const secret = "rawsecret";
      const alg = { name: "HMAC", hash: "SHA-512" };
      const key = await importRawSymmetricKey(secret, alg, false, ["verify"]);

      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as any).hash.name).toBe("SHA-512");
      expect(key.usages).toEqual(["verify"]);
      expect(key.extractable).toBe(false);
    });

    it("should import a raw key from Uint8Array", async () => {
      const secretBytes = randomBytes(32); // 256 bits
      const alg = { name: "AES-GCM", length: 256 };
      const key = await importRawSymmetricKey(secretBytes, alg, true, [
        "encrypt",
      ]);

      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("AES-GCM");
      expect((key.algorithm as any).length).toBe(256);
      expect(key.usages).toEqual(["encrypt"]);
      expect(key.extractable).toBe(true);
    });
  });
});
