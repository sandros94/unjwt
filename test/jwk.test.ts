import { describe, it, expect } from "vitest";
import { generateKey, exportKey, importKey } from "../src/jwk";
import { base64UrlEncode, randomBytes } from "../src/utils";
import type { JWK } from "../src/types";

describe("JWK Utilities", () => {
  describe("generateKey", () => {
    it("should generate an HMAC key", async () => {
      const crypto = await generateKey("HS256");
      expect(crypto).toBeInstanceOf(CryptoKey);
      expect(crypto.algorithm).toStrictEqual({
        hash: {
          name: "SHA-256",
        },
        length: 512,
        name: "HMAC",
      });
      expect(crypto.extractable).toBe(true);
      expect(crypto.type).toBe("secret");
      expect(crypto.usages).toEqual(["sign", "verify"]);
    });

    it("should throw error for unsupported algorithm", async () => {
      await expect(
        // @ts-expect-error - Testing invalid type
        generateKey("unsupported"),
      ).rejects.toThrow(
        "Unsupported or unknown algorithm for key generation: unsupported",
      );
    });
  });

  describe("exportKey", () => {
    it("should export a generated HMAC key to JWK", async () => {
      const crypto = await generateKey("HS256");
      const exportedKey = await exportKey(crypto);

      expect(exportedKey).toHaveProperty("kty", "oct");
      expect(exportedKey).toHaveProperty("alg", "HS256");
      expect(exportedKey).toHaveProperty("ext", true);
    });

    it("should throw error for non-extractable key", async () => {
      await expect(
        exportKey(await generateKey("HS256", { extractable: false })),
      ).rejects.toThrow("Cannot export a non-extractable key.");
    });
  });

  describe("importKey (Symmetric)", () => {
    it("should import a valid oct JWK for HMAC", async () => {
      const rawKeyBytes = randomBytes(32); // Generate a 256-bit key
      const k = base64UrlEncode(rawKeyBytes);

      const jwk: JWK = {
        kty: "oct",
        k,
        alg: "HS256",
        key_ops: ["sign", "verify"],
        ext: true,
      };
      const alg = { name: "HMAC", hash: "SHA-256" };
      const key = await importKey(jwk, alg, true, ["sign", "verify"]);

      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as HmacKeyAlgorithm).hash.name).toBe("SHA-256");
      expect(key.usages).toContain("sign");
      expect(key.usages).toContain("verify");
      expect(key.extractable).toBe(true);

      const exportedRaw = await crypto.subtle.exportKey("raw", key);
      expect(new Uint8Array(exportedRaw)).toEqual(rawKeyBytes);
    });

    it("should import a valid oct JWK for AES-KW", async () => {
      const rawKeyBytes = randomBytes(16); // Generate a 128-bit key
      const k = base64UrlEncode(rawKeyBytes);

      const jwk: JWK = {
        kty: "oct",
        k,
        alg: "A128KW",
      };
      const alg = { name: "AES-KW" };
      const key = await importKey(jwk, alg, true, ["wrapKey", "unwrapKey"]);

      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("AES-KW");
      expect(key.usages).toContain("wrapKey");
      expect(key.usages).toContain("unwrapKey");
      expect(key.extractable).toBe(true);

      const exportedRaw = await crypto.subtle.exportKey("raw", key);
      expect(new Uint8Array(exportedRaw)).toEqual(rawKeyBytes);
    });

    it("should import a raw key from string for HMAC", async () => {
      const secret = "rawsecret";
      const alg = { name: "HMAC", hash: "SHA-512" };
      const key = await importKey(secret, alg, false, ["verify"]);

      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as HmacKeyAlgorithm).hash.name).toBe("SHA-512");
      expect(key.usages).toEqual(["verify"]);
      expect(key.extractable).toBe(false);
    });

    it("should import a raw key from Uint8Array for AES-GCM", async () => {
      const secretBytes = randomBytes(32); // 256 bits
      const alg = { name: "AES-GCM", length: 256 };
      const key = await importKey(secretBytes, alg, true, ["encrypt"]);

      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("AES-GCM");
      expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
      expect(key.usages).toEqual(["encrypt"]);
      expect(key.extractable).toBe(true);

      // Verify key material
      const exportedRaw = await crypto.subtle.exportKey("raw", key);
      expect(new Uint8Array(exportedRaw)).toEqual(secretBytes);
    });

    it("should throw error for invalid key format (non-JWK object)", async () => {
      const invalidKey = { some: "object" } as any; // Invalid format
      const alg = { name: "HMAC", hash: "SHA-256" };
      await expect(importKey(invalidKey, alg, true, ["sign"])).rejects.toThrow(
        "Invalid key format. Expected symmetric JWK (oct), Uint8Array, or string.",
      );
    });

    it("should throw error for non-oct JWK type", async () => {
      const jwk: JWK = { kty: "RSA", n: "..." }; // Invalid kty
      const alg = { name: "HMAC", hash: "SHA-256" };
      await expect(importKey(jwk, alg, true, ["sign"])).rejects.toThrow(
        "Invalid key format. Expected symmetric JWK (oct), Uint8Array, or string.",
      );
    });

    it("should throw error if JWK 'k' parameter is missing or not string", async () => {
      const jwkMissingK: JWK = { kty: "oct", alg: "HS256" }; // Missing 'k'
      // @ts-expect-error - Testing invalid k type
      const jwkBadK: JWK = { kty: "oct", k: 12_345 }; // Invalid 'k' type
      const alg = { name: "HMAC", hash: "SHA-256" };

      await expect(importKey(jwkMissingK, alg, true, ["sign"])).rejects.toThrow(
        "Symmetric JWK must contain the 'k' parameter as a string",
      );
      await expect(importKey(jwkBadK, alg, true, ["sign"])).rejects.toThrow(
        "Symmetric JWK must contain the 'k' parameter as a string",
      );
    });
  });
});
