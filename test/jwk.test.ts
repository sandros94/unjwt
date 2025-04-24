import { describe, it, expect } from "vitest";
import { generateKey, exportKey, importKey } from "../src/jwk";
import { base64UrlEncode, base64UrlDecode, randomBytes } from "../src/utils";
import type { JWK } from "../src/types";

describe("JWK Utilities", () => {
  describe("generateKey (Symmetric)", () => {
    it("should generate an oct JWK with specified length", async () => {
      const jwk = await generateKey("oct", 256);
      expect(jwk.kty).toBe("oct");
      expect(jwk.k).toBeTypeOf("string");
      expect(jwk.ext).toBe(true);
      expect(base64UrlDecode(jwk.k).length).toBe(32);
    });

    it("should generate an oct JWK with alg property", async () => {
      const alg = "HS256";
      const jwk = await generateKey("oct", 256, { alg });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe(alg);
      expect(base64UrlDecode(jwk.k).length).toBe(32);
    });

    it("should generate JWKs with different lengths", async () => {
      const jwk128 = await generateKey("oct", 128);
      expect(base64UrlDecode(jwk128.k).length).toBe(16);

      const jwk192 = await generateKey("oct", 192);
      expect(base64UrlDecode(jwk192.k).length).toBe(24);

      const jwk512 = await generateKey("oct", 512);
      expect(base64UrlDecode(jwk512.k).length).toBe(64);
    });

    it("should throw error for invalid length option", async () => {
      // @ts-expect-error - Testing invalid length
      await expect(generateKey("oct", "1")).rejects.toThrow(
        "Invalid options for 'oct' key generation. 'length' (128, 192, 256, or 512) is required.",
      );
      await expect(
        // @ts-expect-error - Testing invalid length
        generateKey("oct", 1),
      ).rejects.toThrow(
        "Invalid options for 'oct' key generation. 'length' (128, 192, 256, or 512) is required.",
      );
    });

    it("should throw error for unsupported key type", async () => {
      await expect(
        // @ts-expect-error - Testing invalid type
        generateKey("unsupported", 256),
      ).rejects.toThrow("Unsupported key type for generation: unsupported");
    });
  });

  describe("exportKey (Symmetric)", () => {
    it("should export an imported HMAC key to JWK (likely uses fallback)", async () => {
      const secret = "mysecretkeyforsigning";
      const alg = { name: "HMAC", hash: "SHA-256" };
      const key = await importKey(secret, alg, true, ["sign"]);

      const jwk = await exportKey(key);

      expect(jwk.kty).toBe("oct");
      expect(jwk.k).toBeTypeOf("string");
      // Fallback path correctly infers HS256 from HMAC SHA-256
      expect(jwk.alg).toBe("HS256");
      expect(jwk.key_ops).toEqual(["sign"]);
      expect(jwk.ext).toBe(true);

      // Re-import the exported JWK
      const reimportedKey = await importKey(jwk, alg, true, ["sign"]);
      expect(reimportedKey.type).toBe("secret");
      expect(reimportedKey.algorithm.name).toBe("HMAC");
    });

    it("should export an imported AES-KW key to JWK (likely uses subtle.exportKey('jwk'))", async () => {
      const keyBytes = randomBytes(16); // 128 bits
      const alg = { name: "AES-KW" };
      const key = await importKey(keyBytes, alg, true, ["wrapKey"]);

      const jwk = await exportKey(key);

      expect(jwk.kty).toBe("oct");
      expect(jwk.k).toBeTypeOf("string");
      expect(jwk.alg).toBe("A128KW"); // JWA identifier
      expect(jwk.key_ops).toEqual(["wrapKey"]);
      expect(jwk.ext).toBe(true);
      // Verify key material by re-importing and exporting raw
      const reimportedKey = await importKey(jwk, alg, true, ["wrapKey"]);
      const rawExported = await crypto.subtle.exportKey("raw", reimportedKey);
      expect(new Uint8Array(rawExported)).toEqual(keyBytes);
    });

    it("should export an imported AES-GCM key to JWK, inferring alg if needed", async () => {
      const keyBytes = randomBytes(32); // 256 bits
      const alg = { name: "AES-GCM" };
      const key = await importKey(keyBytes, alg, true, ["encrypt"]);

      const jwk = await exportKey(key);

      expect(jwk.kty).toBe("oct");
      expect(jwk.k).toBeTypeOf("string");
      expect(jwk.alg).toMatch(/A256GCM|AES-GCM/); // Allow either standard or generic name
      expect(jwk.key_ops).toEqual(["encrypt"]);
      expect(jwk.ext).toBe(true);

      // Verify key material
      const reimportedKey = await importKey(jwk, alg, true, ["encrypt"]);
      const rawExported = await crypto.subtle.exportKey("raw", reimportedKey);
      expect(new Uint8Array(rawExported)).toEqual(keyBytes);
    });

    it("should throw error if exporting non-extractable key", async () => {
      const key = await importKey(
        "nonextractable",
        { name: "HMAC", hash: "SHA-256" },
        false, // Not extractable
        ["verify"],
      );
      await expect(exportKey(key)).rejects.toThrow(
        "Key must be extractable to export to JWK format.",
      );
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
