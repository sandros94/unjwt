import { describe, it, expect } from "vitest";
import { generateKey, exportKey, importKey } from "../src/jwk";
import { base64UrlEncode, randomBytes } from "../src/utils";

describe("JWK Utilities", () => {
  describe("generateKey", () => {
    it("should generate an HMAC key", async () => {
      const cryptoKey = await generateKey("HS256");

      expect(cryptoKey).toBeInstanceOf(CryptoKey);
      expect(cryptoKey.algorithm).toStrictEqual({
        hash: {
          name: "SHA-256",
        },
        length: 512,
        name: "HMAC",
      });
      expect(cryptoKey.extractable).toBe(true);
      expect(cryptoKey.type).toBe("secret");
      expect(cryptoKey.usages).toEqual(["sign", "verify"]);
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
      const cryptoKey = await generateKey("HS256");
      const exportedKey = await exportKey(cryptoKey);

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

  describe("importKey", () => {
    it("should import an HMAC key", async () => {
      const key = {
        kty: "oct",
        k: base64UrlEncode(randomBytes(64)),
        alg: "HS256",
        ext: true,
      } as JsonWebKey;

      const cryptoKey = await importKey(key);
      expect(cryptoKey).toBeInstanceOf(CryptoKey);
      expect(cryptoKey.algorithm).toStrictEqual({
        hash: {
          name: "SHA-256",
        },
        length: 512,
        name: "HMAC",
      });
      expect(cryptoKey.extractable).toBe(true);
      expect(cryptoKey.type).toBe("secret");
      expect(cryptoKey.usages).toEqual(["sign", "verify"]);
    });
  });
});
