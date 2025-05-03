import { describe, it, expect } from "vitest";
import { generateKey, exportKey, importKey } from "../src/jwk";
import { base64UrlEncode, randomBytes } from "../src/utils";
import type { JWK } from "../src/types/jwk"; // Import the JWK type

// Helper to check CryptoKey properties
const checkCryptoKey = (
  key: CryptoKey,
  expectedAlgName: string,
  expectedType: KeyType,
  expectedUsages: KeyUsage[],
  expectedExtractable = true,
) => {
  expect(key).toBeInstanceOf(CryptoKey);
  expect(key.algorithm.name).toBe(expectedAlgName);
  expect(key.type).toBe(expectedType);
  expect(key.usages).toEqual(expect.arrayContaining(expectedUsages));
  expect(key.usages.length).toBe(expectedUsages.length);
  expect(key.extractable).toBe(expectedExtractable);
};

describe("JWK Utilities", () => {
  describe("generateKey", () => {
    // --- Symmetric Keys ---
    it("should generate an HS256 key", async () => {
      const cryptoKey = await generateKey("HS256");
      checkCryptoKey(cryptoKey, "HMAC", "secret", ["sign", "verify"]);
      expect((cryptoKey.algorithm as HmacKeyAlgorithm).hash.name).toBe(
        "SHA-256",
      );
    });

    it("should generate an HS512 key", async () => {
      const cryptoKey = await generateKey("HS512");
      checkCryptoKey(cryptoKey, "HMAC", "secret", ["sign", "verify"]);
      expect((cryptoKey.algorithm as HmacKeyAlgorithm).hash.name).toBe(
        "SHA-512",
      );
    });

    it("should generate an A128GCM key", async () => {
      const cryptoKey = await generateKey("A128GCM");
      checkCryptoKey(cryptoKey, "AES-GCM", "secret", ["encrypt", "decrypt"]);
      expect((cryptoKey.algorithm as AesKeyAlgorithm).length).toBe(128);
    });

    it("should generate an A256GCM key", async () => {
      const cryptoKey = await generateKey("A256GCM");
      checkCryptoKey(cryptoKey, "AES-GCM", "secret", ["encrypt", "decrypt"]);
      expect((cryptoKey.algorithm as AesKeyAlgorithm).length).toBe(256);
    });

    it("should generate an AES-KW key via PBES2 alg", async () => {
      const cryptoKey = await generateKey("PBES2-HS256+A128KW");
      checkCryptoKey(cryptoKey, "AES-KW", "secret", ["wrapKey", "unwrapKey"]);
      expect((cryptoKey.algorithm as AesKeyAlgorithm).length).toBe(128);
    });

    // --- Asymmetric Keys ---
    it("should generate an RS256 key pair", async () => {
      const keyPair = await generateKey("RS256");
      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      checkCryptoKey(keyPair.publicKey, "RSASSA-PKCS1-v1_5", "public", [
        "verify",
      ]);
      checkCryptoKey(keyPair.privateKey, "RSASSA-PKCS1-v1_5", "private", [
        "sign",
      ]);
      expect(
        (keyPair.publicKey.algorithm as RsaHashedKeyAlgorithm).hash.name,
      ).toBe("SHA-256");
    });

    it("should generate an PS384 key pair", async () => {
      const keyPair = await generateKey("PS384");
      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      checkCryptoKey(keyPair.publicKey, "RSA-PSS", "public", ["verify"]);
      checkCryptoKey(keyPair.privateKey, "RSA-PSS", "private", ["sign"]);
      expect(
        (keyPair.publicKey.algorithm as RsaHashedKeyAlgorithm).hash.name,
      ).toBe("SHA-384");
    });

    it("should generate an RSA-OAEP-256 key pair", async () => {
      const keyPair = await generateKey("RSA-OAEP-256");
      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      checkCryptoKey(keyPair.publicKey, "RSA-OAEP", "public", [
        "wrapKey",
        "encrypt",
      ]);
      checkCryptoKey(keyPair.privateKey, "RSA-OAEP", "private", [
        "unwrapKey",
        "decrypt",
      ]);
      expect(
        (keyPair.publicKey.algorithm as RsaHashedKeyAlgorithm).hash.name,
      ).toBe("SHA-256");
    });

    // --- Composite Keys ---
    it("should generate an A128CBC-HS256 composite key", async () => {
      const compositeKey = await generateKey("A128CBC-HS256");
      expect(compositeKey).toHaveProperty("encryptionKey");
      expect(compositeKey).toHaveProperty("macKey");
      checkCryptoKey(compositeKey.encryptionKey, "AES-CBC", "secret", [
        "encrypt",
        "decrypt",
      ]);
      checkCryptoKey(compositeKey.macKey, "HMAC", "secret", ["sign", "verify"]);
      expect(
        (compositeKey.encryptionKey.algorithm as AesKeyAlgorithm).length,
      ).toBe(128);
      expect(
        (compositeKey.macKey.algorithm as HmacKeyAlgorithm).hash.name,
      ).toBe("SHA-256");
      expect((compositeKey.macKey.algorithm as HmacKeyAlgorithm).length).toBe(
        128,
      ); // Check derived length
    });

    it("should generate an A256CBC-HS512 composite key", async () => {
      const compositeKey = await generateKey("A256CBC-HS512");
      expect(compositeKey).toHaveProperty("encryptionKey");
      expect(compositeKey).toHaveProperty("macKey");
      checkCryptoKey(compositeKey.encryptionKey, "AES-CBC", "secret", [
        "encrypt",
        "decrypt",
      ]);
      checkCryptoKey(compositeKey.macKey, "HMAC", "secret", ["sign", "verify"]);
      expect(
        (compositeKey.encryptionKey.algorithm as AesKeyAlgorithm).length,
      ).toBe(256);
      expect(
        (compositeKey.macKey.algorithm as HmacKeyAlgorithm).hash.name,
      ).toBe("SHA-512");
      expect((compositeKey.macKey.algorithm as HmacKeyAlgorithm).length).toBe(
        256,
      );
    });

    // --- Options ---
    it("should generate non-extractable key", async () => {
      const cryptoKey = await generateKey("HS256", { extractable: false });
      checkCryptoKey(cryptoKey, "HMAC", "secret", ["sign", "verify"], false);
    });

    it("should generate RSA key with specific modulusLength", async () => {
      const keyPair = await generateKey("RS256", { modulusLength: 3072 });
      expect(
        (keyPair.privateKey.algorithm as RsaHashedKeyAlgorithm).modulusLength,
      ).toBe(3072);
    });

    it("should generate key with specific usages", async () => {
      const cryptoKey = await generateKey("HS256", { keyUsage: ["sign"] });
      checkCryptoKey(cryptoKey, "HMAC", "secret", ["sign"]);
    });

    // --- Error Handling ---
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
    // --- Basic Exports ---
    it("should export HS256 key", async () => {
      const cryptoKey = await generateKey("HS256");
      const jwk = await exportKey(cryptoKey);
      expect(jwk).toEqual(
        expect.objectContaining({
          kty: "oct",
          alg: "HS256",
          ext: true,
          key_ops: ["sign", "verify"],
        }),
      );
      expect(jwk).toHaveProperty("k");
    });

    // --- Error Handling ---
    it("should throw error for non-extractable key", async () => {
      const cryptoKey = await generateKey("HS256", { extractable: false });
      await expect(exportKey(cryptoKey)).rejects.toThrow(
        "Cannot export a non-extractable key.",
      );
    });
  });

  describe("importKey", () => {
    // --- Basic Imports ---
    it("should import an HS256 key", async () => {
      const jwk: JWK = {
        kty: "oct",
        k: base64UrlEncode(randomBytes(64)), // 512 bits
        alg: "HS256",
        ext: true,
        key_ops: ["sign", "verify"],
      };
      const cryptoKey = await importKey(jwk);
      checkCryptoKey(cryptoKey, "HMAC", "secret", ["sign", "verify"]);
      expect((cryptoKey.algorithm as HmacKeyAlgorithm).hash.name).toBe(
        "SHA-256",
      );
    });

    it("should import an RS256 keys", async () => {
      // Generate a real key pair to get valid n, e values
      const { publicKey, privateKey } = await generateKey("RS256");
      const [exportedPublic, exportedPrivate] = await Promise.all([
        exportKey(publicKey),
        exportKey(privateKey),
      ]);
      const [cryptoKeyPublic, cryptoKeyPrivate] = await Promise.all([
        importKey(exportedPublic),
        importKey(exportedPrivate),
      ]);

      checkCryptoKey(cryptoKeyPublic, "RSASSA-PKCS1-v1_5", "public", [
        "verify",
      ]);
      expect(
        (cryptoKeyPublic.algorithm as RsaHashedKeyAlgorithm).hash.name,
      ).toBe("SHA-256");
      checkCryptoKey(cryptoKeyPrivate, "RSASSA-PKCS1-v1_5", "private", [
        "sign",
      ]);
      expect(
        (cryptoKeyPrivate.algorithm as RsaHashedKeyAlgorithm).hash.name,
      ).toBe("SHA-256");
    });

    // --- Fallback Logic ---
    it("should use alg from options if missing in JWK", async () => {
      const jwk: JWK = {
        kty: "oct",
        k: base64UrlEncode(randomBytes(64)),
        ext: true,
        key_ops: ["sign", "verify"],
      };
      const cryptoKey = await importKey(jwk, { alg: "HS384" });
      checkCryptoKey(cryptoKey, "HMAC", "secret", ["sign", "verify"]);
      expect((cryptoKey.algorithm as HmacKeyAlgorithm).hash.name).toBe(
        "SHA-384",
      );
    });

    // --- Error Handling ---
    it("should throw if alg is missing in JWK and options", async () => {
      const jwk: JWK = {
        kty: "oct",
        k: base64UrlEncode(randomBytes(64)),
      };
      await expect(importKey(jwk)).rejects.toThrow(
        "Algorithm ('alg') missing in JWK and options",
      );
    });

    it("should throw for RSA key with missing alg", async () => {
      const jwk: JWK = {
        kty: "RSA",
        n: "n",
        e: "AQAB",
      };
      await expect(importKey(jwk)).rejects.toThrow(
        "Algorithm ('alg') missing in JWK and options",
      );
    });

    it("should throw for missing alg", async () => {
      await expect(importKey({})).rejects.toThrow(
        "Algorithm ('alg') must be present in JWK or options",
      );
    });

    it("should throw for missing kty in AES-KW", async () => {
      const _cryptoKey = await generateKey("A128KW");
      const { kty: _, ...exportedKey } = await exportKey(_cryptoKey);

      await expect(importKey(exportedKey)).rejects.toThrow(
        "JWK with alg 'A128KW' must have kty 'oct'.",
      );
    });
  });
});
