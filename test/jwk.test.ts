import { describe, it, expect } from "vitest";
import { generateKey, exportKey, importKey } from "../src/jwk";
import { base64UrlEncode, randomBytes, deriveKeyBitsFromPassword } from "../src/utils";

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
      const jwk = await exportKey(await generateKey("HS256"));

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
      const cryptoKey = await importKey({
        kty: "oct",
        k: base64UrlEncode(randomBytes(64)), // 512 bits
        alg: "HS256",
        ext: true,
        key_ops: ["sign", "verify"],
      });

      checkCryptoKey(cryptoKey, "HMAC", "secret", ["sign", "verify"]);
      expect((cryptoKey.algorithm as HmacKeyAlgorithm).hash.name).toBe(
        "SHA-256",
      );
    });

    it("should import AES-CBC part of A128CBC-HS256 key", async () => {
      const cryptoKey = await importKey({
        alg: "A128CBC-HS256",
        ext: true,
        k: base64UrlEncode(randomBytes(16)), // 128 bits
        key_ops: ["encrypt", "decrypt"],
        kty: "oct",
      });

      checkCryptoKey(cryptoKey, "AES-CBC", "secret", ["encrypt", "decrypt"]);
      expect((cryptoKey.algorithm as AesKeyAlgorithm).length).toBe(128);
    });

    // --- Importing Raw Key Bits ---
    it("should import raw key bits for HS256", async () => {
      const derivedBits = new Uint8Array(32).buffer; // Example 256 bits for HS256
      const cryptoKey = await importKey(derivedBits, {
        alg: "HS256",
        keyUsages: ["sign", "verify"],
      });

      expect(cryptoKey).toBeInstanceOf(CryptoKey);
      expect(cryptoKey.algorithm.name).toBe("HMAC");
      expect(cryptoKey.type).toBe("secret");
      expect(cryptoKey.usages).toEqual(expect.arrayContaining(["sign", "verify"]));
    });

    it("should import a raw key bits which successfully encrypt and decrypt", async () => {
      const password = "password123";
      const { derivedBits } = await deriveKeyBitsFromPassword(password, {
        keyLength: 128,
        iterations: 16, // 16 iterations for testing
      });

      const cryptoKey = await importKey(derivedBits, {
        alg: "A128GCM",
        keyUsages: ["encrypt", "decrypt"],
      });

      const data = "Hello, World!";
      const iv = randomBytes(12);
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv,
          tagLength: 128,
        },
        cryptoKey,
        new TextEncoder().encode(data),
      );
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv,
          tagLength: 128,
        },
        cryptoKey,
        encryptedData,
      );

      expect(encryptedData).toBeInstanceOf(ArrayBuffer);
      expect(new TextDecoder().decode(decryptedData)).toBe(data);
    });

    // --- Fallback Logic ---
    it("should infer keyUsages from jwk.use='sig' (HMAC)", async () => {
      const cryptoKey = await importKey({
        kty: "oct",
        k: base64UrlEncode(randomBytes(32)), // 256 bits
        alg: "HS256",
        use: "sig",
        ext: true,
      });

      checkCryptoKey(cryptoKey, "HMAC", "secret", ["sign", "verify"]); // Default for HMAC includes both
    });

    it("should infer keyUsages from jwk.use='sig' (RSA)", async () => {
      const { publicKey, privateKey } = await generateKey("RS256");
      const [exportPublic, exportPrivate] = await Promise.all([
        exportKey(publicKey, { use: "sig" }),
        exportKey(privateKey, { use: "sig" }),
      ]);
      delete exportPublic.key_ops;
      delete exportPrivate.key_ops;

      const [cryptoKeyPublic, cryptoKeyPrivate] = await Promise.all([
        importKey(exportPublic),
        importKey(exportPrivate),
      ]);

      checkCryptoKey(cryptoKeyPublic, "RSASSA-PKCS1-v1_5", "public", [
        "verify",
      ]);
      checkCryptoKey(cryptoKeyPrivate, "RSASSA-PKCS1-v1_5", "private", [
        "sign",
      ]);
    });

    it("should infer keyUsages from jwk.use='enc' (AES-KW)", async () => {
      const cryptoKey = await importKey({
        alg: "A128KW",
        ext: true,
        k: base64UrlEncode(randomBytes(16)), // 128 bits
        kty: "oct",
        use: "enc",
      });

      checkCryptoKey(cryptoKey, "AES-KW", "secret", ["wrapKey", "unwrapKey"]);
    });

    it("should infer keyUsages from jwk.use='enc' (AES-GCM)", async () => {
      const cryptoKey = await importKey({
        alg: "A128GCM",
        ext: true,
        k: base64UrlEncode(randomBytes(16)), // 128 bits
        kty: "oct",
        use: "enc",
      });

      checkCryptoKey(cryptoKey, "AES-GCM", "secret", ["encrypt", "decrypt"]);
    });

    it("should infer keyUsages from jwk.use='enc' (RSA-OAEP)", async () => {
      const { publicKey, privateKey } = await generateKey("RSA-OAEP");
      const [exportPublic, exportPrivate] = await Promise.all([
        exportKey(publicKey, { use: "enc" }),
        exportKey(privateKey, { use: "enc" }),
      ]);
      delete exportPublic.key_ops;
      delete exportPrivate.key_ops;

      const [cryptoKeyPublic, cryptoKeyPrivate] = await Promise.all([
        importKey(exportPublic),
        importKey(exportPrivate),
      ]);

      checkCryptoKey(cryptoKeyPublic, "RSA-OAEP", "public", [
        "wrapKey",
        "encrypt",
      ]);
      checkCryptoKey(cryptoKeyPrivate, "RSA-OAEP", "private", [
        "unwrapKey",
        "decrypt",
      ]);
    });

    it("should use default usages if jwk.use is irrelevant", async () => {
      const cryptoKey = await importKey({
        kty: "oct",
        k: base64UrlEncode(randomBytes(32)),
        alg: "HS256",
        use: "enc", // Incorrect use for HMAC
        ext: true,
      });

      // Falls back to default 'sign', 'verify' for HS256
      checkCryptoKey(cryptoKey, "HMAC", "secret", ["sign", "verify"]);
    });

    // --- Error Handling ---
    it("should throw if alg is missing and cannot be inferred", async () => {
      await expect(importKey({})).rejects.toThrow(
        "Algorithm ('alg') must be present in JWK or options.",
      );
    });

    it("should throw for unsupported algorithm", async () => {
      await expect(importKey({
        kty: "oct",
        k: base64UrlEncode(randomBytes(64)),
        alg: "unsupported",
      })).rejects.toThrow(
        "Unsupported or unknown algorithm for key import: unsupported",
      );
    });

    it("should throw if alg is missing in JWK and options (oct)", async () => {
      await expect(importKey({
        kty: "oct",
        k: base64UrlEncode(randomBytes(64)),
      })).rejects.toThrow(
        "Algorithm ('alg') missing in JWK and options, cannot infer for 'oct' key type.",
      );
    });

    it("should throw if alg is missing in JWK and options (RSA)", async () => {
      await expect(importKey({
        kty: "RSA",
        n: "n",
        e: "AQAB",
      })).rejects.toThrow(
        "Algorithm ('alg') missing in JWK and options, cannot infer specific RSA algorithm.",
      );
    });

    it("should throw for AES-KW import if kty is not 'oct'", async () => {
      await expect(importKey({
        kty: "RSA", // Incorrect kty
        k: base64UrlEncode(randomBytes(16)),
        alg: "A128KW",
        ext: true,
        key_ops: ["wrapKey", "unwrapKey"],
      })).rejects.toThrow(
        "JWK with alg 'A128KW' must have kty 'oct'.",
      );
    });

    it("should throw for AES-GCM import if kty is not 'oct'", async () => {
      await expect(importKey({
        kty: "RSA", // Incorrect kty
        k: base64UrlEncode(randomBytes(16)),
        alg: "A128GCM",
        ext: true,
        key_ops: ["encrypt", "decrypt"],
      })).rejects.toThrow(
        "JWK with alg 'A128GCM' must have kty 'oct'.",
      );
    });
  });
});
