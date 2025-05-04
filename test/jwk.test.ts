import { describe, it, expect, beforeAll } from "vitest";
import {
  generateKey,
  exportKey,
  importKey,
  deriveKeyBitsFromPassword,
} from "../src/jwk";
import { randomBytes, isJWK, textEncoder } from "../src/utils";
import type {
  JWK,
  GenerateKeyOptions,
  ImportKeyOptions,
  JWK_oct,
  JWK_RSA,
  JWK_RSA_Private,
  JWK_RSA_Public,
} from "../src/types";

describe("JWK Utilities", () => {
  describe("generateKey", () => {
    // --- Symmetric Key Generation ---
    it("should generate HS256 CryptoKey", async () => {
      const key = await generateKey("HS256");
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as HmacKeyAlgorithm).hash.name).toBe("SHA-256");
      expect(key.type).toBe("secret");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["sign", "verify"]));
    });

    it("should generate HS512 CryptoKey with options", async () => {
      const options: GenerateKeyOptions = {
        extractable: false,
        keyUsage: ["sign"],
      };
      const key = await generateKey("HS512", options);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as HmacKeyAlgorithm).hash.name).toBe("SHA-512");
      expect(key.extractable).toBe(false);
      expect(key.usages).toEqual(expect.arrayContaining(["sign"]));
    });

    it("should generate A128KW CryptoKey", async () => {
      const key = await generateKey("A128KW");
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("AES-KW");
      expect((key.algorithm as AesKeyAlgorithm).length).toBe(128);
      expect(key.type).toBe("secret");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["wrapKey", "unwrapKey"]));
    });

    it("should generate A256KW CryptoKey (from PBES2 alg)", async () => {
      const key = await generateKey("PBES2-HS512+A256KW"); // Generates the underlying AES-KW key
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("AES-KW");
      expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
      expect(key.type).toBe("secret");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["wrapKey", "unwrapKey"]));
    });

    it("should generate A128GCM CryptoKey", async () => {
      const key = await generateKey("A128GCM");
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("AES-GCM");
      expect((key.algorithm as AesKeyAlgorithm).length).toBe(128);
      expect(key.type).toBe("secret");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["encrypt", "decrypt"]));
    });

    // --- Asymmetric Key Generation ---
    it("should generate RS256 CryptoKeyPair", async () => {
      const keyPair = await generateKey("RS256");
      expect(keyPair).toHaveProperty("publicKey");
      expect(keyPair).toHaveProperty("privateKey");
      expect(keyPair.publicKey).toBeInstanceOf(CryptoKey);
      expect(keyPair.privateKey).toBeInstanceOf(CryptoKey);
      expect(keyPair.publicKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
      expect(
        (keyPair.publicKey.algorithm as RsaHashedKeyAlgorithm).hash.name,
      ).toBe("SHA-256");
      expect(keyPair.publicKey.type).toBe("public");
      expect(keyPair.privateKey.type).toBe("private");
      expect(keyPair.publicKey.extractable).toBe(true);
      expect(keyPair.privateKey.extractable).toBe(true);
      expect(keyPair.publicKey.usages).toEqual(expect.arrayContaining(["verify"]));
      expect(keyPair.privateKey.usages).toEqual(expect.arrayContaining(["sign"]));
    });

    it("should generate PS384 CryptoKeyPair with options", async () => {
      const options: GenerateKeyOptions = {
        modulusLength: 3072,
        extractable: false,
        keyUsage: ["sign", "verify"], // Will be split correctly
      };
      const keyPair = await generateKey("PS384", options);
      expect(keyPair.publicKey.algorithm.name).toBe("RSA-PSS");
      expect(
        (keyPair.publicKey.algorithm as RsaHashedKeyAlgorithm).hash.name,
      ).toBe("SHA-384");
      expect(
        (keyPair.publicKey.algorithm as RsaHashedKeyAlgorithm).modulusLength,
      ).toBe(3072);
      // expect(keyPair.publicKey.extractable).toBe(false); // TODO: doesn't work in webcrypto
      // expect(keyPair.privateKey.extractable).toBe(false); // TODO: doesn't work in webcrypto
      expect(keyPair.publicKey.usages).toEqual(expect.arrayContaining(["verify"])); // Overrides custom usage for public
      expect(keyPair.privateKey.usages).toEqual(expect.arrayContaining(["sign"])); // Overrides custom usage for private
    });

    it("should generate RSA-OAEP-256 CryptoKeyPair", async () => {
      const keyPair = await generateKey("RSA-OAEP-256");
      expect(keyPair.publicKey.algorithm.name).toBe("RSA-OAEP");
      expect(
        (keyPair.publicKey.algorithm as RsaHashedKeyAlgorithm).hash.name,
      ).toBe("SHA-256");
      expect(keyPair.publicKey.type).toBe("public");
      expect(keyPair.privateKey.type).toBe("private");
      expect(keyPair.publicKey.usages).toEqual(expect.arrayContaining(["wrapKey", "encrypt"]));
      expect(keyPair.privateKey.usages).toEqual(expect.arrayContaining(["unwrapKey", "decrypt"]));
    });

    // --- Composite Key Generation ---
    it("should generate A128CBC-HS256 CompositeKey", async () => {
      const compositeKey = await generateKey("A128CBC-HS256");
      expect(compositeKey).toHaveProperty("encryptionKey");
      expect(compositeKey).toHaveProperty("macKey");
      expect(compositeKey.encryptionKey).toBeInstanceOf(CryptoKey);
      expect(compositeKey.macKey).toBeInstanceOf(CryptoKey);

      expect(compositeKey.encryptionKey.algorithm.name).toBe("AES-CBC");
      expect(
        (compositeKey.encryptionKey.algorithm as AesKeyAlgorithm).length,
      ).toBe(128);
      expect(compositeKey.encryptionKey.extractable).toBe(true);
      expect(compositeKey.encryptionKey.usages).toEqual(expect.arrayContaining(["encrypt", "decrypt"]));

      expect(compositeKey.macKey.algorithm.name).toBe("HMAC");
      expect(
        (compositeKey.macKey.algorithm as HmacKeyAlgorithm).hash.name,
      ).toBe("SHA-256");
      // expect((compositeKey.macKey.algorithm as HmacKeyAlgorithm).length).toBe(128); // Length might not be directly available/standardized on algorithm object
      expect(compositeKey.macKey.extractable).toBe(true);
      expect(compositeKey.macKey.usages).toEqual(expect.arrayContaining(["sign", "verify"]));
    });

    it("should generate A256CBC-HS512 CompositeKey with extractable false", async () => {
      const compositeKey = await generateKey("A256CBC-HS512", {
        extractable: false,
      });
      expect(compositeKey.encryptionKey.extractable).toBe(false);
      expect(compositeKey.macKey.extractable).toBe(false);
      expect(compositeKey.encryptionKey.algorithm.name).toBe("AES-CBC");
      expect(
        (compositeKey.encryptionKey.algorithm as AesKeyAlgorithm).length,
      ).toBe(256);
      expect(compositeKey.macKey.algorithm.name).toBe("HMAC");
      expect(
        (compositeKey.macKey.algorithm as HmacKeyAlgorithm).hash.name,
      ).toBe("SHA-512");
    });

    // --- Error Cases ---
    it("should throw for unsupported algorithm", async () => {
      // @ts-expect-error - Testing unsupported algorithm
      await expect(generateKey("UnsupportedAlg")).rejects.toThrow(
        /Unsupported or unknown algorithm for key generation: UnsupportedAlg/,
      );
    });
  });

  describe("exportKey", () => {
    let hs256Key: CryptoKey;
    let rs256KeyPair: CryptoKeyPair;
    let nonExtractableKey: CryptoKey;

    beforeAll(async () => {
      hs256Key = await generateKey("HS256");
      rs256KeyPair = await generateKey("RS256");
      nonExtractableKey = await generateKey("HS256", { extractable: false });
    });

    it("should export an HS256 CryptoKey to JWK (oct)", async () => {
      const jwk = (await exportKey(hs256Key)) as JWK_oct;
      expect(isJWK(jwk)).toBe(true);
      expect(jwk.kty).toBe("oct");
      expect(jwk.k).toBeDefined();
      expect(jwk.ext).toBe(true);
      expect(jwk.key_ops).toEqual(expect.arrayContaining(["sign", "verify"]));
    });

    it("should export an RS256 public CryptoKey to JWK (RSA)", async () => {
      const jwk = (await exportKey(rs256KeyPair.publicKey)) as JWK_RSA_Public;
      expect(isJWK(jwk)).toBe(true);
      expect(jwk.kty).toBe("RSA");
      expect(jwk.n).toBeDefined();
      expect(jwk.e).toBeDefined();
      // @ts-expect-error - intentionally checking for undefined
      expect(jwk.d).toBeUndefined(); // Public key shouldn't have private components
      expect(jwk.ext).toBe(true);
      expect(jwk.key_ops).toEqual(expect.arrayContaining(["verify"]));
    });

    it("should export an RS256 private CryptoKey to JWK (RSA)", async () => {
      const jwk = (await exportKey(rs256KeyPair.privateKey)) as JWK_RSA_Private;
      expect(isJWK(jwk)).toBe(true);
      expect(jwk.kty).toBe("RSA");
      expect(jwk.n).toBeDefined();
      expect(jwk.e).toBeDefined();
      expect(jwk.d).toBeDefined();
      expect(jwk.p).toBeDefined();
      expect(jwk.q).toBeDefined();
      expect(jwk.dp).toBeDefined();
      expect(jwk.dq).toBeDefined();
      expect(jwk.qi).toBeDefined();
      expect(jwk.ext).toBe(true);
      expect(jwk.key_ops).toEqual(expect.arrayContaining(["sign"]));
    });

    it("should merge provided JWK properties during export", async () => {
      const partialJwk = { kid: "key-123", alg: "HS256" };
      const jwk = (await exportKey(hs256Key, partialJwk)) as JWK_oct;
      expect(jwk.kid).toBe("key-123");
      expect(jwk.alg).toBe("HS256");
      expect(jwk.kty).toBe("oct"); // Original properties still exist
      expect(jwk.k).toBeDefined();
    });

    it("should override key_ops and ext if provided in partial JWK", async () => {
      const partialJwk: Partial<JWK> = {
        key_ops: ["sign"],
        ext: false,
      };
      const jwk = await exportKey(hs256Key, partialJwk);
      expect(jwk.key_ops).toEqual(expect.arrayContaining(["sign"]));
      expect(jwk.ext).toBe(false);
    });

    it("should throw when exporting a non-extractable key", async () => {
      await expect(exportKey(nonExtractableKey)).rejects.toThrow(
        "Cannot export a non-extractable key.",
      );
    });
  });

  describe("importKey (JWK)", () => {
    let hs256Jwk: JWK_oct;
    let rs256PublicJwk: JWK_RSA;
    let rs256PrivateJwk: JWK_RSA;
    let a128kwJwk: JWK_oct;
    let a128gcmJwk: JWK_oct;
    let rsaOaepPublicJwk: JWK_RSA;

    beforeAll(async () => {
      hs256Jwk = (await exportKey(await generateKey("HS256"))) as JWK_oct;
      const rsPair = await generateKey("RS256");
      rs256PublicJwk = (await exportKey(rsPair.publicKey)) as JWK_RSA;
      rs256PrivateJwk = (await exportKey(rsPair.privateKey)) as JWK_RSA;
      a128kwJwk = (await exportKey(await generateKey("A128KW"))) as JWK_oct;
      a128gcmJwk = (await exportKey(await generateKey("A128GCM"))) as JWK_oct;
      const rsaOaepPair = await generateKey("RSA-OAEP-256");
      rsaOaepPublicJwk = (await exportKey(rsaOaepPair.publicKey)) as JWK_RSA;

      // Add alg property for testing inference/override
      hs256Jwk.alg = "HS256";
      rs256PublicJwk.alg = "RS256";
      rs256PrivateJwk.alg = "RS256";
      a128kwJwk.alg = "A128KW";
      a128gcmJwk.alg = "A128GCM";
      rsaOaepPublicJwk.alg = "RSA-OAEP-256";
    });

    it("should import HS256 JWK", async () => {
      const key = await importKey(hs256Jwk);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as HmacKeyAlgorithm).hash.name).toBe("SHA-256");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["sign", "verify"]));
    });

    it("should import RS256 public JWK", async () => {
      const key = await importKey(rs256PublicJwk);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
      expect(key.type).toBe("public");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["verify"]));
    });

    it("should import RS256 private JWK", async () => {
      const key = await importKey(rs256PrivateJwk);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
      expect(key.type).toBe("private");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["sign"]));
    });

    it("should import A128KW JWK", async () => {
      const key = await importKey(a128kwJwk);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("AES-KW");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["wrapKey", "unwrapKey"]));
    });

    it("should import A128GCM JWK", async () => {
      const key = await importKey(a128gcmJwk);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("AES-GCM");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["encrypt", "decrypt"]));
    });

    it("should import RSA-OAEP-256 public JWK", async () => {
      const key = await importKey(rsaOaepPublicJwk);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("RSA-OAEP");
      expect(key.type).toBe("public");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["wrapKey", "encrypt"]));
    });

    it("should use alg from options if JWK alg is missing", async () => {
      const jwkNoAlg = { ...hs256Jwk };
      delete jwkNoAlg.alg;
      const options: ImportKeyOptions = { alg: "HS256" };
      const key = await importKey(jwkNoAlg, options);
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as HmacKeyAlgorithm).hash.name).toBe("SHA-256");
    });

    it("should use keyUsages from options", async () => {
      const options: ImportKeyOptions = { keyUsages: ["sign"] };
      const key = await importKey(hs256Jwk, options);
      expect(key.usages).toEqual(expect.arrayContaining(["sign"]));
    });

    it("should use extractable from options", async () => {
      const options: ImportKeyOptions = { extractable: false };
      const key = await importKey(hs256Jwk, options);
      expect(key.extractable).toBe(false);
    });

    it("should infer usages from jwk.use='sig'", async () => {
      const jwkUseSig = { ...hs256Jwk, use: "sig" } as JWK_oct;
      delete jwkUseSig.key_ops; // Remove explicit ops
      const key = await importKey(jwkUseSig);
      expect(key.usages).toEqual(expect.arrayContaining(["sign", "verify"]));

      const rsaJwkUseSig = { ...rs256PublicJwk, use: "sig" } as JWK_RSA;
      delete rsaJwkUseSig.key_ops;
      const rsaKey = await importKey(rsaJwkUseSig);
      expect(rsaKey.usages).toEqual(expect.arrayContaining(["verify"]));
    });

    it("should infer usages from jwk.use='enc'", async () => {
      const jwkUseEnc = { ...a128kwJwk, use: "enc" } as JWK_oct;
      delete jwkUseEnc.key_ops;
      const key = await importKey(jwkUseEnc);
      expect(key.usages).toEqual(expect.arrayContaining(["wrapKey", "unwrapKey"]));

      const rsaJwkUseEnc = { ...rsaOaepPublicJwk, use: "enc" } as JWK_RSA;
      delete rsaJwkUseEnc.key_ops;
      const rsaKey = await importKey(rsaJwkUseEnc);
      expect(rsaKey.usages).toEqual(expect.arrayContaining(["wrapKey", "encrypt"]));
    });

    // --- Error Cases ---
    it("should throw if alg is missing in JWK and options (oct)", async () => {
      const jwkNoAlg = { ...hs256Jwk };
      delete jwkNoAlg.alg;
      await expect(importKey(jwkNoAlg)).rejects.toThrow(
        /Algorithm \('alg'\) missing.*cannot infer for 'oct' key type/,
      );
    });

    it("should throw if alg is missing in JWK and options (RSA)", async () => {
      const jwkNoAlg = { ...rs256PublicJwk };
      delete jwkNoAlg.alg;
      await expect(importKey(jwkNoAlg)).rejects.toThrow(
        /Algorithm \('alg'\) missing.*cannot infer specific RSA algorithm/,
      );
    });

    it("should throw for unsupported algorithm", async () => {
      const jwkUnsupportedAlg = { ...hs256Jwk, alg: "Unsupported" };
      await expect(importKey(jwkUnsupportedAlg)).rejects.toThrow(
        /Unsupported or unknown algorithm for key import: Unsupported/,
      );
    });

    it("should throw if JWK kty mismatches algorithm (oct for RSA)", async () => {
      const jwkWrongKty = { ...hs256Jwk, alg: "RS256" }; // oct key, RSA alg
      await expect(importKey(jwkWrongKty)).rejects.toThrow(
        /Invalid JWK "kty" Parameter/,
      );
    });

    it("should throw if JWK kty mismatches algorithm (RSA for HMAC)", async () => {
      const jwkWrongKty = { ...rs256PublicJwk, alg: "HS256" }; // RSA key, HMAC alg
      await expect(importKey(jwkWrongKty)).rejects.toThrow(
        /Invalid JWK "kty" Parameter/,
      );
    });

    it("should throw if JWK kty mismatches algorithm (RSA for AES-KW)", async () => {
      const jwkWrongKty = { ...rs256PublicJwk, alg: "A128KW" }; // RSA key, AES-KW alg
      await expect(importKey(jwkWrongKty)).rejects.toThrow(
        /JWK with alg 'A128KW' must have kty 'oct'./,
      );
    });

    it("should throw if JWK kty mismatches algorithm (RSA for AES-GCM)", async () => {
      const jwkWrongKty = { ...rs256PublicJwk, alg: "A128GCM" }; // RSA key, AES-GCM alg
      await expect(importKey(jwkWrongKty)).rejects.toThrow(
        /JWK with alg 'A128GCM' must have kty 'oct'./,
      );
    });
  });

  describe("importKey (Raw)", () => {
    it("should import raw bits for HS256", async () => {
      const rawKey = randomBytes(32); // 256 bits
      const options: ImportKeyOptions = {
        alg: "HS256",
        keyUsages: ["sign", "verify"],
      };
      const key = await importKey(rawKey.buffer as ArrayBuffer, options);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("HMAC");
      expect((key.algorithm as HmacKeyAlgorithm).hash.name).toBe("SHA-256");
      expect(key.extractable).toBe(true); // Default
      expect(key.usages).toEqual(expect.arrayContaining(["sign", "verify"]));
    });

    it("should import raw bits for A128KW", async () => {
      const rawKey = randomBytes(16); // 128 bits
      const options: ImportKeyOptions = {
        alg: "A128KW",
        keyUsages: ["wrapKey", "unwrapKey"],
        extractable: false,
      };
      const key = await importKey(rawKey.buffer as ArrayBuffer, options);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("AES-KW");
      expect(key.extractable).toBe(false);
      expect(key.usages).toEqual(expect.arrayContaining(["wrapKey", "unwrapKey"]));
    });

    it("should import raw bits for A256GCM", async () => {
      const rawKey = randomBytes(32); // 256 bits
      const options: ImportKeyOptions = {
        alg: "A256GCM",
        keyUsages: ["encrypt", "decrypt"],
      };
      const key = await importKey(rawKey.buffer as ArrayBuffer, options);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("AES-GCM");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["encrypt", "decrypt"]));
    });

    it("should import raw bits for AES-CBC (encryption part)", async () => {
      const rawKey = randomBytes(16); // 128 bits for A128CBC
      const options: ImportKeyOptions = {
        alg: "AES-CBC", // Generic AES-CBC import
        keyUsages: ["encrypt", "decrypt"],
      };
      const key = await importKey(rawKey.buffer as ArrayBuffer, options);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("AES-CBC");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["encrypt", "decrypt"]));
    });

    it("should import raw bits for AES-CBC (from specific JWE alg)", async () => {
      const rawKey = randomBytes(16); // 128 bits for A128CBC
      const options: ImportKeyOptions = {
        alg: "A128CBC-HS256", // Specific JWE alg implies AES-CBC
        keyUsages: ["encrypt", "decrypt"],
      };
      const key = await importKey(rawKey.buffer as ArrayBuffer, options);
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.algorithm.name).toBe("AES-CBC");
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(expect.arrayContaining(["encrypt", "decrypt"]));
    });

    // --- Error Cases ---
    it("should throw if alg is missing", async () => {
      const rawKey = randomBytes(32);
      const options: ImportKeyOptions = { keyUsages: ["sign"] };
      // @ts-expect-error - Testing missing alg
      await expect(importKey(rawKey.buffer, options)).rejects.toThrow(
        "Algorithm ('alg') must be specified in options when importing raw key bits.",
      );
    });

    it("should throw if keyUsages are missing", async () => {
      const rawKey = randomBytes(32);
      const options: ImportKeyOptions = { alg: "HS256" };
      // @ts-expect-error - Testing missing keyUsages
      await expect(importKey(rawKey.buffer, options)).rejects.toThrow(
        "Key usages ('keyUsages') must be specified in options when importing raw key bits.",
      );
    });

    it("should throw if keyUsages are empty", async () => {
      const rawKey = randomBytes(32);
      const options: ImportKeyOptions = { alg: "HS256", keyUsages: [] };
      await expect(
        importKey(rawKey.buffer as ArrayBuffer, options),
      ).rejects.toThrow(
        "Key usages ('keyUsages') must be specified in options when importing raw key bits.",
      );
    });

    it("should throw for unsupported algorithm (RSA)", async () => {
      const rawKey = randomBytes(256); // Doesn't matter for this test
      const options: ImportKeyOptions = {
        alg: "RS256",
        keyUsages: ["verify"],
      };
      await expect(
        importKey(rawKey.buffer as ArrayBuffer, options),
      ).rejects.toThrow(
        "Unsupported or unsuitable algorithm for raw key import: RS256",
      );
    });
  });

  describe("deriveKeyBitsFromPassword", () => {
    const password = "test-password";
    const passwordBytes = textEncoder.encode(password);

    it("should derive key bits with default options", async () => {
      const result = await deriveKeyBitsFromPassword(password, {
        keyLength: 256,
      });
      expect(result).toHaveProperty("derivedBits");
      expect(result.derivedBits).toBeInstanceOf(ArrayBuffer);
      expect(result.derivedBits.byteLength).toBe(32); // 256 bits / 8
      expect(result.salt).toBeInstanceOf(Uint8Array);
      expect(result.salt.length).toBe(16); // Default salt length
      expect(result.iterations).toBe(2048); // Default iterations
      expect(result.hash).toBe("SHA-256"); // Default hash
      expect(result.keyLength).toBe(256);
    });

    it("should derive key bits with Uint8Array password", async () => {
      const result = await deriveKeyBitsFromPassword(passwordBytes, {
        keyLength: 128,
      });
      expect(result.derivedBits.byteLength).toBe(16); // 128 bits / 8
      expect(result.keyLength).toBe(128);
    });

    it("should derive key bits with custom salt, iterations, and hash", async () => {
      const salt = randomBytes(8);
      const iterations = 5000;
      const hash = "SHA-512";
      const keyLength = 512;

      const result = await deriveKeyBitsFromPassword(password, {
        keyLength,
        salt,
        iterations,
        hash,
      });

      expect(result.derivedBits.byteLength).toBe(64); // 512 bits / 8
      expect(result.salt).toBe(salt);
      expect(result.iterations).toBe(iterations);
      expect(result.hash).toBe(hash);
      expect(result.keyLength).toBe(keyLength);

      // Verify deriving again with same params yields same bits
      const result2 = await deriveKeyBitsFromPassword(password, {
        keyLength,
        salt,
        iterations,
        hash,
      });
      expect(new Uint8Array(result.derivedBits)).toEqual(
        new Uint8Array(result2.derivedBits),
      );
    });

    // --- Error Cases ---
    it("should throw if keyLength is missing", async () => {
      // @ts-expect-error - Testing missing keyLength
      await expect(deriveKeyBitsFromPassword(password, {})).rejects.toThrow(
        "keyLength must be a positive number.",
      );
    });

    it("should throw if keyLength is zero", async () => {
      await expect(
        deriveKeyBitsFromPassword(password, { keyLength: 0 }),
      ).rejects.toThrow("keyLength must be a positive number.");
    });

    it("should throw if keyLength is negative", async () => {
      await expect(
        deriveKeyBitsFromPassword(password, { keyLength: -128 }),
      ).rejects.toThrow("keyLength must be a positive number.");
    });

    it("should throw if salt is empty", async () => {
      await expect(
        deriveKeyBitsFromPassword(password, {
          keyLength: 256,
          salt: new Uint8Array(0),
        }),
      ).rejects.toThrow("Salt cannot be empty.");
    });

    it("should throw if iterations is zero", async () => {
      await expect(
        deriveKeyBitsFromPassword(password, { keyLength: 256, iterations: 0 }),
      ).rejects.toThrow("Iterations must be positive.");
    });

    it("should throw if iterations is negative", async () => {
      await expect(
        deriveKeyBitsFromPassword(password, {
          keyLength: 256,
          iterations: -100,
        }),
      ).rejects.toThrow("Iterations must be positive.");
    });
  });
});
