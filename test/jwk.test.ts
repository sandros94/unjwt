import { describe, it, expect, beforeAll, afterEach } from "vitest";
import * as jose from "jose";
import {
  generateKey,
  generateJWK,
  deriveKeyFromPassword,
  deriveJWKFromPassword,
  importKey,
  exportKey,
  wrapKey,
  unwrapKey,
  deriveSharedSecret,
  importPEM,
  exportPEM,
  importFromPEM,
  exportToPEM,
  getJWKFromSet,
  getJWKsFromSet,
  WeakMapJWKCache,
  configureJWKCache,
  clearJWKCache,
} from "../src/core/jwk";
import {
  isCryptoKey,
  isCryptoKeyPair,
  randomBytes,
  base64UrlDecode,
  base64UrlEncode,
} from "../src/core/utils";
import type {
  JWKSet,
  JWK_oct,
  JWK_EC_Private,
  JWK_EC_Public,
  JWK_RSA_Private,
  JWK_RSA_Public,
  JWKPEMAlgorithm,
} from "../src/core/types";
import { rsa, ec } from "./keys";
import { deriveECDHESKey, encryptRSAES, bitLengthCEK } from "../src/core/_crypto";

describe.concurrent("JWK Utilities", () => {
  describe("generateKey", () => {
    it("should generate symmetric CryptoKey (HS256)", async () => {
      const key = await generateKey("HS256");
      expect(isCryptoKey(key)).toBe(true);
      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("HMAC");

      const jwk = await exportKey(key);
      await expect(jose.importJWK({ ...jwk, alg: "HS256" })).resolves.toBeInstanceOf(Object);
    });

    it("should generate symmetric JWK (HS256, toJWK: true)", async () => {
      const jwk = await generateKey("HS256", { toJWK: true });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("HS256");
      expect(typeof jwk.k).toBe("string");

      await expect(jose.importJWK(jwk)).resolves.toBeInstanceOf(Object);
    });

    it("should generate symmetric CryptoKey (A128KW)", async () => {
      const key = await generateKey("A128KW");
      expect(isCryptoKey(key)).toBe(true);
      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("AES-KW");

      const jwk = await exportKey(key);
      await expect(jose.importJWK({ ...jwk, alg: "A128KW" })).resolves.toBeInstanceOf(Object);
    });

    it("should generate symmetric JWK (A128KW, toJWK: true)", async () => {
      const jwk = await generateKey("A128KW", { toJWK: true });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A128KW");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlDecode(jwk.k, false).length).toBe(16); // 128 bits

      await expect(jose.importJWK(jwk)).resolves.toBeInstanceOf(Object);
    });

    it("should generate asymmetric CryptoKeyPair (RS256)", async () => {
      const keyPair = await generateKey("RS256", { modulusLength: 1024 });
      expect(isCryptoKeyPair(keyPair)).toBe(true);
      expect(keyPair.publicKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
      expect(keyPair.privateKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");

      const jwk = await exportKey(keyPair.privateKey);
      await expect(jose.importJWK({ ...jwk, alg: "RS256" })).resolves.toBeInstanceOf(Object);
    });

    it("should generate asymmetric JWK pair (RS256, toJWK: true)", async () => {
      const jwkPair = await generateKey("RS256", {
        toJWK: true,
        modulusLength: 1024,
      });
      expect(jwkPair.privateKey.kty).toBe("RSA");
      expect(jwkPair.privateKey.alg).toBe("RS256");
      expect(jwkPair.privateKey.d).toBeDefined();
      expect(jwkPair.publicKey.kty).toBe("RSA");
      expect(jwkPair.publicKey.alg).toBe("RS256");
      // @ts-expect-error d is not part of RSA public key
      expect(jwkPair.publicKey.d).toBeUndefined();
      expect(jwkPair.publicKey.n).toBe(jwkPair.privateKey.n);

      await expect(jose.importJWK(jwkPair.privateKey)).resolves.toBeInstanceOf(CryptoKey);
      await expect(jose.importJWK(jwkPair.publicKey)).resolves.toBeInstanceOf(CryptoKey);
    });

    it("should generate asymmetric CryptoKeyPair (ES256)", async () => {
      const keyPair = await generateKey("ES256");
      expect(isCryptoKeyPair(keyPair)).toBe(true);
      expect(keyPair.publicKey.algorithm.name).toBe("ECDSA");
      expect((keyPair.publicKey.algorithm as EcKeyAlgorithm).namedCurve).toBe("P-256");

      const jwk = await exportKey(keyPair.privateKey);
      await expect(jose.importJWK({ ...jwk, alg: "ES256" })).resolves.toBeInstanceOf(Object);
    });

    it("should generate asymmetric JWK pair (ES256, toJWK: true)", async () => {
      const jwkPair = await generateKey("ES256", { toJWK: true });
      expect(jwkPair.privateKey.kty).toBe("EC");
      expect(jwkPair.privateKey.alg).toBe("ES256");
      expect(jwkPair.privateKey.crv).toBe("P-256");
      expect(jwkPair.privateKey.d).toBeDefined();
      expect(jwkPair.publicKey.kty).toBe("EC");
      expect(jwkPair.publicKey.alg).toBe("ES256");
      expect(jwkPair.publicKey.crv).toBe("P-256");
      // @ts-expect-error d is not part of EC public key
      expect(jwkPair.publicKey.d).toBeUndefined();
      expect(jwkPair.publicKey.x).toBe(jwkPair.privateKey.x);

      await expect(jose.importJWK(jwkPair.privateKey)).resolves.toBeInstanceOf(CryptoKey);
      await expect(jose.importJWK(jwkPair.publicKey)).resolves.toBeInstanceOf(CryptoKey);
    });

    it("should generate asymmetric JWK pair with custom `kid`", async () => {
      const kid = crypto.randomUUID();
      const jwkPair = await generateJWK("Ed25519", { kid });
      expect(jwkPair.privateKey.kty).toBe("OKP");
      expect(jwkPair.privateKey.alg).toBe("Ed25519");
      expect(jwkPair.privateKey.kid).toBe(kid);
      expect(jwkPair.privateKey.crv).toBe("Ed25519");
      expect(jwkPair.privateKey.d).toBeDefined();
      expect(jwkPair.publicKey.kty).toBe("OKP");
      expect(jwkPair.publicKey.alg).toBe("Ed25519");
      expect(jwkPair.publicKey.kid).toBe(kid);
      expect(jwkPair.publicKey.crv).toBe("Ed25519");
      // @ts-expect-error d is not part of OKP public key
      expect(jwkPair.publicKey.d).toBeUndefined();
      expect(jwkPair.publicKey.x).toBe(jwkPair.privateKey.x);

      await expect(jose.importJWK(jwkPair.privateKey)).resolves.toBeInstanceOf(CryptoKey);
      await expect(jose.importJWK(jwkPair.publicKey)).resolves.toBeInstanceOf(CryptoKey);
    });

    it("should generate AES-CBC key as Uint8Array", async () => {
      const keyBytes = await generateKey("A128CBC-HS256");
      expect(keyBytes).toBeInstanceOf(Uint8Array);
      expect(keyBytes.length).toBe(32); // 128 (enc) + 256 (mac) / 8
    });

    it("should generate AES-CBC key as JWK (toJWK: true)", async () => {
      const jwk = await generateKey("A128CBC-HS256", {
        toJWK: true,
      });
      expect(jwk.kty).toBe("oct");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlDecode(jwk.k, false).length).toBe(32);

      // Verify with jose (note: jose doesn't directly use this alg, but can import raw oct keys)
      const imported = await jose.importJWK(jwk);
      const exported = await jose.exportJWK(imported);
      expect(exported.k).toEqual(jwk.k);
    });

    it("should respect extractable option (false)", async () => {
      const key = await generateKey("HS256", { extractable: false });
      expect(isCryptoKey(key)).toBe(true);
      expect(key.extractable).toBe(false);
    });

    it("should respect extractable option (true)", async () => {
      const key = await generateKey("HS256", { extractable: true });
      expect(isCryptoKey(key)).toBe(true);
      expect(key.extractable).toBe(true); // Default is true
    });

    it("should generate asymmetric CryptoKeyPair (EdDSA, Ed448)", async () => {
      const keyPair = await generateKey("EdDSA", { namedCurve: "Ed448" });
      expect(isCryptoKeyPair(keyPair)).toBe(true);
      expect(keyPair.publicKey.algorithm.name).toBe("Ed448");
      expect(keyPair.privateKey.algorithm.name).toBe("Ed448");
    });

    it("should generate ECDH-ES CryptoKeyPair with X25519 curve", async () => {
      const keyPair = await generateKey("ECDH-ES", { namedCurve: "X25519" });
      expect(isCryptoKeyPair(keyPair)).toBe(true);
      expect(keyPair.publicKey.algorithm.name).toBe("X25519");
      expect(keyPair.privateKey.algorithm.name).toBe("X25519");
    });

    it("should throw for unsupported EdDSA namedCurve", async () => {
      await expect(
        // @ts-expect-error Intentionally passing an unsupported namedCurve
        generateKey("EdDSA", { namedCurve: "Ed999" }),
      ).rejects.toThrow("Unsupported namedCurve provided. Supported values are: Ed25519 and Ed448");
    });

    it("should throw for unsupported ECDH-ES namedCurve", async () => {
      await expect(
        // @ts-expect-error Intentionally passing an unsupported namedCurve
        generateKey("ECDH-ES", { namedCurve: "P-999" }),
      ).rejects.toThrow(
        "Unsupported namedCurve provided. Supported values are: P-256, P-384, P-521 and X25519",
      );
    });

    it("should throw for unsupported algorithm", async () => {
      // @ts-expect-error Intentionally passing an unsupported algorithm
      await expect(generateKey("UnsupportedAlg")).rejects.toThrow();
    });
  });

  describe("generateJWK", () => {
    it("should generate symmetric JWK (HS256)", async () => {
      const jwk = await generateJWK("HS256");
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("HS256");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlDecode(jwk.k, false).length).toBe(64);
    });
  });

  describe("deriveKeyFromPassword/deriveJWKFromPassword", () => {
    const password = "password123";
    const salt = randomBytes(16);
    const iterations = 2000; // Keep low for tests

    it("should derive CryptoKey (PBES2-HS256+A128KW)", async () => {
      const key = await deriveKeyFromPassword(password, "PBES2-HS256+A128KW", {
        salt,
        iterations,
      });
      expect(isCryptoKey(key)).toBe(true);
      expect(key.algorithm.name).toBe("AES-KW");
      expect((key.algorithm as AesKeyAlgorithm).length).toBe(128);
      expect(key.extractable).toBe(false); // Default
    });

    it("should derive JWK (PBES2-HS384+A192KW, toJWK: true)", async () => {
      const jwk = await deriveKeyFromPassword(password, "PBES2-HS384+A192KW", {
        salt,
        iterations,
        toJWK: true,
      });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A192KW");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlDecode(jwk.k, false).length).toBe(24); // 192 bits
    });

    it("should derive JWK with custom `kid`", async () => {
      const kid = "custom-key-id";
      const jwk = await deriveJWKFromPassword(password, "PBES2-HS256+A128KW", {
        salt,
        iterations,
        kid,
      });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A128KW");
      expect(jwk.kid).toBe(kid);
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlDecode(jwk.k, false).length).toBe(16); // 128 bits
    });

    it("should respect extractable and keyUsage options", async () => {
      const key = await deriveKeyFromPassword(password, "PBES2-HS512+A256KW", {
        salt,
        iterations,
        extractable: true,
        keyUsage: ["wrapKey"],
      });
      expect(isCryptoKey(key)).toBe(true);
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(["wrapKey"]);
    });

    it("should throw for invalid salt length", async () => {
      await expect(
        deriveKeyFromPassword(password, "PBES2-HS256+A128KW", {
          salt: randomBytes(7),
          iterations,
        }),
      ).rejects.toThrow("must be 8 or more octets");
    });

    it("should throw for invalid iterations", async () => {
      await expect(
        deriveKeyFromPassword(password, "PBES2-HS256+A128KW", {
          salt,
          iterations: 0,
        }),
      ).rejects.toThrow("must be a positive integer");
    });

    it("should derive JWK with custom `kid`", async () => {
      const kid = "custom-key-id";
      const jwk = await deriveJWKFromPassword(password, "PBES2-HS256+A128KW", {
        salt,
        iterations,
        kid,
      });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A128KW");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlDecode(jwk.k, false).length).toBe(16); // 128 bits
    });
  });

  describe("importKey", () => {
    it("should return CryptoKey if input is CryptoKey", async () => {
      const originalKey = await generateKey("HS256");
      const importedKey = await importKey(originalKey);
      expect(importedKey).toBe(originalKey);
    });

    it("should return Uint8Array if input is Uint8Array", async () => {
      const originalBytes = randomBytes(32);
      const importedBytes = await importKey(originalBytes);
      expect(importedBytes).toBe(originalBytes);
    });

    it("should return cached CryptoKey for same asymmetric JWK object reference", async () => {
      const { privateKey } = await generateKey("ES256");
      const jwk = await exportKey(privateKey);
      // Import same object twice — second call hits the WeakMap cache
      const key1 = await importKey(jwk, "ES256");
      const key2 = await importKey(jwk, "ES256");
      expect(key1).toBe(key2);
    });

    it("should import symmetric JWK (oct) to Uint8Array", async () => {
      const jwk: JWK_oct = {
        kty: "oct",
        k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
      };
      const keyBytes = await importKey(jwk);
      expect(keyBytes).toBeInstanceOf(Uint8Array);
      expect(keyBytes.length).toBe(64); // HS512 example key

      const decodedByKey = base64UrlDecode(jwk.k, false);
      expect(keyBytes).toEqual(decodedByKey);
    });

    it("should import JWK_oct as non-extractable CryptoKey when asCryptoKey is true", async () => {
      const jwk = await generateJWK("A256GCM");
      const key = await importKey(jwk, {
        asCryptoKey: true,
        algorithm: { name: "AES-GCM", length: 256 },
        usage: ["encrypt", "decrypt"],
      });
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.extractable).toBe(false); // non-extractable by default
      expect(key.algorithm.name).toBe("AES-GCM");
      expect(key.usages).toContain("encrypt");
    });

    it("should import JWK_oct as extractable CryptoKey when extractable: true", async () => {
      const jwk = await generateJWK("HS256");
      const key = await importKey(jwk, {
        asCryptoKey: true,
        algorithm: { name: "HMAC", hash: "SHA-256" },
        usage: ["sign", "verify"],
        extractable: true,
      });
      expect(key.extractable).toBe(true);
    });

    // --- `expect` intent (M11) ---
    describe("expect option", () => {
      it("rejects a private JWK when expect is 'public'", async () => {
        const { privateKey } = await generateJWK("ES256");
        await expect(importKey(privateKey, { expect: "public" })).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
        );
      });

      it("rejects a public JWK when expect is 'private'", async () => {
        const { publicKey } = await generateJWK("ES256");
        await expect(importKey(publicKey, { expect: "private" })).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
        );
      });

      it("accepts matching intent on both sides", async () => {
        const { privateKey, publicKey } = await generateJWK("ES256");
        await expect(importKey(privateKey, { expect: "private" })).resolves.toBeInstanceOf(
          CryptoKey,
        );
        await expect(importKey(publicKey, { expect: "public" })).resolves.toBeInstanceOf(CryptoKey);
      });

      it("rejects a private CryptoKey when expect is 'public'", async () => {
        const { privateKey } = await generateKey("ES256");
        await expect(importKey(privateKey, { expect: "public" } as any)).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
        );
      });

      it("is a no-op on symmetric (oct) JWKs", async () => {
        const jwk = await generateJWK("HS256");
        // oct JWKs have no public/private distinction — both directions succeed.
        await expect(importKey(jwk, { expect: "public" })).resolves.toBeInstanceOf(Uint8Array);
        await expect(importKey(jwk, { expect: "private" })).resolves.toBeInstanceOf(Uint8Array);
      });
    });
  });

  describe("exportKey", () => {
    it("should export symmetric CryptoKey to JWK", async () => {
      const cryptoKey = await generateKey("A128GCM");
      const jwk = await exportKey<JWK_oct>(cryptoKey);
      expect(jwk.kty).toBe("oct");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlDecode(jwk.k, false).length).toBe(16);

      await expect(jose.importJWK(jwk)).resolves.toBeInstanceOf(Object);
    });

    it("should export asymmetric public CryptoKey to JWK", async () => {
      const { publicKey } = await generateKey("ES256");
      const jwk = await exportKey<JWK_EC_Public>(publicKey);
      expect(jwk.kty).toBe("EC");
      expect(jwk.crv).toBe("P-256");
      // @ts-expect-error d is not part of EC public key
      expect(jwk.d).toBeUndefined();
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();

      await expect(jose.importJWK(jwk, "ES256")).resolves.toBeInstanceOf(Object);
    });

    it("should export asymmetric private CryptoKey to JWK", async () => {
      const { privateKey } = await generateKey("ES256");
      const jwk = await exportKey<JWK_EC_Private>(privateKey);
      expect(jwk.kty).toBe("EC");
      expect(jwk.crv).toBe("P-256");
      expect(jwk.d).toBeDefined();
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();

      await expect(jose.importJWK(jwk, "ES256")).resolves.toBeInstanceOf(Object);
    });

    it("should merge provided partial JWK properties", async () => {
      const cryptoKey = await generateKey("HS256");
      const jwk = await exportKey<JWK_oct>(cryptoKey, { use: "sig" });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("HS256"); // carried through from Web Crypto export
      expect(jwk.use).toBe("sig");
      expect(typeof jwk.k).toBe("string");

      await expect(jose.importJWK(jwk)).resolves.toBeInstanceOf(Object);
    });
  });

  describe("wrapKey / unwrapKey", async () => {
    const cek = randomBytes(32); // Example: 256-bit key
    const cekCryptoKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, true, [
      "encrypt",
      "decrypt",
    ]);

    // --- AES-KW ---
    it("should wrap/unwrap with AES-KW (A128KW)", async () => {
      const wrappingKey = await generateKey("A128KW");
      const { encryptedKey } = await wrapKey("A128KW", cek, wrappingKey);
      expect(encryptedKey).toBeInstanceOf(Uint8Array);

      const unwrappedBytes = await unwrapKey("A128KW", encryptedKey, wrappingKey, {
        format: "raw",
      });
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey("A128KW", encryptedKey, wrappingKey, {
        format: "cryptokey",
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(isCryptoKey(unwrappedKey)).toBe(true);
      expect(unwrappedKey.algorithm.name).toBe("AES-GCM");
    });

    // --- RSA-OAEP ---
    it("should wrap/unwrap with RSA-OAEP", async () => {
      const { publicKey, privateKey } = await generateKey("RSA-OAEP", {
        modulusLength: 2048,
      });
      const { encryptedKey } = await wrapKey("RSA-OAEP", cekCryptoKey, publicKey);
      expect(encryptedKey).toBeInstanceOf(Uint8Array);

      const unwrappedKey = await unwrapKey("RSA-OAEP", encryptedKey, privateKey, {
        format: "cryptokey",
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(isCryptoKey(unwrappedKey)).toBe(true);
      const exportedUnwrapped = await exportKey<JWK_oct>(unwrappedKey);
      const exportedOriginal = await exportKey<JWK_oct>(cekCryptoKey);
      expect(exportedUnwrapped.k).toEqual(exportedOriginal.k);
    });

    describe("RSA-OAEP variants", () => {
      const rsaAlgorithms = ["RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512"] as const;
      type RSAAlg = (typeof rsaAlgorithms)[number];
      const rsaKeyPairs: Partial<Record<RSAAlg, CryptoKeyPair>> = {};

      beforeAll(async () => {
        await Promise.all(
          rsaAlgorithms.map(async (alg) => {
            rsaKeyPairs[alg] = (await generateKey(alg, {
              modulusLength: 2048,
            })) as CryptoKeyPair;
          }),
        );
      });

      it.each(rsaAlgorithms)(
        "should return raw CEK bytes for %s when format is 'raw'",
        async (alg) => {
          const pair = rsaKeyPairs[alg]!;
          const cekBytes = randomBytes(32);
          const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

          const unwrapped = await unwrapKey(alg, encryptedKey, pair.privateKey, {
            enc: "A128GCM",
            format: "raw",
          });

          expect(unwrapped).toBeInstanceOf(Uint8Array);
          expect(unwrapped).toEqual(cekBytes);
        },
      );

      it.each(rsaAlgorithms)(
        "should infer AES-GCM CryptoKey for %s when enc is provided",
        async (alg) => {
          const pair = rsaKeyPairs[alg]!;
          const cekBytes = randomBytes(32);
          const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

          const unwrappedKey = await unwrapKey(alg, encryptedKey, pair.privateKey, {
            enc: "A256GCM",
          });

          expect(isCryptoKey(unwrappedKey)).toBe(true);
          expect(unwrappedKey.algorithm.name).toBe("AES-GCM");
        },
      );

      it("should infer AES-GCM CryptoKey from CEK length when enc and unwrappedKeyAlgorithm are absent", async () => {
        const alg: RSAAlg = "RSA-OAEP";
        const pair = rsaKeyPairs[alg]!;
        const cekBytes = randomBytes(32); // 256 bits → infers AES-GCM-256
        const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

        const unwrappedKey = await unwrapKey(alg, encryptedKey, pair.privateKey, {
          format: "cryptokey",
          // no enc, no unwrappedKeyAlgorithm — hits inferAesImportAlgorithm bitLength branch
        });

        expect(isCryptoKey(unwrappedKey)).toBe(true);
        expect(unwrappedKey.algorithm.name).toBe("AES-GCM");
        expect((unwrappedKey.algorithm as AesKeyAlgorithm).length).toBe(256);
      });

      it("should throw when enc is absent and CEK length is non-standard", async () => {
        const alg: RSAAlg = "RSA-OAEP";
        const pair = rsaKeyPairs[alg]!;
        const cekBytes = randomBytes(20); // 160 bits — not 128/192/256 → inferAesImportAlgorithm returns undefined
        const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

        await expect(
          unwrapKey(alg, encryptedKey, pair.privateKey, {
            format: "cryptokey",
            // no enc, no unwrappedKeyAlgorithm — inferAesImportAlgorithm returns undefined
          }),
        ).rejects.toThrow(/Unable to infer algorithm for RSA-OAEP unwrapped key/i);
      });

      it("should handle composite CBC CEK via RSA-OAEP-256", async () => {
        const alg: RSAAlg = "RSA-OAEP-256";
        const pair = rsaKeyPairs[alg]!;
        const cekBytes = randomBytes(bitLengthCEK("A256CBC-HS512") >> 3);
        const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

        await expect(
          unwrapKey(alg, encryptedKey, pair.privateKey, {
            enc: "A256CBC-HS512",
          }),
        ).rejects.toThrow(/Unable to infer algorithm for RSA-OAEP unwrapped key/i);

        const unwrapped = await unwrapKey(alg, encryptedKey, pair.privateKey, {
          enc: "A256CBC-HS512",
          format: "raw",
        });

        expect(unwrapped).toBeInstanceOf(Uint8Array);
        expect(unwrapped).toEqual(cekBytes);
      });
    });

    // --- AES-GCMKW ---
    it("should wrap/unwrap with AES-GCMKW (A128GCMKW)", async () => {
      const wrappingKey = await generateKey("A128GCM", { extractable: true }); // Key for AES-GCMKW must be AES-GCM
      const { encryptedKey, iv, tag } = await wrapKey("A128GCMKW", cek, wrappingKey);
      expect(encryptedKey).toBeInstanceOf(Uint8Array);
      expect(typeof iv).toBe("string");
      expect(typeof tag).toBe("string");

      const unwrappedBytes = await unwrapKey("A128GCMKW", encryptedKey, wrappingKey, {
        iv,
        tag,
        format: "raw",
      });
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey("A128GCMKW", encryptedKey, wrappingKey, {
        iv,
        tag,
        format: "cryptokey",
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(isCryptoKey(unwrappedKey)).toBe(true);
    });

    // --- PBES2 ---
    it("should wrap/unwrap with PBES2", async () => {
      const password = "test-password";
      const p2s = randomBytes(16);
      const p2c = 2000;
      const {
        encryptedKey,
        p2s: returnedP2s,
        p2c: returnedP2c,
      } = await wrapKey("PBES2-HS256+A128KW", cek, password, { p2s, p2c });

      expect(encryptedKey).toBeInstanceOf(Uint8Array);
      expect(returnedP2s).toBeDefined();
      expect(returnedP2c).toBe(p2c);

      const unwrappedBytes = await unwrapKey("PBES2-HS256+A128KW", encryptedKey, password, {
        p2s: returnedP2s!,
        p2c: returnedP2c!,
        format: "raw",
      });
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey("PBES2-HS256+A128KW", encryptedKey, password, {
        p2s: returnedP2s!,
        p2c: returnedP2c!,
        format: "cryptokey",
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(isCryptoKey(unwrappedKey)).toBe(true);
    });

    it("should throw wrapKey if PBES2 options missing", async () => {
      await expect(wrapKey("PBES2-HS256+A128KW", cek, "password")).rejects.toThrow(
        "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
      );
    });

    it("should throw unwrapKey if AES-GCMKW options missing", async () => {
      const wrappingKey = await generateKey("A128GCM", { extractable: true });
      const { encryptedKey } = await wrapKey("A128GCMKW", cek, wrappingKey);
      await expect(unwrapKey("A128GCMKW", encryptedKey, wrappingKey)).rejects.toThrow(
        "AES-GCMKW requires 'iv' and 'tag' options",
      );
    });

    it("should throw unwrapKey if PBES2 options missing", async () => {
      const { encryptedKey } = await wrapKey("PBES2-HS256+A128KW", cek, "password", {
        p2s: randomBytes(8),
        p2c: 1000,
      });
      await expect(unwrapKey("PBES2-HS256+A128KW", encryptedKey, "password")).rejects.toThrow(
        "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
      );
    });

    it("should throw unwrapKey for wrong key/tag", async () => {
      const wrappingKey1 = await generateKey("A128KW");
      const wrappingKey2 = await generateKey("A128KW");
      const { encryptedKey } = await wrapKey("A128KW", cek, wrappingKey1);
      await expect(unwrapKey("A128KW", encryptedKey, wrappingKey2)).rejects.toThrow(); // Subtle crypto errors vary, check for any throw
    });

    it("should throw wrapKey for invalid key type", async () => {
      await expect(wrapKey("A128KW", cek, "not-a-key-object")).rejects.toThrow(TypeError);
      await expect(wrapKey("RSA-OAEP", cek, randomBytes(32))).rejects.toThrow(); // RSA needs CryptoKey
    });

    it("should throw wrapKey for unsupported algorithm", async () => {
      await expect(
        // @ts-expect-error intentionally invalid algorithm
        wrapKey("UNSUPPORTED-WRAP-ALG", cek, randomBytes(16)),
      ).rejects.toThrow("Unsupported key wrapping algorithm");
    });

    it("should throw wrapKey for ECDH-ES direct without options.ecdh.enc", async () => {
      const recipientKeys = (await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;
      await expect(wrapKey("ECDH-ES", cek, recipientKeys.publicKey)).rejects.toThrow(
        "options.ecdh.enc",
      );
    });

    it("should throw unwrapKey RSA-OAEP when unwrapping key is not a CryptoKey", async () => {
      await expect(
        unwrapKey("RSA-OAEP", new Uint8Array(32), randomBytes(32) as any, {
          format: "raw",
        }),
      ).rejects.toThrow("RSA-OAEP requires the unwrapping key to be provided as a CryptoKey");
    });

    it("should throw unwrapKey for invalid key type", async () => {
      const wrappingKey = await generateKey("A128KW");
      const { encryptedKey } = await wrapKey("A128KW", cek, wrappingKey);
      await expect(unwrapKey("A128KW", encryptedKey, "not-a-key-object")).rejects.toThrow(
        TypeError,
      );
    });

    it("should throw unwrapKey for unsupported algorithm", async () => {
      await expect(
        // @ts-expect-error intentionally invalid algorithm
        unwrapKey("UNSUPPORTED-ALG", new Uint8Array(0), new Uint8Array(0)),
      ).rejects.toThrow("Unsupported key unwrapping algorithm");
    });

    it("should throw for ECDH-ES unwrapKey without epk option", async () => {
      const recipientKeys = (await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;

      await expect(
        unwrapKey("ECDH-ES", new Uint8Array(0), recipientKeys.privateKey, {
          enc: "A128GCM",
          // no epk — triggers "ECDH-ES requires 'epk'"
        }),
      ).rejects.toThrow("ECDH-ES requires 'epk'");
    });

    it("should throw when ECDH-ES unwrapping key is not a CryptoKey", async () => {
      const senderKeys = (await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;

      await expect(
        unwrapKey("ECDH-ES", new Uint8Array(0), randomBytes(32) as any, {
          epk: senderKeys.publicKey,
          enc: "A128GCM",
        }),
      ).rejects.toThrow("ECDH-ES requires the unwrapping key to be a CryptoKey");
    });

    it("should throw when ECDH-ES unwrapping key is not an ECDH/X25519 key", async () => {
      const senderKeys = (await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;
      const aesKey = (await generateKey("A128GCM")) as CryptoKey;

      await expect(
        unwrapKey("ECDH-ES", new Uint8Array(0), aesKey as any, {
          epk: senderKeys.publicKey,
          enc: "A128GCM",
        }),
      ).rejects.toThrow(/ECDH with the provided key is not allowed/i);
    });

    it("should throw for ECDH-ES unwrapKey without enc option", async () => {
      const recipientKeys = (await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;
      const senderKeys = (await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;

      await expect(
        unwrapKey("ECDH-ES", new Uint8Array(0), recipientKeys.privateKey, {
          epk: senderKeys.publicKey,
          // no enc — triggers "ECDH-ES requires content encryption algorithm"
        }),
      ).rejects.toThrow("ECDH-ES requires content encryption algorithm");
    });

    it("should throw for ECDH-ES+KW unwrapKey with empty wrapped key", async () => {
      const recipientKeys = (await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;
      const senderKeys = (await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;

      await expect(
        unwrapKey("ECDH-ES+A128KW", new Uint8Array(0), recipientKeys.privateKey, {
          epk: senderKeys.publicKey,
          enc: "A128GCM",
          // empty wrappedKey — triggers "requires an encrypted key"
        }),
      ).rejects.toThrow("ECDH-ES key agreement with key wrapping requires an encrypted key");
    });

    it("should unwrap ECDH-ES shared secret", async () => {
      const recipientKeys = (await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;
      const senderKeys = (await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;

      const apu = randomBytes(16);
      const apv = randomBytes(16);

      const expectedSharedSecret = await deriveECDHESKey(
        recipientKeys.publicKey,
        senderKeys.privateKey,
        "A128GCM",
        128,
        apu,
        apv,
      );

      const unwrapped = await unwrapKey("ECDH-ES", new Uint8Array(0), recipientKeys.privateKey, {
        epk: senderKeys.publicKey,
        apu: base64UrlEncode(apu),
        apv: base64UrlEncode(apv),
        enc: "A128GCM",
        format: "raw",
      });

      expect(unwrapped).toBeInstanceOf(Uint8Array);
      expect(unwrapped).toEqual(expectedSharedSecret);
    });

    it("should unwrap ECDH-ES+A128KW encrypted key", async () => {
      const recipientKeys = (await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;
      const senderKeys = (await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;

      const apu = randomBytes(16);
      const apv = randomBytes(16);

      const sharedSecret = await deriveECDHESKey(
        recipientKeys.publicKey,
        senderKeys.privateKey,
        "ECDH-ES+A128KW",
        128,
        apu,
        apv,
      );

      const cekBytes = randomBytes(16); // 128-bit CEK for A128KW

      const sharedSecretKey = await crypto.subtle.importKey(
        "raw",
        sharedSecret,
        { name: "AES-KW" },
        true,
        ["wrapKey"],
      );

      const cekCryptoKey = await crypto.subtle.importKey(
        "raw",
        cekBytes,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"],
      );

      const encryptedKey = new Uint8Array(
        await crypto.subtle.wrapKey("raw", cekCryptoKey, sharedSecretKey, "AES-KW"),
      );

      const unwrapped = await unwrapKey("ECDH-ES+A128KW", encryptedKey, recipientKeys.privateKey, {
        epk: senderKeys.publicKey,
        apu: base64UrlEncode(apu),
        apv: base64UrlEncode(apv),
        enc: "A128GCM",
        format: "raw",
      });

      expect(unwrapped).toBeInstanceOf(Uint8Array);
      expect(unwrapped).toEqual(cekBytes);
    });

    it("wrapKey/unwrapKey ECDH-ES direct roundtrip — P-256", async () => {
      const recipientKP = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
      );
      const enc = "A128GCM";

      const { encryptedKey, epk, apu, apv } = await wrapKey(
        "ECDH-ES",
        randomBytes(16), // ignored for direct ECDH-ES
        recipientKP.publicKey,
        { ecdh: { enc } },
      );

      expect(encryptedKey.length).toBe(0); // no encrypted key for direct agreement
      expect(epk).toBeDefined();

      const derived = await unwrapKey("ECDH-ES", encryptedKey, recipientKP.privateKey, {
        epk: epk!,
        apu,
        apv,
        enc,
        format: "raw",
      });

      expect(derived).toBeInstanceOf(Uint8Array);
      expect(derived.length).toBe(16); // 128 bits for A128GCM
    });

    it("wrapKey/unwrapKey ECDH-ES+A128KW roundtrip", async () => {
      const recipientKP = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
      );
      const cekToWrap = randomBytes(16);

      const { encryptedKey, epk, apu, apv } = await wrapKey(
        "ECDH-ES+A128KW",
        cekToWrap,
        recipientKP.publicKey,
      );

      expect(encryptedKey.length).toBeGreaterThan(0);

      const unwrapped = await unwrapKey("ECDH-ES+A128KW", encryptedKey, recipientKP.privateKey, {
        epk: epk!,
        apu,
        apv,
        enc: "A128GCM",
        format: "raw",
      });

      expect(unwrapped).toEqual(cekToWrap);
    });

    it("wrapKey/unwrapKey ECDH-ES+A256KW roundtrip — X25519", async () => {
      const recipientKP = (await crypto.subtle.generateKey({ name: "X25519" }, true, [
        "deriveBits",
      ])) as CryptoKeyPair;
      const cekToWrap = randomBytes(32);

      const { encryptedKey, epk, apu, apv } = await wrapKey(
        "ECDH-ES+A256KW",
        cekToWrap,
        recipientKP.publicKey,
      );

      const unwrapped = await unwrapKey("ECDH-ES+A256KW", encryptedKey, recipientKP.privateKey, {
        epk: epk!,
        apu,
        apv,
        enc: "A256GCM",
        format: "raw",
      });

      expect(unwrapped).toEqual(cekToWrap);
    });
  });

  describe("deriveSharedSecret", () => {
    it("produces the same secret on both sides — P-256", async () => {
      const [recipientKP, ephemeralKP] = await Promise.all([
        crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]),
        crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]),
      ]);

      const [sender, recipient] = await Promise.all([
        deriveSharedSecret(recipientKP.publicKey, ephemeralKP.privateKey, "ECDH-ES+A128KW"),
        deriveSharedSecret(ephemeralKP.publicKey, recipientKP.privateKey, "ECDH-ES+A128KW"),
      ]);

      expect(sender).toEqual(recipient);
      expect(sender.length).toBe(16);
    });

    it("produces the same secret on both sides — X25519", async () => {
      const [recipientKP, ephemeralKP] = await Promise.all([
        crypto.subtle.generateKey({ name: "X25519" }, true, [
          "deriveBits",
        ]) as Promise<CryptoKeyPair>,
        crypto.subtle.generateKey({ name: "X25519" }, true, [
          "deriveBits",
        ]) as Promise<CryptoKeyPair>,
      ]);

      const [sender, recipient] = await Promise.all([
        deriveSharedSecret(recipientKP.publicKey, ephemeralKP.privateKey, "A256GCM"),
        deriveSharedSecret(ephemeralKP.publicKey, recipientKP.privateKey, "A256GCM"),
      ]);

      expect(sender).toEqual(recipient);
      expect(sender.length).toBe(32);
    });

    it("throws when alg is ECDH-ES without keyLength", async () => {
      const kp = await generateKey("ECDH-ES", { namedCurve: "P-256" });
      await expect(deriveSharedSecret(kp.publicKey, kp.privateKey, "ECDH-ES")).rejects.toThrow(
        "keyLength",
      );
    });

    it("accepts explicit keyLength for ECDH-ES direct", async () => {
      const kp = await generateKey("ECDH-ES", { namedCurve: "P-256" });
      const secret = await deriveSharedSecret(kp.publicKey, kp.privateKey, "ECDH-ES", {
        keyLength: 256,
      });
      expect(secret.length).toBe(32);
    });
  });

  describe("getJWKFromSet", () => {
    const jwkSet = {
      keys: [
        { kty: "oct", kid: "key-1", alg: "HS256", k: "abc" },
        { kty: "oct", kid: "key-2", alg: "HS384", k: "def" },
      ],
    };

    it("should throw for invalid JWK Set", () => {
      // @ts-expect-error intentionally invalid JWK set
      expect(() => getJWKFromSet(null, "key-1")).toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
      );
      // @ts-expect-error intentionally invalid JWK set
      expect(() => getJWKFromSet({ notKeys: [] }, "key-1")).toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
      );
    });

    it("should find a key by string kid", () => {
      const key = getJWKFromSet(jwkSet, "key-1");
      expect(key.kid).toBe("key-1");
    });

    it("should throw when string kid is not found", () => {
      expect(() => getJWKFromSet(jwkSet, "missing-kid")).toThrow(
        'No key found in JWK Set with kid "missing-kid"',
      );
    });

    it("should throw when object header kid is not found (includes alg in message)", () => {
      expect(() => getJWKFromSet(jwkSet, { kid: "missing-kid", alg: "HS256" })).toThrow(
        /No key found in JWK Set with kid "missing-kid" and alg "HS256"/,
      );
    });

    it("should throw when object header kid is not found (includes kty in message)", () => {
      expect(() => getJWKFromSet(jwkSet, { kid: "missing-kid", kty: "EC" })).toThrow(
        /No key found in JWK Set with kid "missing-kid".*and kty "EC"/,
      );
    });

    it("should throw when object header has no kid and set has multiple keys", () => {
      expect(() => getJWKFromSet(jwkSet, { alg: "HS256" })).toThrow(
        "JWK Set contains multiple keys",
      );
    });

    it("should return the only key when set has one key and no kid in header", () => {
      const singleKeySet = { keys: [{ kty: "oct", kid: "only", alg: "HS256", k: "abc" }] };
      const key = getJWKFromSet(singleKeySet, { alg: "HS256" });
      expect(key.kid).toBe("only");
    });

    it("should throw for invalid input type", () => {
      // @ts-expect-error intentionally invalid
      expect(() => getJWKFromSet(jwkSet, 42)).toThrow(TypeError);
    });
  });

  describe("getJWKsFromSet", () => {
    const jwkSet: JWKSet = {
      keys: [
        { kty: "oct", kid: "k1", alg: "HS256", k: "abc" },
        { kty: "oct", kid: "k2", alg: "HS384", k: "def" },
        { kty: "EC", kid: "k3", alg: "ES256", crv: "P-256", x: "x", y: "y" },
      ],
    };

    it("should throw for invalid JWK Set", () => {
      // @ts-expect-error intentionally invalid
      expect(() => getJWKsFromSet(null)).toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
      );
    });

    it("should return all keys when no filter is given", () => {
      expect(getJWKsFromSet(jwkSet)).toHaveLength(3);
    });

    it("should return a copy — mutating the result does not affect the set", () => {
      const result = getJWKsFromSet(jwkSet);
      result.pop();
      expect(jwkSet.keys).toHaveLength(3);
    });

    it("should filter with a predicate", () => {
      const result = getJWKsFromSet(jwkSet, (k) => k.kty === "oct");
      expect(result).toHaveLength(2);
      expect(result.every((k) => k.kty === "oct")).toBe(true);
    });

    it("should filter with a predicate matching a single key", () => {
      const result = getJWKsFromSet(jwkSet, (k) => k.kid === "k1");
      expect(result).toHaveLength(1);
      expect(result[0]!.kid).toBe("k1");
    });

    it("should return all keys when predicate always returns true", () => {
      expect(getJWKsFromSet(jwkSet, () => true)).toHaveLength(3);
    });

    it("should return empty array when predicate matches no keys", () => {
      expect(getJWKsFromSet(jwkSet, (k) => k.kty === "RSA")).toHaveLength(0);
    });
  });

  describe("PEM <-> JWK Conversion", () => {
    describe("importPEM", () => {
      it("should import PKCS#8 PEM to JWK (RSA)", async () => {
        const jwk = await importPEM<JWK_RSA_Private>(rsa.pem.pkcs8, "RS256");
        expect(jwk.kty).toBe("RSA");
        expect(jwk.alg).toBe("RS256");
        expect(jwk.d).toBeDefined();
      });

      it("should import SPKI PEM to JWK (RSA)", async () => {
        const jwk = await importPEM<JWK_RSA_Public>(rsa.pem.spki, "RS256");
        expect(jwk.kty).toBe("RSA");
        expect(jwk.alg).toBe("RS256");
        // @ts-expect-error d should not be on public key
        expect(jwk.d).toBeUndefined();

        const joseKey = await jose.importSPKI(rsa.pem.spki, "RS256");
        const joseJwk = await jose.exportJWK(joseKey);
        expect(jwk).toEqual(expect.objectContaining(joseJwk));
      });

      it("should import X.509 PEM to JWK (RSA Public Key)", async () => {
        const jwk = await importPEM(rsa.pem.x509, "RS256");
        expect(jwk.kty).toBe("RSA");
        expect(jwk.alg).toBe("RS256");
        // @ts-expect-error d should not be on public key
        expect(jwk.d).toBeUndefined();

        const joseKey = await jose.importX509(rsa.pem.x509, "RS256");
        const joseJwk = await jose.exportJWK(joseKey);
        expect(jwk).toEqual(expect.objectContaining(joseJwk));
      });

      it("should import PKCS#8 PEM to JWK (EC)", async () => {
        const jwk = await importPEM<JWK_EC_Private>(ec.pem.pkcs8, "ES256");
        expect(jwk.kty).toBe("EC");
        expect(jwk.alg).toBe("ES256");
        expect(jwk.crv).toBe("P-256");
        expect(jwk.d).toBeDefined();
      });

      it("should import SPKI PEM to JWK (EC)", async () => {
        const jwk = await importPEM<JWK_EC_Public>(ec.pem.spki, "ES256");
        expect(jwk.kty).toBe("EC");
        expect(jwk.alg).toBe("ES256");

        const joseKey = await jose.importSPKI(ec.pem.spki, "ES256");
        const joseJwk = await jose.exportJWK(joseKey);
        expect(jwk).toEqual(expect.objectContaining(joseJwk));
      });

      it("should merge jwkExtras", async () => {
        const jwk = await importPEM(rsa.pem.spki, "RS256", {
          jwkParams: { kid: "test-kid", use: "enc" },
        });
        expect(jwk.kid).toBe("test-kid");
        expect(jwk.use).toBe("enc"); // Overrides any 'use' from the key itself if exportKey doesn't prioritize input jwkExtras
        expect(jwk.alg).toBe("RS256"); // Should still be set from the 'alg' param
      });

      it("honours an explicit options.pemType override", async () => {
        // Label says PUBLIC KEY; explicit pemType "spki" matches and succeeds.
        const jwk = await importPEM(rsa.pem.spki, "RS256", { pemType: "spki" });
        expect(jwk.kty).toBe("RSA");
        // Forcing pkcs8 on a SPKI body still fails at label assertion.
        await expect(importPEM(rsa.pem.spki, "RS256", { pemType: "pkcs8" })).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
        );
      });

      it("throws when PEM type cannot be inferred", async () => {
        const stripped = rsa.pem.spki.replace(/-----(BEGIN|END) [A-Z ]+-----/g, "").trim();
        await expect(importPEM(stripped, "RS256")).rejects.toThrow(/Cannot infer PEM type/);
      });

      it("should throw for unsupported PEM type", async () => {
        await expect(
          importPEM(rsa.pem.spki, "RS256", {
            // @ts-expect-error testing invalid type
            pemType: "unsupported",
          }),
        ).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_UNSUPPORTED" }),
        );
      });

      it("rejects PEM with a mismatched label", async () => {
        // SPKI body fed to the pkcs8 importer — label says PUBLIC but pkcs8 requires PRIVATE.
        await expect(importPEM(rsa.pem.spki, "RS256", { pemType: "pkcs8" })).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
        );
        // Symmetric case: pkcs8 body fed to the spki importer.
        await expect(importPEM(rsa.pem.pkcs8, "RS256", { pemType: "spki" })).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
        );
      });
    });

    describe("exportPEM", () => {
      it("should export private RSA JWK to PKCS#8 PEM", async () => {
        const pem = await exportPEM(rsa.jwk.private);

        // TODO: beautify this garbage
        expect(`${pem}\n`.replace(/\\n/g, "")).toMatch(rsa.pem.pkcs8.replace(/\\n/g, ""));
      });

      it("should export public RSA JWK to SPKI PEM", async () => {
        const pem = await exportPEM(rsa.jwk.public);

        const joseKey = await jose.importJWK(rsa.jwk.public);
        const josePem = await jose.exportSPKI(joseKey as CryptoKey);
        expect(pem).toEqual(josePem);
      });

      it("should export private EC JWK to PKCS#8 PEM", async () => {
        const pem = await exportPEM(ec.jwk.private);

        const joseKey = await jose.importJWK(ec.jwk.private);
        const josePem = await jose.exportPKCS8(joseKey as CryptoKey);
        expect(pem).toEqual(josePem);
      });

      it("should export public EC JWK to SPKI PEM", async () => {
        const pem = await exportPEM(ec.jwk.public);

        const joseKey = await jose.importJWK(ec.jwk.public);
        const josePem = await jose.exportSPKI(joseKey as CryptoKey);
        expect(pem).toEqual(josePem);
      });

      it("should throw when exporting 'oct' JWK to PEM", async () => {
        const octJwk: JWK_oct = { kty: "oct", k: "somekey" };
        await expect(exportPEM(octJwk)).rejects.toThrow(
          "Octet (symmetric) JWKs (kty: 'oct') cannot be exported",
        );
      });

      it("should throw if alg is missing and required for JWK to CryptoKey conversion", async () => {
        const rsaNoAlg = { ...rsa.jwk.public, alg: undefined };
        await expect(exportPEM(rsaNoAlg)).rejects.toThrow("Algorithm (alg) must be provided");
      });

      it("should use options.alg if JWK has no alg", async () => {
        const rsaNoAlg = { ...rsa.jwk.public, alg: undefined };
        const pem = await exportPEM(rsaNoAlg, { alg: "RS256" as JWKPEMAlgorithm });

        const joseKey = await jose.importJWK(rsa.jwk.public);
        const josePem = await jose.exportSPKI(joseKey as CryptoKey);
        expect(pem).toEqual(josePem);
      });

      it("should throw when options.pemFormat forces pkcs8 on a public JWK", async () => {
        // M11 intent check catches the mismatch during the intermediate import —
        // the message points at the JWK/direction conflict, which is clearer than the
        // downstream CryptoKey-type check that used to fire.
        await expect(exportPEM(rsa.jwk.public, { pemFormat: "pkcs8" })).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
        );
      });

      it("should throw when options.pemFormat forces spki on a private JWK", async () => {
        await expect(exportPEM(rsa.jwk.private, { pemFormat: "spki" })).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
        );
      });

      it("should throw for unsupported PEM format", async () => {
        await expect(
          exportPEM(rsa.jwk.public, {
            // @ts-expect-error testing invalid type
            pemFormat: "unsupported",
          }),
        ).rejects.toThrow(
          expect.objectContaining({ name: "JWTError", code: "ERR_JWK_UNSUPPORTED" }),
        );
      });
    });

    describe("deprecated aliases", () => {
      it("importFromPEM forwards to importPEM with pemType preserved", async () => {
        const jwk = await importFromPEM<JWK_RSA_Private>(rsa.pem.pkcs8, "pkcs8", "RS256");
        expect(jwk.kty).toBe("RSA");
        expect(jwk.alg).toBe("RS256");
        expect(jwk.d).toBeDefined();
      });

      it("exportToPEM forwards to exportPEM with pemFormat preserved", async () => {
        const pem = await exportToPEM(rsa.jwk.public, "spki");
        const joseKey = await jose.importJWK(rsa.jwk.public);
        const josePem = await jose.exportSPKI(joseKey as CryptoKey);
        expect(pem).toEqual(josePem);
      });
    });
  });

  describe("JWK import cache", () => {
    // Pure WeakMapJWKCache unit tests — no module-level state, safe to run concurrently.
    it("WeakMapJWKCache.get returns undefined for an unseen key", () => {
      const cache = new WeakMapJWKCache();
      const fakeJwk = { kty: "oct", k: "abc", alg: "HS256" } as any;
      expect(cache.get(fakeJwk, "HS256")).toBeUndefined();
    });

    it("WeakMapJWKCache.set then .get returns the stored CryptoKey", async () => {
      const cache = new WeakMapJWKCache();
      const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, [
        "sign",
        "verify",
      ]);
      const fakeJwk = { kty: "oct", k: "abc", alg: "HS256" } as any;
      cache.set(fakeJwk, "HS256", key);
      expect(cache.get(fakeJwk, "HS256")).toBe(key);
      expect(cache.get(fakeJwk, "HS384")).toBeUndefined();
    });

    it("WeakMapJWKCache stores independent entries per alg", async () => {
      const cache = new WeakMapJWKCache();
      const k256 = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, [
        "sign",
        "verify",
      ]);
      const k384 = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-384" }, true, [
        "sign",
        "verify",
      ]);
      const fakeJwk = { kty: "oct", k: "abc" } as any;
      cache.set(fakeJwk, "HS256", k256);
      cache.set(fakeJwk, "HS384", k384);
      expect(cache.get(fakeJwk, "HS256")).toBe(k256);
      expect(cache.get(fakeJwk, "HS384")).toBe(k384);
    });

    // Module-level state tests — must run sequentially to avoid races between
    // configureJWKCache / clearJWKCache calls in the concurrent parent suite.
    describe.sequential("module-level cache control", () => {
      afterEach(() => clearJWKCache());

      it("default cache returns the same CryptoKey for the same object reference", async () => {
        const jwk = await generateJWK("ES256");
        const first = await importKey(jwk.privateKey, "ES256");
        const second = await importKey(jwk.privateKey, "ES256");
        expect(first).toBe(second);
      });

      it("clearJWKCache() causes a fresh CryptoKey to be created on next call", async () => {
        const jwk = await generateJWK("ES256");
        const before = await importKey(jwk.privateKey, "ES256");
        clearJWKCache();
        const after = await importKey(jwk.privateKey, "ES256");
        expect(before).not.toBe(after);
      });

      it("configureJWKCache(false) disables caching — each call produces a new CryptoKey", async () => {
        configureJWKCache(false);
        const jwk = await generateJWK("ES256");
        const first = await importKey(jwk.privateKey, "ES256");
        const second = await importKey(jwk.privateKey, "ES256");
        expect(first).not.toBe(second);
      });

      it("custom JWKCacheAdapter get/set are called with the correct arguments", async () => {
        const jwk = await generateJWK("RS256");
        const sets: Array<[object, string]> = [];
        configureJWKCache({
          get: (_jwk, _alg) => undefined,
          set: (jwk, alg, _key) => {
            sets.push([jwk, alg]);
          },
        });
        await importKey(jwk.privateKey, "RS256");
        expect(sets.length).toBe(1);
        expect(sets[0]![0]).toBe(jwk.privateKey);
        expect(sets[0]![1]).toBe("RS256");
      });
    });
  });
});
