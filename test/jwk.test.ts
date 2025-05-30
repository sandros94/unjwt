import { describe, it, expect } from "vitest";
import {
  generateKey,
  deriveKeyFromPassword,
  importKey,
  exportKey,
  wrapKey,
  unwrapKey,
  importJWKFromPEM,
  exportJWKToPEM,
} from "../src/jwk";
import {
  isCryptoKey,
  isCryptoKeyPair,
  randomBytes,
  base64UrlDecode,
} from "../src/utils";
import type {
  JWK,
  JWK_oct,
  JWK_EC_Private,
  JWK_EC_Public,
  JWK_RSA_Private,
  JWK_RSA_Public,
  JWKPEMAlgorithm,
} from "../src/types";
import { rsa, ec } from "./keys";

describe.concurrent("JWK Utilities", () => {
  describe("generateKey", () => {
    it("should generate symmetric CryptoKey (HS256)", async () => {
      const key = await generateKey("HS256");
      expect(isCryptoKey(key)).toBe(true);
      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("HMAC");
    });

    it("should generate symmetric JWK (HS256, toJWK: true)", async () => {
      const jwk = await generateKey("HS256", { toJWK: true });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("HS256");
      expect(typeof (jwk as JWK_oct).k).toBe("string");
    });

    it("should generate symmetric CryptoKey (A128KW)", async () => {
      const key = await generateKey("A128KW");
      expect(isCryptoKey(key)).toBe(true);
      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("AES-KW");
    });

    it("should generate symmetric JWK (A128KW, toJWK: true)", async () => {
      const jwk = await generateKey("A128KW", { toJWK: true });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A128KW");
      expect(typeof (jwk as JWK_oct).k).toBe("string");
      expect(base64UrlDecode((jwk as JWK_oct).k, false).length).toBe(16); // 128 bits
    });

    it("should generate asymmetric CryptoKeyPair (RS256)", async () => {
      const keyPair = await generateKey("RS256", { modulusLength: 1024 }); // Use smaller size for tests
      expect(isCryptoKeyPair(keyPair)).toBe(true);
      expect(keyPair.publicKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
      expect(keyPair.privateKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
    });

    it("should generate asymmetric JWK pair (RS256, toJWK: true)", async () => {
      const jwkPair = await generateKey("RS256", {
        toJWK: true,
        modulusLength: 1024,
      });
      expect(jwkPair.privateKey.kty).toBe("RSA");
      expect(jwkPair.privateKey.alg).toBe("RS256");
      expect((jwkPair.privateKey as JWK_RSA_Private).d).toBeDefined();
      expect(jwkPair.publicKey.kty).toBe("RSA");
      expect(jwkPair.publicKey.alg).toBe("RS256");
      // @ts-expect-error d is not part of RSA public key
      expect(jwkPair.publicKey.d).toBeUndefined();
      expect((jwkPair.publicKey as JWK_RSA_Public).n).toBe(
        (jwkPair.privateKey as JWK_RSA_Private).n,
      );
    });

    it("should generate asymmetric CryptoKeyPair (ES256)", async () => {
      const keyPair = await generateKey("ES256");
      expect(isCryptoKeyPair(keyPair)).toBe(true);
      expect(keyPair.publicKey.algorithm.name).toBe("ECDSA");
      expect((keyPair.publicKey.algorithm as EcKeyAlgorithm).namedCurve).toBe(
        "P-256",
      );
    });

    it("should generate asymmetric JWK pair (ES256, toJWK: true)", async () => {
      const jwkPair = await generateKey("ES256", { toJWK: true });
      expect(jwkPair.privateKey.kty).toBe("EC");
      expect(jwkPair.privateKey.alg).toBe("ES256");
      expect((jwkPair.privateKey as JWK_EC_Private).crv).toBe("P-256");
      expect((jwkPair.privateKey as JWK_EC_Private).d).toBeDefined();
      expect(jwkPair.publicKey.kty).toBe("EC");
      expect(jwkPair.publicKey.alg).toBe("ES256");
      expect((jwkPair.publicKey as JWK_EC_Public).crv).toBe("P-256");
      // @ts-expect-error d is not part of EC public key
      expect(jwkPair.publicKey.d).toBeUndefined();
      expect((jwkPair.publicKey as JWK_EC_Public).x).toBe(
        (jwkPair.privateKey as JWK_EC_Private).x,
      );
    });

    it("should generate AES-CBC key as Uint8Array", async () => {
      const keyBytes = await generateKey("A128CBC-HS256");
      expect(keyBytes).toBeInstanceOf(Uint8Array);
      expect(keyBytes.length).toBe(32); // 128 (enc) + 256 (mac) / 8
    });

    it("should generate AES-CBC key as JWK (toJWK: true)", async () => {
      const jwk = await generateKey("A128CBC-HS256", { toJWK: true });
      expect(jwk.kty).toBe("oct");
      expect(typeof (jwk as JWK_oct).k).toBe("string");
      expect(base64UrlDecode((jwk as JWK_oct).k, false).length).toBe(32);
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

    it("should throw for unsupported algorithm", async () => {
      // @ts-expect-error Intentionally passing an unsupported algorithm
      await expect(generateKey("UnsupportedAlg")).rejects.toThrow();
    });
  });

  describe("deriveKeyFromPassword", () => {
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

    it("should import symmetric JWK (oct) to Uint8Array", async () => {
      const jwk: JWK_oct = {
        kty: "oct",
        k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
      };
      const keyBytes = await importKey(jwk);
      expect(keyBytes).toBeInstanceOf(Uint8Array);
      expect(keyBytes.length).toBe(64); // HS512 example key
    });

    // it("should import asymmetric public JWK (RSA) to CryptoKey", async () => {
    //   const jwk: JWK = {
    //     kty: "RSA",
    //     alg: "RS256",
    //     n: "...",
    //     e: "AQAB",
    //     use: "sig",
    //   };
    //   await expect(importKey(jwk, "RS256")).resolves.toBeDefined();
    // });

    // it("should import asymmetric private JWK (EC) to CryptoKey", async () => {
    //   const jwk: JWK = {
    //     kty: "EC",
    //     alg: "ES256",
    //     crv: "P-256",
    //     x: "...",
    //     y: "...",
    //     d: "...",
    //     use: "sig",
    //   }; // Provide actual values
    //   await expect(importKey(jwk, "ES256")).resolves.toBeDefined();
    // });
  });

  describe("exportKey", () => {
    it("should export symmetric CryptoKey to JWK", async () => {
      const cryptoKey = await generateKey("A128GCM");
      const jwk = await exportKey(cryptoKey);
      expect(jwk.kty).toBe("oct");
      expect(typeof (jwk as JWK_oct).k).toBe("string");
      expect(base64UrlDecode((jwk as JWK_oct).k, false).length).toBe(16);
    });

    it("should export asymmetric public CryptoKey to JWK", async () => {
      const { publicKey } = await generateKey("ES256");
      const jwk = await exportKey(publicKey);
      expect(jwk.kty).toBe("EC");
      expect((jwk as JWK_EC_Public).crv).toBe("P-256");
      // @ts-expect-error d is not part of EC public key
      expect(jwk.d).toBeUndefined();
      expect((jwk as JWK_EC_Public).x).toBeDefined();
      expect((jwk as JWK_EC_Public).y).toBeDefined();
    });

    it("should export asymmetric private CryptoKey to JWK", async () => {
      const { privateKey } = await generateKey("ES256");
      const jwk = await exportKey(privateKey);
      expect(jwk.kty).toBe("EC");
      expect((jwk as JWK_EC_Private).crv).toBe("P-256");
      // @ts-expect-error d is not part of EC public key
      expect(jwk.d).toBeDefined();
      expect((jwk as JWK_EC_Private).x).toBeDefined();
      expect((jwk as JWK_EC_Private).y).toBeDefined();
    });

    it("should merge provided partial JWK properties", async () => {
      const cryptoKey = await generateKey("HS256");
      const jwk = await exportKey(cryptoKey, { alg: "HS256", use: "sig" });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("HS256");
      expect(jwk.use).toBe("sig");
      expect(typeof (jwk as JWK_oct).k).toBe("string");
    });
  });

  describe("wrapKey / unwrapKey", async () => {
    const cek = randomBytes(32); // Example: 256-bit key
    const cekCryptoKey = await crypto.subtle.importKey(
      "raw",
      cek,
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"],
    );

    // --- AES-KW ---
    it("should wrap/unwrap with AES-KW (A128KW)", async () => {
      const wrappingKey = await generateKey("A128KW");
      const { encryptedKey } = await wrapKey("A128KW", cek, wrappingKey);
      expect(encryptedKey).toBeInstanceOf(Uint8Array);

      const unwrappedBytes = await unwrapKey(
        "A128KW",
        encryptedKey,
        wrappingKey,
        { returnAs: false },
      );
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey(
        "A128KW",
        encryptedKey,
        wrappingKey,
        { returnAs: true, unwrappedKeyAlgorithm: { name: "AES-GCM" } },
      );
      expect(isCryptoKey(unwrappedKey)).toBe(true);
      expect(unwrappedKey.algorithm.name).toBe("AES-GCM");
    });

    // --- RSA-OAEP ---
    it("should wrap/unwrap with RSA-OAEP", async () => {
      const { publicKey, privateKey } = await generateKey("RSA-OAEP", {
        modulusLength: 2048,
      });
      const { encryptedKey } = await wrapKey(
        "RSA-OAEP",
        cekCryptoKey,
        publicKey,
      ); // Wrap with public
      expect(encryptedKey).toBeInstanceOf(Uint8Array);

      const unwrappedBytes = await unwrapKey(
        "RSA-OAEP",
        encryptedKey,
        privateKey,
        { returnAs: false },
      ); // Unwrap with private
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey(
        "RSA-OAEP",
        encryptedKey,
        privateKey,
        { returnAs: true, unwrappedKeyAlgorithm: { name: "AES-GCM" } },
      );
      expect(isCryptoKey(unwrappedKey)).toBe(true);
      expect(unwrappedKey.algorithm.name).toBe("AES-GCM");
    });

    // --- AES-GCMKW ---
    it("should wrap/unwrap with AES-GCMKW (A128GCMKW)", async () => {
      const wrappingKey = await generateKey("A128GCM", { extractable: true }); // Key for AES-GCMKW must be AES-GCM
      const { encryptedKey, iv, tag } = await wrapKey(
        "A128GCMKW",
        cek,
        wrappingKey,
      );
      expect(encryptedKey).toBeInstanceOf(Uint8Array);
      expect(typeof iv).toBe("string");
      expect(typeof tag).toBe("string");

      const unwrappedBytes = await unwrapKey(
        "A128GCMKW",
        encryptedKey,
        wrappingKey,
        { iv, tag, returnAs: false },
      );
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey(
        "A128GCMKW",
        encryptedKey,
        wrappingKey,
        { iv, tag, returnAs: true, unwrappedKeyAlgorithm: { name: "AES-GCM" } },
      );
      expect(isCryptoKey(unwrappedKey)).toBe(true);
    });

    // --- PBES2 ---
    it("should wrap/unwrap with PBES2", async () => {
      const password = "test-password";
      const p2s = randomBytes(8);
      const p2c = 1000; // Low count for tests
      const {
        encryptedKey,
        p2s: returnedP2s,
        p2c: returnedP2c,
      } = await wrapKey("PBES2-HS256+A128KW", cek, password, { p2s, p2c });
      expect(encryptedKey).toBeInstanceOf(Uint8Array);
      expect(returnedP2s).toBeDefined();
      expect(returnedP2c).toBe(p2c);

      const unwrappedBytes = await unwrapKey(
        "PBES2-HS256+A128KW",
        encryptedKey,
        password,
        { p2s: returnedP2s!, p2c: returnedP2c!, returnAs: false },
      );
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey(
        "PBES2-HS256+A128KW",
        encryptedKey,
        password,
        {
          p2s: returnedP2s!,
          p2c: returnedP2c!,
          returnAs: true,
          unwrappedKeyAlgorithm: { name: "AES-GCM" },
        },
      );
      expect(isCryptoKey(unwrappedKey)).toBe(true);
    });

    it("should throw wrapKey if PBES2 options missing", async () => {
      await expect(
        wrapKey("PBES2-HS256+A128KW", cek, "password"),
      ).rejects.toThrow(
        "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
      );
    });

    it("should throw unwrapKey if AES-GCMKW options missing", async () => {
      const wrappingKey = await generateKey("A128GCM", { extractable: true });
      const { encryptedKey } = await wrapKey("A128GCMKW", cek, wrappingKey);
      await expect(
        unwrapKey("A128GCMKW", encryptedKey, wrappingKey),
      ).rejects.toThrow("AES-GCMKW requires 'iv' and 'tag' options");
    });

    it("should throw unwrapKey if PBES2 options missing", async () => {
      const { encryptedKey } = await wrapKey(
        "PBES2-HS256+A128KW",
        cek,
        "password",
        { p2s: randomBytes(8), p2c: 1000 },
      );
      await expect(
        unwrapKey("PBES2-HS256+A128KW", encryptedKey, "password"),
      ).rejects.toThrow(
        "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
      );
    });

    it("should throw unwrapKey for wrong key/tag", async () => {
      const wrappingKey1 = await generateKey("A128KW");
      const wrappingKey2 = await generateKey("A128KW");
      const { encryptedKey } = await wrapKey("A128KW", cek, wrappingKey1);
      await expect(
        unwrapKey("A128KW", encryptedKey, wrappingKey2),
      ).rejects.toThrow(); // Subtle crypto errors vary, check for any throw
    });

    it("should throw wrapKey for invalid key type", async () => {
      await expect(wrapKey("A128KW", cek, "not-a-key-object")).rejects.toThrow(
        TypeError,
      );
      await expect(wrapKey("RSA-OAEP", cek, randomBytes(32))).rejects.toThrow(); // RSA needs CryptoKey
    });

    it("should throw unwrapKey for invalid key type", async () => {
      const wrappingKey = await generateKey("A128KW");
      const { encryptedKey } = await wrapKey("A128KW", cek, wrappingKey);
      await expect(
        unwrapKey("A128KW", encryptedKey, "not-a-key-object"),
      ).rejects.toThrow(TypeError);
    });
  });

  describe("PEM <-> JWK Conversion", () => {
    describe("importJWKFromPEM", () => {
      it("should import PKCS#8 PEM to JWK (RSA)", async () => {
        const jwk = await importJWKFromPEM(rsa.pem.pkcs8, "pkcs8", "RS256");
        expect(jwk.kty).toBe("RSA");
        expect(jwk.alg).toBe("RS256");
        expect((jwk as JWK_RSA_Private).d).toBeDefined();
      });

      it("should import SPKI PEM to JWK (RSA)", async () => {
        const jwk = await importJWKFromPEM(rsa.pem.spki, "spki", "RS256");
        expect(jwk.kty).toBe("RSA");
        expect(jwk.alg).toBe("RS256");
        expect((jwk as JWK_RSA_Public).n).toBeDefined();
        expect((jwk as JWK_RSA_Public).e).toBeDefined();
        // @ts-expect-error d should not be on public key
        expect(jwk.d).toBeUndefined();
      });

      it("should import X.509 PEM to JWK (RSA Public Key)", async () => {
        const jwk = await importJWKFromPEM(rsa.pem.x509, "x509", "RS256");
        expect(jwk.kty).toBe("RSA");
        expect(jwk.alg).toBe("RS256"); // The 'alg' is from input
        expect((jwk as JWK_RSA_Public).n).toBeDefined();
        // @ts-expect-error d should not be on public key
        expect(jwk.d).toBeUndefined();
      });

      it("should import PKCS#8 PEM to JWK (EC)", async () => {
        const jwk = await importJWKFromPEM(ec.pem.pkcs8, "pkcs8", "ES256");
        expect(jwk.kty).toBe("EC");
        expect(jwk.alg).toBe("ES256");
        expect((jwk as JWK_EC_Private).crv).toBe("P-256");
        expect((jwk as JWK_EC_Private).d).toBeDefined();
      });

      it("should import SPKI PEM to JWK (EC)", async () => {
        const jwk = await importJWKFromPEM(ec.pem.spki, "spki", "ES256");
        expect(jwk.kty).toBe("EC");
        expect(jwk.alg).toBe("ES256");
        expect((jwk as JWK_EC_Public).crv).toBe("P-256");
        expect((jwk as JWK_EC_Public).x).toBeDefined();
        // @ts-expect-error d should not be on public key
        expect(jwk.d).toBeUndefined();
      });

      it("should merge jwkExtras", async () => {
        const jwk = await importJWKFromPEM(
          rsa.pem.spki,
          "spki",
          "RS256",
          undefined,
          {
            kid: "test-kid",
            use: "enc",
          },
        );
        expect(jwk.kid).toBe("test-kid");
        expect(jwk.use).toBe("enc"); // Overrides any 'use' from the key itself if exportKey doesn't prioritize input jwkExtras
        expect(jwk.alg).toBe("RS256"); // Should still be set from the 'alg' param
      });

      it("should throw for unsupported PEM type", async () => {
        await expect(
          // @ts-expect-error testing invalid type
          importJWKFromPEM(rsa.pem.spki, "unsupported", "RS256"),
        ).rejects.toThrow(TypeError);
      });
    });

    describe("exportJWKToPEM", () => {
      it("should export private RSA JWK to PKCS#8 PEM", async () => {
        const pem = await exportJWKToPEM(rsa.jwk.private, "pkcs8");

        // TODO: beautify this garbage
        expect(`${pem}\n`.replace(/\\n/g, "")).toMatch(
          rsa.pem.pkcs8.replace(/\\n/g, ""),
        );
      });

      it("should export public RSA JWK to SPKI PEM", async () => {
        const pem = await exportJWKToPEM(rsa.jwk.public, "spki");

        // TODO: beautify this garbage
        expect(`${pem}\n`.replace(/\\n/g, "")).toMatch(
          rsa.pem.spki.replace(/\\n/g, ""),
        );
      });

      it("should export private EC JWK to PKCS#8 PEM", async () => {
        const pem = await exportJWKToPEM(ec.jwk.private, "pkcs8");

        // TODO: beautify this garbage
        expect(`${pem}\n`.replace(/\\n/g, "")).toMatch(
          ec.pem.pkcs8.replace(/\\n/g, ""),
        );
      });

      it("should export public EC JWK to SPKI PEM", async () => {
        const pem = await exportJWKToPEM(ec.jwk.public, "spki");

        // TODO: beautify this garbage
        expect(`${pem}\n`.replace(/\\n/g, "")).toMatch(
          ec.pem.spki.replace(/\\n/g, ""),
        );
      });

      it("should throw when exporting 'oct' JWK to PEM", async () => {
        const octJwk: JWK_oct = { kty: "oct", k: "somekey" };
        await expect(exportJWKToPEM(octJwk, "pkcs8")).rejects.toThrow(
          "Octet (symmetric) JWKs (kty: 'oct') cannot be exported",
        );
      });

      it("should throw if alg is missing and required for JWK to CryptoKey conversion", async () => {
        const rsaNoAlg: JWK = { ...rsa.jwk.public, alg: undefined };
        await expect(exportJWKToPEM(rsaNoAlg, "spki")).rejects.toThrow(
          "Algorithm (alg) must be provided",
        );
      });
      it("should use algForCryptoKeyImport if JWK has no alg", async () => {
        const rsaNoAlg: JWK = { ...rsa.jwk.public, alg: undefined };
        const pem = await exportJWKToPEM(
          rsaNoAlg,
          "spki",
          "RS256" as JWKPEMAlgorithm,
        );

        // TODO: beautify this garbage
        expect(`${pem}\n`.replace(/\\n/g, "")).toMatch(
          rsa.pem.spki.replace(/\\n/g, ""),
        );
      });

      it("should throw when exporting public JWK as PKCS#8", async () => {
        await expect(exportJWKToPEM(rsa.jwk.public, "pkcs8")).rejects.toThrow(
          "Only 'private' type CryptoKeys can be exported to PKCS8",
        );
      });

      it("should throw when exporting private JWK as SPKI", async () => {
        await expect(exportJWKToPEM(rsa.jwk.private, "spki")).rejects.toThrow(
          "Only 'public' type CryptoKeys can be exported to SPKI",
        );
      });

      it("should throw for unsupported PEM format", async () => {
        await expect(
          // @ts-expect-error testing invalid type
          exportJWKToPEM(rsa.jwk.public, "unsupported"),
        ).rejects.toThrow(TypeError);
      });
    });
  });
});
