import { createHash } from "node:crypto";
import { describe, it, expect, expectTypeOf, beforeAll, afterEach } from "vitest";
import { secureRandomBytes } from "unsecure";
import { textEncoder } from "unsecure/utils";
import {
  base64UrlStringify,
  base64UrlParse,
  base64Stringify,
  base64Parse,
} from "../src/core/utils/base64.ts";
import * as jose from "jose";
import {
  generateKey,
  generateJWK,
  deriveKeyFromPassword,
  deriveJWKFromPassword,
  importKey,
  exportJWK,
  wrapKey,
  unwrapKey,
  deriveSharedSecret,
  importPEM,
  exportPEM,
  getJWKsFromSet,
  thumbprint,
  toPublicJWK,
  WeakMapJWKCache,
  configureJWKCache,
  clearJWKCache,
  JWTError,
  isJWTError,
  isUnsecureError,
} from "../src/core/jwk.ts";
import { sign, verify } from "../src/core/jws.ts";
import { encrypt, decrypt } from "../src/core/jwe.ts";
import { isCryptoKey, isCryptoKeyPair } from "../src/core/utils/index.ts";
import type {
  JWEEncryptJWK,
  JWK,
  JWKSet,
  JWK_oct,
  JWK_EC_Private,
  JWK_EC_Public,
  JWK_RSA_Private,
  JWK_RSA_Public,
  JWK_OKP_Private,
  JWK_OKP_Public,
  JWKPEMAlgorithm,
  JWK_OKP_SIGN,
  JWK_ECDH_ES,
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
  GenerateKeyReturn,
  GenerateJWKReturn,
  GeneratedKeyMap,
  GeneratedJWKMap,
  ImportedKey,
  ImportedKeyMap,
} from "../src/core/types/index.ts";
import { rsa, ec } from "./keys.ts";

const STRING_KEY_MESSAGE = "Key must be a JWK, CryptoKey or Uint8Array, not a string.";
import { deriveECDHESKey, encryptRSAES, bitLengthCEK } from "../src/core/_crypto/index.ts";

describe.concurrent("JWK Utilities", () => {
  describe("generateKey", () => {
    it("should generate symmetric CryptoKey (HS256)", async () => {
      const key = await generateKey("HS256");
      expect(isCryptoKey(key)).toBe(true);
      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("HMAC");

      const jwk = await exportJWK(key);
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

      const jwk = await exportJWK(key);
      await expect(jose.importJWK({ ...jwk, alg: "A128KW" })).resolves.toBeInstanceOf(Object);
    });

    it("should generate symmetric JWK (A128KW, toJWK: true)", async () => {
      const jwk = await generateKey("A128KW", { toJWK: true });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A128KW");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlParse(jwk.k, { returnAs: "uint8array" }).length).toBe(16); // 128 bits

      await expect(jose.importJWK(jwk)).resolves.toBeInstanceOf(Object);
    });

    it("should generate asymmetric CryptoKeyPair (RS256)", async () => {
      const keyPair = await generateKey("RS256", { modulusLength: 2048 });
      expect(isCryptoKeyPair(keyPair)).toBe(true);
      expect(keyPair.publicKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
      expect(keyPair.privateKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");

      const jwk = await exportJWK(keyPair.privateKey);
      await expect(jose.importJWK({ ...jwk, alg: "RS256" })).resolves.toBeInstanceOf(Object);
    });

    it("should generate asymmetric JWK pair (RS256, toJWK: true)", async () => {
      const jwkPair = await generateKey("RS256", {
        toJWK: true,
        modulusLength: 2048,
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

      const jwk = await exportJWK(keyPair.privateKey);
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
      expect(base64UrlParse(jwk.k, { returnAs: "uint8array" }).length).toBe(32);

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

    it.each(["Ed448", "X448"])("refuses to generate an EdDSA key on %s", async (namedCurve) => {
      const error = await generateKey("EdDSA", { namedCurve: namedCurve as never }).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_UNSUPPORTED")).toBe(true);
    });

    it("refuses to generate an ECDH-ES key on X448", async () => {
      const error = await generateJWK("ECDH-ES", { namedCurve: "X448" as never }).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_UNSUPPORTED")).toBe(true);
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
      ).rejects.toThrow("Unsupported namedCurve, expected Ed25519");
    });

    it("should throw for unsupported ECDH-ES namedCurve", async () => {
      await expect(
        // @ts-expect-error Intentionally passing an unsupported namedCurve
        generateKey("ECDH-ES", { namedCurve: "P-999" }),
      ).rejects.toThrow("Unsupported namedCurve, expected P-256, P-384, P-521 or X25519");
    });

    it("should throw for unsupported algorithm", async () => {
      // @ts-expect-error Intentionally passing an unsupported algorithm
      await expect(generateKey("UnsupportedAlg")).rejects.toThrow(/unsupported/i);
    });
  });

  describe("generateJWK", () => {
    it("should generate symmetric JWK (HS256)", async () => {
      const jwk = await generateJWK("HS256");
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("HS256");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlParse(jwk.k, { returnAs: "uint8array" }).length).toBe(64);
    });
  });

  describe("generated JWK members", () => {
    it("carries no ext and no key_ops unless keyUsage is given", async () => {
      const secret = await generateJWK("HS256");
      const pair = await generateJWK("ES256");
      const composite = await generateKey("A256CBC-HS512", { toJWK: true });
      const derived = await deriveJWKFromPassword("pw", {
        alg: "PBES2-HS256+A128KW",
        salt: "saltsaltsalt",
        iterations: 1000,
      });
      const fromPEM = await importPEM(await exportPEM(pair.privateKey), "ES256");
      for (const jwk of [secret, pair.privateKey, pair.publicKey, composite, derived, fromPEM]) {
        expect(jwk).not.toHaveProperty("ext");
        expect(jwk).not.toHaveProperty("key_ops");
      }
      expect(secret.alg).toBe("HS256");
      expect(fromPEM.alg).toBe("ES256");
      await expect(
        verify(await sign({ a: 1 }, pair.privateKey), pair.publicKey),
      ).resolves.toBeDefined();
    });

    it("emits key_ops for the usages an explicit keyUsage left", async () => {
      const pair = await generateJWK("ES256", { keyUsage: ["sign", "verify"] });
      expect(pair.privateKey.key_ops).toEqual(["sign"]);
      expect(pair.publicKey.key_ops).toEqual(["verify"]);
      expect(toPublicJWK(pair.privateKey)).toEqual(pair.publicKey);
      const secret = await generateKey("A256GCM", { toJWK: true, keyUsage: ["decrypt"] });
      expect(secret.key_ops).toEqual(["decrypt"]);
      const derived = await deriveJWKFromPassword("pw", {
        alg: "PBES2-HS256+A128KW",
        salt: "saltsaltsalt",
        iterations: 1000,
        keyUsage: ["unwrapKey"],
      });
      expect(derived.key_ops).toEqual(["unwrapKey"]);
    });
  });

  describe("toPublicJWK", () => {
    const pairAlgorithms = [
      "RS256",
      "PS256",
      "RSA-OAEP-256",
      "ES256",
      "ES512",
      "Ed25519",
      "ECDH-ES",
      "ECDH-ES+A128KW",
    ] as const;

    it.each(pairAlgorithms)("equals the generated public half for %s", async (alg) => {
      const pair = await generateJWK(alg, { use: "sig", x5u: "https://example.com/k" });
      const derived = toPublicJWK(pair.privateKey);
      expect(derived).toEqual(pair.publicKey);
      expect(derived).not.toBe(pair.privateKey);
      expect(derived).not.toHaveProperty(["d", "p", "q", "dp", "dq", "qi", "oth"]);
    });

    it("equals the generated public half for X25519", async () => {
      const pair = await generateJWK("ECDH-ES", { namedCurve: "X25519" });
      const derived = toPublicJWK(pair.privateKey);
      expect(derived).toEqual(pair.publicKey);
      expect(derived).not.toBe(pair.privateKey);
    });

    it("verifies and encrypts with the derived half", async () => {
      const signer = await generateJWK("ES256");
      const token = await sign({ sub: "u1" }, signer.privateKey);
      const { payload } = await verify(token, toPublicJWK(signer.privateKey));
      expect(payload).toEqual({ sub: "u1" });

      const recipient = await generateJWK("RSA-OAEP-256");
      const jwe = await encrypt({ secret: 1 }, toPublicJWK(recipient.privateKey), {
        enc: "A256GCM",
      });
      expect((await decrypt(jwe, recipient.privateKey)).payload).toEqual({ secret: 1 });
    });

    it('drops a "k" member', async () => {
      const { publicKey } = await generateJWK("ES256");
      const derived = toPublicJWK({ ...publicKey, k: "c2VjcmV0" } as JWK_EC_Public);
      expect(derived).toEqual(publicKey);
      expect(derived).not.toHaveProperty("k");
    });

    it("returns an equal copy of a public JWK", async () => {
      const { publicKey } = await generateJWK("ES256");
      const copy = toPublicJWK(publicKey);
      expect(copy).toEqual(publicKey);
      expect(copy).not.toBe(publicKey);
    });

    it("leaves key_ops absent when the input has none and ignores unknown operations", () => {
      const { key_ops: _ops, ...bare } = ec.jwk.private;
      expect(toPublicJWK(bare)).not.toHaveProperty("key_ops");
      expect(
        toPublicJWK({ ...ec.jwk.private, key_ops: ["sign", "constructor", "sign"] as KeyUsage[] })
          .key_ops,
      ).toEqual(["verify"]);
    });

    it("drops prototype-polluting members", () => {
      const polluted = JSON.parse(
        `${JSON.stringify(ec.jwk.private).slice(0, -1)},"__proto__":{"polluted":true}}`,
      ) as JWK_EC_Private;
      const derived = toPublicJWK(polluted);
      expect(Object.hasOwn(derived, "__proto__")).toBe(false);
      expect((derived as { polluted?: unknown }).polluted).toBeUndefined();
    });

    it("refuses an oct JWK, a non-JWK, and a JWK without its public members", async () => {
      const secret = await generateJWK("HS256");
      // @ts-expect-error an oct JWK has no public half
      expect(() => toPublicJWK(secret)).toThrow(
        expect.objectContaining({
          code: "ERR_JWK_INVALID",
          message: "An oct JWK has no public half.",
        }),
      );
      // @ts-expect-error not a JWK
      expect(() => toPublicJWK("nope")).toThrow(
        expect.objectContaining({
          code: "ERR_JWK_INVALID",
          message: "toPublicJWK expects an asymmetric JWK.",
        }),
      );
      expect(() =>
        toPublicJWK({ kty: "EC", crv: "P-256", d: "x" } as unknown as JWK_EC_Private),
      ).toThrow(
        expect.objectContaining({
          code: "ERR_JWK_INVALID",
          message: "EC JWK lacks the public members of its key type.",
        }),
      );
    });
  });

  describe("deriveKeyFromPassword/deriveJWKFromPassword", () => {
    const password = "password123";
    const salt = secureRandomBytes(16);
    const iterations = 2000; // Keep low for tests

    it("should derive CryptoKey (PBES2-HS256+A128KW)", async () => {
      const key = await deriveKeyFromPassword(password, {
        alg: "PBES2-HS256+A128KW",
        salt,
        iterations,
      });
      expect(isCryptoKey(key)).toBe(true);
      expect(key.algorithm.name).toBe("AES-KW");
      expect((key.algorithm as AesKeyAlgorithm).length).toBe(128);
      expect(key.extractable).toBe(false); // Default
    });

    it("should derive JWK (PBES2-HS384+A192KW, toJWK: true)", async () => {
      const jwk = await deriveKeyFromPassword(password, {
        alg: "PBES2-HS384+A192KW",
        salt,
        iterations,
        toJWK: true,
      });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A192KW");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlParse(jwk.k, { returnAs: "uint8array" }).length).toBe(24); // 192 bits
    });

    it("should derive JWK with custom `kid`", async () => {
      const kid = "custom-key-id";
      const jwk = await deriveJWKFromPassword(password, {
        alg: "PBES2-HS256+A128KW",
        salt,
        iterations,
        kid,
      });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A128KW");
      expect(jwk.kid).toBe(kid);
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlParse(jwk.k, { returnAs: "uint8array" }).length).toBe(16); // 128 bits
      expectTypeOf(jwk.alg).toEqualTypeOf<"A128KW">();
      expectTypeOf(jwk.kid).toEqualTypeOf<string>();
      expectTypeOf(jwk).toExtend<JWEEncryptJWK>();
    });

    it("types the derived JWK by its PBES2 alg, without `kid` when `kid: false`", async () => {
      const jwk = await deriveJWKFromPassword(password, {
        alg: "PBES2-HS512+A256KW",
        salt,
        iterations,
        kid: false,
      });
      expect(jwk.alg).toBe("A256KW");
      expect(jwk.kid).toBeUndefined();
      expectTypeOf(jwk.alg).toEqualTypeOf<"A256KW">();
      expectTypeOf(jwk.kid).toEqualTypeOf<string | undefined>();
      expectTypeOf(() =>
        deriveJWKFromPassword(password, { alg: "PBES2-HS384+A192KW", salt, iterations }),
      ).returns.resolves.toExtend<{ kty: "oct"; alg: "A192KW"; kid: string }>();
    });

    it("should respect extractable and keyUsage options", async () => {
      const key = await deriveKeyFromPassword(password, {
        alg: "PBES2-HS512+A256KW",
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
        deriveKeyFromPassword(password, {
          alg: "PBES2-HS256+A128KW",
          salt: secureRandomBytes(7),
          iterations,
        }),
      ).rejects.toThrow("must be 8 or more octets");
    });

    it("should throw for invalid iterations", async () => {
      await expect(
        deriveKeyFromPassword(password, { alg: "PBES2-HS256+A128KW", salt, iterations: 0 }),
      ).rejects.toThrow("must be a positive integer");
    });

    it.each([[1], [1.5], [999], [1000.5], ["2000"], [undefined]])(
      "refuses %j iterations, as PBES2 encryption does",
      async (count) => {
        const error = await deriveKeyFromPassword(password, {
          alg: "PBES2-HS256+A128KW",
          salt,
          iterations: count as never,
        }).catch((e) => e);
        expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
        expect(error.message).toContain('"iterations"');
      },
    );

    it("derives at the iteration floor and above the encryption default", async () => {
      for (const count of [1000, 600_001]) {
        await expect(
          deriveKeyFromPassword(password, { alg: "PBES2-HS256+A128KW", salt, iterations: count }),
        ).resolves.toSatisfy(isCryptoKey);
      }
    });

    it("refuses a salt shorter than 8 octets as an option error", async () => {
      const error = await deriveKeyFromPassword(password, {
        alg: "PBES2-HS256+A128KW",
        salt: "short",
        iterations,
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toContain('"salt"');
    });

    it("should derive JWK with custom `kid`", async () => {
      const kid = "custom-key-id";
      const jwk = await deriveJWKFromPassword(password, {
        alg: "PBES2-HS256+A128KW",
        salt,
        iterations,
        kid,
      });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("A128KW");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlParse(jwk.k, { returnAs: "uint8array" }).length).toBe(16); // 128 bits
    });
  });

  describe("importKey", () => {
    it("rejects a string key, pointing at the PEM and secret alternatives", async () => {
      // @ts-expect-error strings are not key material; exercises the runtime guard
      const error = await importKey("-----BEGIN PUBLIC KEY-----").catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe(STRING_KEY_MESSAGE);
    });

    it("should return CryptoKey if input is CryptoKey", async () => {
      const originalKey = await generateKey("HS256");
      const importedKey = await importKey(originalKey);
      expect(importedKey).toBe(originalKey);
    });

    it("should return Uint8Array if input is Uint8Array", async () => {
      const originalBytes = secureRandomBytes(32);
      const importedBytes = await importKey(originalBytes);
      expect(importedBytes).toBe(originalBytes);
    });

    it("should return cached CryptoKey for same asymmetric JWK object reference", async () => {
      const { privateKey } = await generateKey("ES256");
      const jwk = await exportJWK(privateKey);
      // Import same object twice — second call hits the WeakMap cache
      const key1 = await importKey(jwk, "ES256");
      const key2 = await importKey(jwk, "ES256");
      expect(key1).toBe(key2);
    });

    it('rejects a "k" member on a non-oct JWK', async () => {
      const { k } = await generateJWK("HS256");
      const key = { kty: "EC", alg: "HS256", k } as unknown as JWK;
      const error = await importKey(key, "HS256").catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe('JWK "k" is defined only for "oct" keys, not "EC".');

      const withPublicMembers = { ...(await generateJWK("ES256")).publicKey, k } as JWK;
      await expect(importKey(withPublicMembers, "ES256")).rejects.toMatchObject({
        code: "ERR_JWK_INVALID",
      });
    });

    it("should import symmetric JWK (oct) to Uint8Array", async () => {
      const jwk: JWK_oct = {
        kty: "oct",
        k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
      };
      const keyBytes = await importKey(jwk);
      expect(keyBytes).toBeInstanceOf(Uint8Array);
      expect(keyBytes.length).toBe(64); // HS512 example key

      const decodedByKey = base64UrlParse(jwk.k, { returnAs: "uint8array" });
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

    describe("oct key length validation", () => {
      const shortK = base64UrlStringify(secureRandomBytes(8));

      it("rejects an undersized HS256 key (RFC 7518 §3.2)", async () => {
        await expect(importKey({ kty: "oct", k: shortK, alg: "HS256" })).rejects.toThrow(
          "HS256 requires a key of at least 32 bytes",
        );
      });

      it("accepts an HS256 key at the minimum size", async () => {
        const k = base64UrlStringify(secureRandomBytes(32));
        const bytes = await importKey({ kty: "oct", k, alg: "HS256" });
        expect(bytes).toBeInstanceOf(Uint8Array);
      });

      it("rejects a wrong-size A128KW key", async () => {
        await expect(importKey({ kty: "oct", k: shortK, alg: "A128KW" })).rejects.toThrow(
          "A128KW requires a key of exactly 16 bytes",
        );
      });

      it("rejects a wrong-size A256GCMKW key", async () => {
        await expect(importKey({ kty: "oct", k: shortK, alg: "A256GCMKW" })).rejects.toThrow(
          "A256GCMKW requires a key of exactly 32 bytes",
        );
      });

      it("rejects a wrong-size composite A256CBC-HS512 key", async () => {
        await expect(importKey({ kty: "oct", k: shortK, alg: "A256CBC-HS512" })).rejects.toThrow(
          "A256CBC-HS512 requires a key of exactly 64 bytes",
        );
      });

      it("rejects an undersized HMAC key via asCryptoKey", async () => {
        await expect(
          importKey(
            { kty: "oct", k: shortK },
            {
              asCryptoKey: true,
              algorithm: { name: "HMAC", hash: "SHA-256" },
              usage: ["sign", "verify"],
            },
          ),
        ).rejects.toThrow("HMAC with SHA-256 requires a key of at least 32 bytes");
      });

      it("skips validation when no alg is present", async () => {
        const bytes = await importKey({ kty: "oct", k: shortK });
        expect(bytes).toBeInstanceOf(Uint8Array);
        expect((bytes as Uint8Array).length).toBe(8);
      });
    });

    describe("declared algorithm authority", () => {
      it("rejects a JWK whose alg differs from the operation's", async () => {
        const { privateKey } = await generateJWK("ECDH-ES", { namedCurve: "P-256" });
        const error = await importKey(privateKey, "ES256").catch((e) => e);
        expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
        expect(error.message).toBe('JWK "alg" is "ECDH-ES" but the operation requires "ES256".');
      });

      it("rejects a symmetric JWK borrowed for another algorithm", async () => {
        const jwk = await generateJWK("A128GCM");
        const error = await importKey(jwk, "HS512").catch((e) => e);
        expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
        expect(error.message).toBe('JWK "alg" is "A128GCM" but the operation requires "HS512".');
      });

      it("accepts a JWK whose alg matches, and one that declares none", async () => {
        const { privateKey } = await generateJWK("ES256");
        await expect(importKey(privateKey, "ES256")).resolves.toBeInstanceOf(CryptoKey);

        const { alg: _alg, ...algLess } = privateKey;
        await expect(importKey(algLess as JWK_EC_Private, "ES256")).resolves.toBeInstanceOf(
          CryptoKey,
        );
      });

      it('lets a content-encryption oct JWK serve "dir" — the one symmetric role mapping', async () => {
        const jwk = await generateJWK("A256GCM");
        await expect(importKey(jwk, "dir")).resolves.toBeInstanceOf(Uint8Array);
      });

      it("measures oct key length against the operation's algorithm", async () => {
        const k = base64UrlStringify(secureRandomBytes(16));
        await expect(importKey({ kty: "oct", k }, "HS512")).rejects.toThrow(
          "HS512 requires a key of at least 64 bytes",
        );
      });
    });

    describe('"key_ops" and "ext" on the JWK', () => {
      it("intersects key_ops with the usages the operation needs", async () => {
        const { privateKey } = await generateJWK("ES256");
        const key = await importKey({ ...privateKey, key_ops: ["sign", "verify"] }, "ES256");
        expect(key.usages).toEqual(["sign"]);
      });

      it("rejects key_ops that permit none of them", async () => {
        const { privateKey } = await generateJWK("ES256");
        for (const key_ops of [[], ["verify"]] as KeyUsage[][]) {
          const error = await importKey({ ...privateKey, key_ops }, "ES256").catch((e) => e);
          expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
          expect(error.message).toBe('JWK "key_ops" does not permit sign.');
        }
      });

      it("keeps private key material non-extractable however the JWK marks ext", async () => {
        const { privateKey, publicKey } = await generateJWK("ES256");
        const priv = await importKey({ ...privateKey, ext: true }, "ES256");
        expect(priv.extractable).toBe(false);

        const pub = await importKey(publicKey, "ES256");
        expect(pub.extractable).toBe(true);
      });

      it('honours a JWK "ext": false on a public key', async () => {
        const { publicKey } = await generateJWK("ES256");
        const key = await importKey({ ...publicKey, ext: false }, "ES256");
        expect(key.extractable).toBe(false);
      });

      it("imports an extractable key when the caller asks for one", async () => {
        const { privateKey } = await generateJWK("ES256");
        const key = await importKey(privateKey, {
          alg: "ES256",
          extractable: true,
        });
        expect(key.extractable).toBe(true);
      });
    });

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
        await expect(importKey(privateKey, { expect: "public" })).rejects.toThrow(
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

  describe("exportJWK", () => {
    it("writes the key, not the CryptoKey: no ext, no key_ops", async () => {
      const pair = await generateKey("ES256", { keyUsage: ["sign", "verify"] });
      for (const [key, alg] of [
        [pair.privateKey, "ES256"],
        [pair.publicKey, "ES256"],
        [await generateKey("HS256"), "HS256"],
      ] as const) {
        const jwk = await exportJWK(key);
        expect(jwk).not.toHaveProperty("ext");
        expect(jwk).not.toHaveProperty("key_ops");
        await expect(importKey(jwk, alg)).resolves.toBeDefined();
      }
    });

    it("should export symmetric CryptoKey to JWK", async () => {
      const cryptoKey = await generateKey("A128GCM");
      const jwk = await exportJWK<JWK_oct>(cryptoKey);
      expect(jwk.kty).toBe("oct");
      expect(typeof jwk.k).toBe("string");
      expect(base64UrlParse(jwk.k, { returnAs: "uint8array" }).length).toBe(16);

      await expect(jose.importJWK(jwk)).resolves.toBeInstanceOf(Object);
    });

    it("should export asymmetric public CryptoKey to JWK", async () => {
      const { publicKey } = await generateKey("ES256");
      const jwk = await exportJWK<JWK_EC_Public>(publicKey);
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
      const jwk = await exportJWK<JWK_EC_Private>(privateKey);
      expect(jwk.kty).toBe("EC");
      expect(jwk.crv).toBe("P-256");
      expect(jwk.d).toBeDefined();
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();

      await expect(jose.importJWK(jwk, "ES256")).resolves.toBeInstanceOf(Object);
    });

    it("should merge provided partial JWK properties", async () => {
      const cryptoKey = await generateKey("HS256");
      const jwk = await exportJWK<JWK_oct>(cryptoKey, { use: "sig" });
      expect(jwk.kty).toBe("oct");
      expect(jwk.alg).toBe("HS256"); // carried through from Web Crypto export
      expect(jwk.use).toBe("sig");
      expect(typeof jwk.k).toBe("string");

      await expect(jose.importJWK(jwk)).resolves.toBeInstanceOf(Object);
    });
  });

  describe("wrapKey / unwrapKey", async () => {
    const cek = secureRandomBytes(32); // Example: 256-bit key
    const cekCryptoKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, true, [
      "encrypt",
      "decrypt",
    ]);

    it("should wrap/unwrap with AES-KW (A128KW)", async () => {
      const wrappingKey = await generateKey("A128KW");
      const { encryptedKey } = await wrapKey(cek, wrappingKey, { alg: "A128KW" });
      expect(encryptedKey).toBeInstanceOf(Uint8Array);

      const unwrappedBytes = await unwrapKey(encryptedKey, wrappingKey, {
        alg: "A128KW",
        format: "raw",
      });
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey(encryptedKey, wrappingKey, {
        alg: "A128KW",
        format: "cryptokey",
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(isCryptoKey(unwrappedKey)).toBe(true);
      expect(unwrappedKey.algorithm.name).toBe("AES-GCM");
    });

    it("should wrap/unwrap with RSA-OAEP", async () => {
      const { publicKey, privateKey } = await generateKey("RSA-OAEP", {
        modulusLength: 2048,
      });
      const { encryptedKey } = await wrapKey(cekCryptoKey, publicKey, { alg: "RSA-OAEP" });
      expect(encryptedKey).toBeInstanceOf(Uint8Array);

      const unwrappedKey = await unwrapKey(encryptedKey, privateKey, {
        alg: "RSA-OAEP",
        format: "cryptokey",
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(isCryptoKey(unwrappedKey)).toBe(true);
      const exportedUnwrapped = await exportJWK<JWK_oct>(unwrappedKey);
      const exportedOriginal = await exportJWK<JWK_oct>(cekCryptoKey);
      expect(exportedUnwrapped.k).toEqual(exportedOriginal.k);
    });

    describe("RSA-OAEP variants", () => {
      const rsaAlgorithms = ["RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512"] as const;
      type RSAAlg = (typeof rsaAlgorithms)[number];
      const rsaKeyPairs: Partial<Record<RSAAlg, CryptoKeyPair>> = {};

      beforeAll(async () => {
        await Promise.all(
          rsaAlgorithms.map(async (alg) => {
            rsaKeyPairs[alg] = await generateKey(alg, {
              modulusLength: 2048,
            });
          }),
        );
      });

      it.each(rsaAlgorithms)(
        "should return raw CEK bytes for %s when format is 'raw'",
        async (alg) => {
          const pair = rsaKeyPairs[alg]!;
          const cekBytes = secureRandomBytes(32);
          const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

          const unwrapped = await unwrapKey(encryptedKey, pair.privateKey, {
            alg,
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
          const cekBytes = secureRandomBytes(32);
          const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

          const unwrappedKey = await unwrapKey(encryptedKey, pair.privateKey, {
            alg,
            enc: "A256GCM",
          });

          expect(isCryptoKey(unwrappedKey)).toBe(true);
          expect(unwrappedKey.algorithm.name).toBe("AES-GCM");
        },
      );

      it("should infer AES-GCM CryptoKey from CEK length when enc and unwrappedKeyAlgorithm are absent", async () => {
        const alg: RSAAlg = "RSA-OAEP";
        const pair = rsaKeyPairs[alg]!;
        const cekBytes = secureRandomBytes(32); // 256 bits → infers AES-GCM-256
        const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

        const unwrappedKey = await unwrapKey(encryptedKey, pair.privateKey, {
          alg,
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
        const cekBytes = secureRandomBytes(20); // 160 bits — not 128/192/256 → inferAesImportAlgorithm returns undefined
        const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

        await expect(
          unwrapKey(encryptedKey, pair.privateKey, {
            alg,
            format: "cryptokey",
            // no enc, no unwrappedKeyAlgorithm — inferAesImportAlgorithm returns undefined
          }),
        ).rejects.toThrow(/Cannot infer the RSA-OAEP unwrapped key algorithm/i);
      });

      it("should handle composite CBC CEK via RSA-OAEP-256", async () => {
        const alg: RSAAlg = "RSA-OAEP-256";
        const pair = rsaKeyPairs[alg]!;
        const cekBytes = secureRandomBytes(bitLengthCEK("A256CBC-HS512") >> 3);
        const encryptedKey = await encryptRSAES(alg, pair.publicKey, cekBytes);

        await expect(
          unwrapKey(encryptedKey, pair.privateKey, { alg, enc: "A256CBC-HS512" }),
        ).rejects.toThrow(/Cannot infer the RSA-OAEP unwrapped key algorithm/i);

        const unwrapped = await unwrapKey(encryptedKey, pair.privateKey, {
          alg,
          enc: "A256CBC-HS512",
          format: "raw",
        });

        expect(unwrapped).toBeInstanceOf(Uint8Array);
        expect(unwrapped).toEqual(cekBytes);
      });
    });

    it("should wrap/unwrap with AES-GCMKW (A128GCMKW)", async () => {
      // AES-GCMKW uses an AES-GCM key to wrap another AES-GCM CEK.
      const wrappingKey = await generateKey("A128GCM", { extractable: true });
      const { encryptedKey, iv, tag } = await wrapKey(cek, wrappingKey, { alg: "A128GCMKW" });
      expect(encryptedKey).toBeInstanceOf(Uint8Array);
      expect(typeof iv).toBe("string");
      expect(typeof tag).toBe("string");

      const unwrappedBytes = await unwrapKey(encryptedKey, wrappingKey, {
        alg: "A128GCMKW",
        iv,
        tag,
        format: "raw",
      });
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey(encryptedKey, wrappingKey, {
        alg: "A128GCMKW",
        iv,
        tag,
        format: "cryptokey",
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(isCryptoKey(unwrappedKey)).toBe(true);
    });

    it("should wrap/unwrap with PBES2", async () => {
      const password = "test-password";
      const p2s = secureRandomBytes(16);
      const p2c = 2000;
      const {
        encryptedKey,
        p2s: returnedP2s,
        p2c: returnedP2c,
      } = await wrapKey(cek, password, { alg: "PBES2-HS256+A128KW", p2s, p2c });

      expect(encryptedKey).toBeInstanceOf(Uint8Array);
      expect(returnedP2s).toBeDefined();
      expect(returnedP2c).toBe(p2c);

      const unwrappedBytes = await unwrapKey(encryptedKey, password, {
        alg: "PBES2-HS256+A128KW",
        p2s: returnedP2s,
        p2c: returnedP2c,
        format: "raw",
      });
      expect(unwrappedBytes).toEqual(cek);

      const unwrappedKey = await unwrapKey(encryptedKey, password, {
        alg: "PBES2-HS256+A128KW",
        p2s: returnedP2s,
        p2c: returnedP2c,
        format: "cryptokey",
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(isCryptoKey(unwrappedKey)).toBe(true);
    });

    it("should throw wrapKey if PBES2 options missing", async () => {
      await expect(wrapKey(cek, "password", { alg: "PBES2-HS256+A128KW" })).rejects.toThrow(
        "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
      );
    });

    it("should throw unwrapKey if AES-GCMKW options missing", async () => {
      const wrappingKey = await generateKey("A128GCM", { extractable: true });
      const { encryptedKey } = await wrapKey(cek, wrappingKey, { alg: "A128GCMKW" });
      await expect(unwrapKey(encryptedKey, wrappingKey, { alg: "A128GCMKW" })).rejects.toThrow(
        "AES-GCMKW requires 'iv' and 'tag' options",
      );
    });

    it("should throw unwrapKey if PBES2 options missing", async () => {
      const { encryptedKey } = await wrapKey(cek, "password", {
        alg: "PBES2-HS256+A128KW",
        p2s: secureRandomBytes(8),
        p2c: 1000,
      });
      await expect(
        unwrapKey(encryptedKey, "password", { alg: "PBES2-HS256+A128KW" }),
      ).rejects.toThrow("PBES2 requires 'p2s' (salt) and 'p2c' (count) options");
    });

    it("should throw unwrapKey for wrong key/tag", async () => {
      const wrappingKey1 = await generateKey("A128KW");
      const wrappingKey2 = await generateKey("A128KW");
      const { encryptedKey } = await wrapKey(cek, wrappingKey1, { alg: "A128KW" });
      // eslint-disable-next-line vitest/require-to-throw-message -- Subtle crypto (AES-KW) unwrap errors vary by runtime; assert only that it rejects
      await expect(unwrapKey(encryptedKey, wrappingKey2, { alg: "A128KW" })).rejects.toThrow();
    });

    it("should throw wrapKey for invalid key type", async () => {
      const stringKeyError = await wrapKey(
        cek,
        // @ts-expect-error A128KW requires a CryptoKey or JWK_oct<"A128KW">; exercises runtime guard
        "not-a-key-object",
        { alg: "A128KW" },
      ).catch((e) => e);
      expect(isJWTError(stringKeyError, "ERR_JWK_INVALID")).toBe(true);
      expect(stringKeyError.message).toBe(STRING_KEY_MESSAGE);
      await expect(
        // @ts-expect-error RSA-OAEP requires a CryptoKey or JWK_RSA_Public; exercises runtime guard
        wrapKey(cek, secureRandomBytes(32), { alg: "RSA-OAEP" }),
        // RSA needs a CryptoKey.
      ).rejects.toThrow(expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }));
    });

    it("should throw wrapKey for unsupported algorithm", async () => {
      await expect(
        // @ts-expect-error intentionally invalid algorithm
        wrapKey(cek, secureRandomBytes(16), { alg: "UNSUPPORTED-WRAP-ALG" }),
      ).rejects.toThrow("Unsupported key wrapping algorithm");
    });

    it("should throw wrapKey for ECDH-ES direct without options.ecdh.enc", async () => {
      const recipientKeys = await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      });
      await expect(wrapKey(cek, recipientKeys.publicKey, { alg: "ECDH-ES" })).rejects.toThrow(
        "options.ecdh.enc",
      );
    });

    it("should throw unwrapKey RSA-OAEP when unwrapping key is not a CryptoKey", async () => {
      await expect(
        unwrapKey(new Uint8Array(32), secureRandomBytes(32) as never, {
          alg: "RSA-OAEP",
          format: "raw",
        }),
      ).rejects.toThrow("RSA-OAEP requires the unwrapping key to be a CryptoKey");
    });

    it("should throw unwrapKey for invalid key type", async () => {
      const wrappingKey = await generateKey("A128KW");
      const { encryptedKey } = await wrapKey(cek, wrappingKey, { alg: "A128KW" });
      const error = await unwrapKey(
        encryptedKey,
        // @ts-expect-error A128KW requires a CryptoKey or JWK_oct<"A128KW">; exercises runtime guard
        "not-a-key-object",
        { alg: "A128KW" },
      ).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe(STRING_KEY_MESSAGE);
    });

    it("should throw unwrapKey for unsupported algorithm", async () => {
      await expect(
        // @ts-expect-error intentionally invalid algorithm
        unwrapKey(new Uint8Array(0), new Uint8Array(0), { alg: "UNSUPPORTED-ALG" }),
      ).rejects.toThrow("Unsupported key unwrapping algorithm");
    });

    it("should throw for ECDH-ES unwrapKey without epk option", async () => {
      const recipientKeys = await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      });

      await expect(
        unwrapKey(new Uint8Array(0), recipientKeys.privateKey, {
          alg: "ECDH-ES",
          enc: "A128GCM",
          // no epk — triggers "ECDH-ES requires 'epk'"
        }),
      ).rejects.toThrow("ECDH-ES requires 'epk'");
    });

    it("should throw when ECDH-ES unwrapping key is not a CryptoKey", async () => {
      const senderKeys = await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      });

      await expect(
        unwrapKey(new Uint8Array(0), secureRandomBytes(32) as never, {
          alg: "ECDH-ES",
          epk: senderKeys.publicKey,
          enc: "A128GCM",
        }),
      ).rejects.toThrow("ECDH-ES requires the unwrapping key to be a CryptoKey");
    });

    it("should throw when ECDH-ES unwrapping key is not an ECDH/X25519 key", async () => {
      const senderKeys = await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      });
      const aesKey = await generateKey("A128GCM");

      await expect(
        unwrapKey(new Uint8Array(0), aesKey, {
          alg: "ECDH-ES",
          epk: senderKeys.publicKey,
          enc: "A128GCM",
        }),
      ).rejects.toThrow(/ECDH with the provided key is not allowed/i);
    });

    it("should throw for ECDH-ES unwrapKey without enc option", async () => {
      const recipientKeys = await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      });
      const senderKeys = await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      });

      await expect(
        unwrapKey(new Uint8Array(0), recipientKeys.privateKey, {
          alg: "ECDH-ES",
          epk: senderKeys.publicKey,
          // no enc — triggers "ECDH-ES requires 'enc' to derive the shared secret"
        }),
      ).rejects.toThrow("ECDH-ES requires 'enc' to derive the shared secret");
    });

    it("should throw for ECDH-ES+KW unwrapKey with empty wrapped key", async () => {
      const recipientKeys = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      });
      const senderKeys = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      });

      await expect(
        unwrapKey(new Uint8Array(0), recipientKeys.privateKey, {
          alg: "ECDH-ES+A128KW",
          epk: senderKeys.publicKey,
          enc: "A128GCM",
          // empty wrappedKey — triggers "requires an encrypted key"
        }),
      ).rejects.toThrow("ECDH-ES key agreement with key wrapping requires an encrypted key");
    });

    it("should unwrap ECDH-ES shared secret", async () => {
      const recipientKeys = await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      });
      const senderKeys = await generateKey("ECDH-ES", {
        namedCurve: "P-256",
      });

      const apu = secureRandomBytes(16);
      const apv = secureRandomBytes(16);

      const expectedSharedSecret = await deriveECDHESKey(
        recipientKeys.publicKey,
        senderKeys.privateKey,
        "A128GCM",
        128,
        apu,
        apv,
      );

      const unwrapped = await unwrapKey(new Uint8Array(0), recipientKeys.privateKey, {
        alg: "ECDH-ES",
        epk: senderKeys.publicKey,
        apu: base64UrlStringify(apu),
        apv: base64UrlStringify(apv),
        enc: "A128GCM",
        format: "raw",
      });

      expect(unwrapped).toBeInstanceOf(Uint8Array);
      expect(unwrapped).toEqual(expectedSharedSecret);
    });

    it("should unwrap ECDH-ES+A128KW encrypted key", async () => {
      const recipientKeys = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      });
      const senderKeys = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      });

      const apu = secureRandomBytes(16);
      const apv = secureRandomBytes(16);

      const sharedSecret = await deriveECDHESKey(
        recipientKeys.publicKey,
        senderKeys.privateKey,
        "ECDH-ES+A128KW",
        128,
        apu,
        apv,
      );

      const cekBytes = secureRandomBytes(16); // 128-bit CEK for A128KW

      const sharedSecretKey = await crypto.subtle.importKey(
        "raw",
        sharedSecret,
        { name: "AES-KW" },
        true,
        ["wrapKey"],
      );

      const aesGcmCek = await crypto.subtle.importKey("raw", cekBytes, { name: "AES-GCM" }, true, [
        "encrypt",
        "decrypt",
      ]);

      const encryptedKey = new Uint8Array(
        await crypto.subtle.wrapKey("raw", aesGcmCek, sharedSecretKey, "AES-KW"),
      );

      const unwrapped = await unwrapKey(encryptedKey, recipientKeys.privateKey, {
        alg: "ECDH-ES+A128KW",
        epk: senderKeys.publicKey,
        apu: base64UrlStringify(apu),
        apv: base64UrlStringify(apv),
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
        // the CEK is ignored for direct ECDH-ES
        secureRandomBytes(16),
        recipientKP.publicKey,
        { alg: "ECDH-ES", ecdh: { enc } },
      );

      expect(encryptedKey.length).toBe(0); // no encrypted key for direct agreement
      expect(epk).toBeDefined();

      const derived = await unwrapKey(encryptedKey, recipientKP.privateKey, {
        alg: "ECDH-ES",
        epk: epk,
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
      const cekToWrap = secureRandomBytes(16);

      const { encryptedKey, epk, apu, apv } = await wrapKey(cekToWrap, recipientKP.publicKey, {
        alg: "ECDH-ES+A128KW",
      });

      expect(encryptedKey.length).toBeGreaterThan(0);

      const unwrapped = await unwrapKey(encryptedKey, recipientKP.privateKey, {
        alg: "ECDH-ES+A128KW",
        epk: epk,
        apu,
        apv,
        enc: "A128GCM",
        format: "raw",
      });

      expect(unwrapped).toEqual(cekToWrap);
    });

    it("wrapKey writes the minimal epk for a generated ephemeral key, as encrypt does", async () => {
      const recipientKP = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
      );
      const { epk } = await wrapKey(secureRandomBytes(16), recipientKP.publicKey, {
        alg: "ECDH-ES+A128KW",
      });
      expect(Object.keys(epk).toSorted()).toEqual(["crv", "kty", "x", "y"]);
    });

    it("wrapKey writes the minimal epk for a caller-supplied ephemeral JWK", async () => {
      const recipient = await generateJWK("ECDH-ES+A128KW", { namedCurve: "X25519" });
      const ephemeral = await generateJWK("ECDH-ES+A128KW", { namedCurve: "X25519" });
      const rawCek = secureRandomBytes(16);
      const { encryptedKey, epk } = await wrapKey(rawCek, recipient.publicKey, {
        alg: "ECDH-ES+A128KW",
        ecdh: { ephemeralKey: ephemeral.privateKey },
      });
      expect(epk).toEqual({
        kty: "OKP",
        crv: "X25519",
        x: (ephemeral.publicKey as JWK_OKP_Public).x,
      });
      const unwrapped = await unwrapKey(encryptedKey, recipient.privateKey, {
        alg: "ECDH-ES+A128KW",
        epk,
        format: "raw",
      });
      expect(unwrapped).toEqual(rawCek);
    });

    it("wrapKey rejects an ephemeral public JWK that is not an EC or OKP key", async () => {
      const recipient = await generateJWK("ECDH-ES+A128KW", { namedCurve: "P-256" });
      const ephemeral = await generateJWK("ECDH-ES+A128KW", { namedCurve: "P-256" });
      const error = await wrapKey(secureRandomBytes(16), recipient.publicKey, {
        alg: "ECDH-ES+A128KW",
        ecdh: {
          ephemeralKey: {
            publicKey: { kty: "oct", k: "AAAA" } as unknown as JWK_EC_Public,
            privateKey: ephemeral.privateKey as JWK_EC_Private,
          },
        },
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe('ECDH-ES ephemeral key JWK "kty" must be "EC" or "OKP".');
    });

    it("wrapKey refuses party info over 1024 bytes, as encrypt does", async () => {
      const recipient = await generateJWK("ECDH-ES+A128KW", { namedCurve: "P-256" });
      const error = await wrapKey(secureRandomBytes(16), recipient.publicKey, {
        alg: "ECDH-ES+A128KW",
        ecdh: { partyUInfo: secureRandomBytes(2000) },
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toBe('"partyUInfo" (apu) must not exceed 1024 bytes (got 2000).');
    });

    it("wrapKey omits empty party info from its result", async () => {
      const recipient = await generateJWK("ECDH-ES+A128KW", { namedCurve: "P-256" });
      const result = await wrapKey(secureRandomBytes(16), recipient.publicKey, {
        alg: "ECDH-ES+A128KW",
        ecdh: { partyUInfo: new Uint8Array(0), partyVInfo: new Uint8Array(0) },
      });
      expect(result).not.toHaveProperty("apu");
      expect(result).not.toHaveProperty("apv");
    });

    it("wrapKey refuses an ephemeral key on another curve than the recipient key", async () => {
      const recipient = await generateJWK("ECDH-ES+A128KW", { namedCurve: "P-384" });
      const ephemeral = await generateJWK("ECDH-ES+A128KW", { namedCurve: "P-256" });
      const error = await wrapKey(secureRandomBytes(16), recipient.publicKey, {
        alg: "ECDH-ES+A128KW",
        ecdh: { ephemeralKey: ephemeral.privateKey },
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe(
        'ECDH-ES ephemeral key curve "P-256" does not match recipient curve "P-384".',
      );
    });

    it("wrapKey/unwrapKey ECDH-ES+A256KW roundtrip — X25519", async () => {
      const recipientKP = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
      const cekToWrap = secureRandomBytes(32);

      const { encryptedKey, epk, apu, apv } = await wrapKey(cekToWrap, recipientKP.publicKey, {
        alg: "ECDH-ES+A256KW",
      });

      const unwrapped = await unwrapKey(encryptedKey, recipientKP.privateKey, {
        alg: "ECDH-ES+A256KW",
        epk: epk,
        apu,
        apv,
        enc: "A256GCM",
        format: "raw",
      });

      expect(unwrapped).toEqual(cekToWrap);
    });

    // WrapKeyResult is discriminated by alg family; compile-time assertions below
    // fail the typecheck run if the conditional narrowing regresses.
    it("wrapKey result narrows by alg at the type level", async () => {
      const aesKw = await generateKey("A128KW");
      const aesKwRes = await wrapKey(cek, aesKw, { alg: "A128KW" });
      expect(aesKwRes.encryptedKey).toBeInstanceOf(Uint8Array);
      // @ts-expect-error AES-KW result has no `p2s` field.
      void aesKwRes.p2s;
      // @ts-expect-error AES-KW result has no `iv` field.
      void aesKwRes.iv;
      // @ts-expect-error AES-KW result has no `epk` field.
      void aesKwRes.epk;

      const pbes2Res = await wrapKey(cek, "password", {
        alg: "PBES2-HS256+A128KW",
        p2s: secureRandomBytes(16),
        p2c: 2000,
      });
      const _pbes2p2s: string = pbes2Res.p2s;
      const _pbes2p2c: number = pbes2Res.p2c;
      void _pbes2p2s;
      void _pbes2p2c;

      const gcmKwRes = await wrapKey(cek, await generateKey("A128GCM"), { alg: "A128GCMKW" });
      const _gcmIv: string = gcmKwRes.iv;
      const _gcmTag: string = gcmKwRes.tag;
      void _gcmIv;
      void _gcmTag;

      const ecdhKP = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
        "deriveBits",
      ]);
      const ecdhRes = await wrapKey(cek, ecdhKP.publicKey, {
        alg: "ECDH-ES",
        ecdh: { enc: "A128GCM" },
      });
      const _epk: JWK_EC_Public | JWK_OKP_Public = ecdhRes.epk;
      void _epk;
    });
  });

  describe("deriveSharedSecret", () => {
    it("produces the same secret on both sides — P-256", async () => {
      const [recipientKP, ephemeralKP] = await Promise.all([
        crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]),
        crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]),
      ]);

      const [sender, recipient] = await Promise.all([
        deriveSharedSecret(recipientKP.publicKey, ephemeralKP.privateKey, {
          enc: "ECDH-ES+A128KW",
        }),
        deriveSharedSecret(ephemeralKP.publicKey, recipientKP.privateKey, {
          enc: "ECDH-ES+A128KW",
        }),
      ]);

      expect(sender).toEqual(recipient);
      expect(sender.length).toBe(16);
    });

    it("produces the same secret on both sides — X25519", async () => {
      const [recipientKP, ephemeralKP] = await Promise.all([
        crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]),
        crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]),
      ]);

      const [sender, recipient] = await Promise.all([
        deriveSharedSecret(recipientKP.publicKey, ephemeralKP.privateKey, { enc: "A256GCM" }),
        deriveSharedSecret(ephemeralKP.publicKey, recipientKP.privateKey, { enc: "A256GCM" }),
      ]);

      expect(sender).toEqual(recipient);
      expect(sender.length).toBe(32);
    });

    it("throws when alg is ECDH-ES without keyLength", async () => {
      const kp = await generateKey("ECDH-ES", { namedCurve: "P-256" });
      await expect(
        deriveSharedSecret(kp.publicKey, kp.privateKey, { enc: "ECDH-ES" }),
      ).rejects.toThrow("keyLength");
    });

    it("accepts explicit keyLength for ECDH-ES direct", async () => {
      const kp = await generateKey("ECDH-ES", { namedCurve: "P-256" });
      const secret = await deriveSharedSecret(kp.publicKey, kp.privateKey, {
        enc: "ECDH-ES",
        keyLength: 256,
      });
      expect(secret.length).toBe(32);
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
      expect(result[0].kid).toBe("k1");
    });

    it("should return all keys when predicate always returns true", () => {
      expect(getJWKsFromSet(jwkSet, () => true)).toHaveLength(3);
    });

    it("should return empty array when predicate matches no keys", () => {
      expect(getJWKsFromSet(jwkSet, (k) => k.kty === "RSA")).toHaveLength(0);
    });

    it("drops entries that are not JWKs", () => {
      const junkSet = {
        keys: [null, "x", 1, [], {}, { kty: "unknown" }, jwkSet.keys[0]],
      } as unknown as JWKSet;
      const result = getJWKsFromSet(junkSet);
      expect(result).toHaveLength(1);
      expect(result[0].kid).toBe("k1");
    });
  });

  describe("PEM <-> JWK Conversion", () => {
    describe("importPEM", () => {
      it("should import PKCS#8 PEM to JWK (RSA)", async () => {
        const jwk = await importPEM(rsa.pem.pkcs8, "RS256", { pemType: "pkcs8" });
        expect(jwk.kty).toBe("RSA");
        expect(jwk.alg).toBe("RS256");
        expect(jwk.d).toBeDefined();
      });

      it("should import SPKI PEM to JWK (RSA)", async () => {
        const jwk = await importPEM(rsa.pem.spki, "RS256", { pemType: "spki" });
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
        const jwk = await importPEM(ec.pem.pkcs8, "ES256", { pemType: "pkcs8" });
        expect(jwk.kty).toBe("EC");
        expect(jwk.alg).toBe("ES256");
        expect(jwk.crv).toBe("P-256");
        expect(jwk.d).toBeDefined();
      });

      it("should import SPKI PEM to JWK (EC)", async () => {
        const jwk = await importPEM(ec.pem.spki, "ES256", { pemType: "spki" });
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
        expect(jwk.use).toBe("enc"); // Overrides any 'use' from the key itself if exportJWK doesn't prioritize input jwkExtras
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

        expect(`${pem}\n`).toBe(rsa.pem.pkcs8);
      });

      it("should export public RSA JWK to SPKI PEM", async () => {
        const pem = await exportPEM(rsa.jwk.public);

        const joseKey = await jose.importJWK(rsa.jwk.public);
        const josePem = await jose.exportSPKI(joseKey);
        expect(pem).toEqual(josePem);
      });

      it("should export private EC JWK to PKCS#8 PEM", async () => {
        const pem = await exportPEM(ec.jwk.private);

        const joseKey = await jose.importJWK(ec.jwk.private);
        const josePem = await jose.exportPKCS8(joseKey);
        expect(pem).toEqual(josePem);
      });

      it("should export public EC JWK to SPKI PEM", async () => {
        const pem = await exportPEM(ec.jwk.public);

        const joseKey = await jose.importJWK(ec.jwk.public);
        const josePem = await jose.exportSPKI(joseKey);
        expect(pem).toEqual(josePem);
      });

      it("should throw when exporting 'oct' JWK to PEM", async () => {
        const octJwk: JWK_oct = { kty: "oct", k: "somekey" };
        await expect(exportPEM(octJwk)).rejects.toThrow("An oct JWK cannot be exported");
      });

      it("should throw if alg is missing and required for JWK to CryptoKey conversion", async () => {
        const rsaNoAlg = { ...rsa.jwk.public, alg: undefined };
        await expect(exportPEM(rsaNoAlg)).rejects.toThrow('"alg" is required, set it on the JWK');
      });

      it("should use options.alg if JWK has no alg", async () => {
        const rsaNoAlg = { ...rsa.jwk.public, alg: undefined };
        const pem = await exportPEM(rsaNoAlg, { alg: "RS256" as JWKPEMAlgorithm });

        const joseKey = await jose.importJWK(rsa.jwk.public);
        const josePem = await jose.exportSPKI(joseKey);
        expect(pem).toEqual(josePem);
      });

      it("should throw when options.pemFormat forces pkcs8 on a public JWK", async () => {
        // The `expect: "private"` intent check catches the direction mismatch during
        // the intermediate import — clearer than the downstream CryptoKey-type error.
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
  });

  describe("JWK import cache", () => {
    // Pure WeakMapJWKCache unit tests — no module-level state, safe to run concurrently.
    it("WeakMapJWKCache.get returns undefined for an unseen key", () => {
      const cache = new WeakMapJWKCache();
      const fakeJwk: JWK_oct = { kty: "oct", k: "abc", alg: "HS256" };
      expect(cache.get(fakeJwk, "HS256")).toBeUndefined();
    });

    it("WeakMapJWKCache.set then .get returns the stored CryptoKey", async () => {
      const cache = new WeakMapJWKCache();
      const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, [
        "sign",
        "verify",
      ]);
      const fakeJwk: JWK_oct = { kty: "oct", k: "abc", alg: "HS256" };
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
      const fakeJwk: JWK_oct = { kty: "oct", k: "abc" };
      cache.set(fakeJwk, "HS256", k256);
      cache.set(fakeJwk, "HS384", k384);
      expect(cache.get(fakeJwk, "HS256")).toBe(k256);
      expect(cache.get(fakeJwk, "HS384")).toBe(k384);
    });

    // Module-level state tests — must run sequentially to avoid races between
    // configureJWKCache / clearJWKCache calls in the concurrent parent suite.
    describe("module-level cache control", { concurrent: false }, () => {
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
          set: (cachedJwk, alg, _key) => {
            sets.push([cachedJwk, alg]);
          },
        });
        await importKey(jwk.privateKey, "RS256");
        expect(sets.length).toBe(1);
        expect(sets[0][0]).toBe(jwk.privateKey);
        expect(sets[0][1]).toBe("RS256");
      });

      it("awaits an adapter whose get/set are asynchronous", async () => {
        const jwk = await generateJWK("RS256");
        const store = new Map<string, CryptoKey>();
        configureJWKCache({
          get: async (cachedJwk, alg) => store.get(`${await thumbprint(cachedJwk)}:${alg}`),
          set: async (cachedJwk, alg, key) => {
            store.set(`${await thumbprint(cachedJwk)}:${alg}`, key);
          },
        });
        const first = await importKey(jwk.privateKey, "RS256");
        expect(store.size).toBe(1);
        // A structurally identical copy hits the same entry: the key is the
        // thumbprint of the material, not the object reference.
        const second = await importKey({ ...jwk.privateKey }, "RS256");
        expect(second).toBe(first);
      });

      it("the documented shared-cache recipe keeps both halves of one pair apart", async () => {
        const [pair, other] = await Promise.all([generateJWK("ES256"), generateJWK("ES256")]);
        const map = new Map<string, CryptoKey>();
        configureJWKCache({
          get: async (jwk, alg) => map.get(await thumbprintCacheKey(jwk, alg)),
          set: async (jwk, alg, key) => {
            map.set(await thumbprintCacheKey(jwk, alg), key);
          },
        });

        const token = await sign({ sub: "u1" }, pair.privateKey);
        const { payload } = await verify(token, pair.publicKey);
        expect(payload.sub).toBe("u1");
        expect(map.size).toBe(2);

        await expect(verify(token, other.publicKey)).rejects.toSatisfy((error) =>
          isJWTError(error, "ERR_JWS_SIGNATURE_INVALID"),
        );
      });
    });
  });

  describe("codec failures wrap into JWTError", () => {
    it('importKey — malformed "k" is ERR_JWK_INVALID with an UnsecureError cause', async () => {
      const jwk: JWK_oct<"HS256"> = { kty: "oct", alg: "HS256", k: `${randomB64(32)}=` };
      const error = await importKey(jwk).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWK: "k" could not be decoded.');
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it('unwrapKey — malformed "iv" is ERR_JWE_INVALID with an UnsecureError cause', async () => {
      const wrappingKey = await generateKey("A256GCMKW");
      const error = await unwrapKey(secureRandomBytes(32), wrappingKey, {
        alg: "A256GCMKW",
        iv: `${randomB64(12)}=`,
        tag: randomB64(16),
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWE: "iv" could not be decoded.');
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it('unwrapKey — malformed "tag" is ERR_JWE_INVALID with an UnsecureError cause', async () => {
      const wrappingKey = await generateKey("A256GCMKW");
      const error = await unwrapKey(secureRandomBytes(32), wrappingKey, {
        alg: "A256GCMKW",
        iv: randomB64(12),
        tag: `${randomB64(16)}=`,
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWE: "tag" could not be decoded.');
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it('unwrapKey — malformed "p2s" is ERR_JWE_INVALID with an UnsecureError cause', async () => {
      const error = await unwrapKey(secureRandomBytes(24), "password", {
        alg: "PBES2-HS256+A128KW",
        p2s: `${randomB64(16)}=`,
        p2c: 1000,
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWE: "p2s" could not be decoded.');
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it.each(["apu", "apv"] as const)(
      'unwrapKey — malformed "%s" is ERR_JWE_INVALID with an UnsecureError cause',
      async (param) => {
        const recipient = await generateKey("ECDH-ES", {
          namedCurve: "P-256",
        });
        const sender = await generateKey("ECDH-ES", { namedCurve: "P-256" });
        const error = await unwrapKey(new Uint8Array(0), recipient.privateKey, {
          alg: "ECDH-ES",
          epk: sender.publicKey,
          enc: "A256GCM",
          [param]: `${randomB64(8)}=`,
        }).catch((e) => e);
        expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
        expect(error.message).toBe(`Invalid JWE: "${param}" could not be decoded.`);
        expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
      },
    );

    it("importPEM — a non-base64 PEM body is ERR_JWK_INVALID with an UnsecureError cause", async () => {
      const pem = "-----BEGIN PUBLIC KEY-----\n!!! not base64 !!!\n-----END PUBLIC KEY-----\n";
      const error = await importPEM(pem, "RS256").catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid PEM: body could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });

    it("importPEM — a garbage X.509 body is ERR_JWK_INVALID with a chained cause", async () => {
      const pem = "-----BEGIN CERTIFICATE-----\n!!! not base64 !!!\n-----END CERTIFICATE-----\n";
      const error = await importPEM(pem, "RS256").catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe("Failed to parse the X.509 certificate.");
      expect(isJWTError(error.cause, "ERR_JWK_INVALID")).toBe(true);
      expect(error.cause.message).toBe("Invalid X.509 certificate: body could not be decoded.");
      expect(isUnsecureError(error.cause.cause, "MALFORMED")).toBe(true);
    });
  });

  describe("reserved jwkParams", () => {
    const RESERVED = [
      "kty",
      "alg",
      "key_ops",
      "ext",
      "k",
      "d",
      "n",
      "e",
      "p",
      "q",
      "dp",
      "dq",
      "qi",
      "x",
      "y",
      "crv",
    ];

    it.each(RESERVED)("exportJWK rejects %s in jwkParams", async (member) => {
      const key = await generateKey("HS256");
      const error = await exportJWK(key, { [member]: "pwned" }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toContain(member);
    });

    it("exportJWK reports every reserved member it found", async () => {
      const key = await generateKey("HS256");
      const error = await exportJWK(key, { kty: "EC", k: "pwned", kid: "ok" } as never).catch(
        (e) => e,
      );
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toContain("kty");
      expect(error.message).toContain("k");
      expect(error.message).not.toContain("kid");
    });

    it("exportJWK still merges non-reserved metadata", async () => {
      const key = await generateKey("HS256");
      const jwk = await exportJWK<JWK_oct>(key, { kid: "k1", use: "sig" });
      expect(jwk.kid).toBe("k1");
      expect(jwk.use).toBe("sig");
      expect(jwk.kty).toBe("oct");
    });

    it("importPEM rejects reserved members in jwkParams", async () => {
      const error = await importPEM(rsa.pem.spki, "RS256", {
        jwkParams: { n: "pwned" } as never,
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toContain("n");
    });
  });

  describe("PEM input strictness", () => {
    it("does not overflow the stack on an OID-dense body", async () => {
      const body = new Uint8Array(60_000).fill(0x06);
      const error = await importPEM(pemBlock("PUBLIC KEY", body), "ECDH-ES").catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    });

    it("rejects a two-block PEM bundle instead of importing the first key", async () => {
      const error = await importPEM(rsa.pem.spki + rsa.pem.spki, "RS256").catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toContain("exactly one");
    });

    it("rejects trailing garbage after a valid block", async () => {
      const error = await importPEM(`${rsa.pem.spki}trailing garbage`, "RS256").catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    });

    it("accepts text before the block (RFC 7468 §2, e.g. openssl attribute dumps)", async () => {
      const jwk = await importPEM(
        `Bag Attributes\n    friendlyName: test\nsubject=CN=test\n${rsa.pem.spki}`,
        "RS256",
      );
      expect(jwk.kty).toBe("RSA");
    });

    it("still accepts surrounding whitespace", async () => {
      const jwk = await importPEM(`\n\n  ${rsa.pem.spki}  \n`, "RS256");
      expect(jwk.kty).toBe("RSA");
    });

    it("rejects a two-certificate bundle", async () => {
      const error = await importPEM(rsa.pem.x509 + rsa.pem.x509, "RS256").catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(isJWTError(error.cause, "ERR_JWK_INVALID")).toBe(true);
      expect(error.cause.message).toContain("exactly one");
    });

    // A truncated certificate used to be parsed with clamped subarrays: short
    // prefixes leaked a raw DataError, longer ones imported a key regardless.
    it.each([96, 200, 400, 500, 700])(
      "rejects a certificate truncated to %s bytes",
      async (length) => {
        const der = base64Parse(
          rsa.pem.x509.replaceAll(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, ""),
          { returnAs: "uint8array" },
        );
        const error = await importPEM(pemBlock("CERTIFICATE", der.slice(0, length)), "RS256").catch(
          (e) => e,
        );
        expect(error).toBeInstanceOf(JWTError);
        expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      },
    );

    it.each([
      ["Ed25519", "EdDSA"],
      ["X25519", "ECDH-ES+A256KW"],
    ] as const)("round-trips a %s key through PEM", async (crv, alg) => {
      const { privateKey, publicKey } = await okpJWKPair(crv, alg);
      const [pkcs8, spki] = await Promise.all([exportPEM(privateKey), exportPEM(publicKey)]);
      const [priv, pub] = await Promise.all([
        importPEM(pkcs8, alg, { pemType: "pkcs8" }),
        importPEM(spki, alg, { pemType: "spki" }),
      ]);
      expect(priv.crv).toBe(crv);
      expect(pub.crv).toBe(crv);
      expect(pub.x).toBe(publicKey.x);
    });

    it.each([
      ["Ed448", "EdDSA", OKP448_FIXTURES.Ed448.spki],
      ["X448", "ECDH-ES+A256KW", OKP448_FIXTURES.X448.spki],
    ] as const)("refuses a %s public key PEM", async (_crv, alg, spki) => {
      const error = await importPEM(
        pemBlock("PUBLIC KEY", base64Parse(spki, { returnAs: "uint8array" })),
        alg,
      ).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toContain("unsupported curve");
    });
  });

  describe("deriveSharedSecret keyLength validation", () => {
    let pair: CryptoKeyPair;
    beforeAll(async () => {
      pair = await generateKey("ECDH-ES", { namedCurve: "P-256" });
    });

    it.each([0, -8, 12, 8200, 1.5, Number.NaN])("rejects keyLength %s", async (keyLength) => {
      const error = await deriveSharedSecret(pair.publicKey, pair.privateKey, {
        enc: "ECDH-ES",
        keyLength,
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    });

    it("still accepts a valid keyLength", async () => {
      const secret = await deriveSharedSecret(pair.publicKey, pair.privateKey, {
        enc: "ECDH-ES",
        keyLength: 256,
      });
      expect(secret.length).toBe(32);
    });
  });

  describe("RSA modulus floor", () => {
    it.each(["RS256", "PS256", "RSA-OAEP-256"] as const)(
      "generateKey rejects %s below 2048 bits",
      async (alg) => {
        const error = await generateKey(alg, { modulusLength: 1024 }).catch((e) => e);
        expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
        expect(error.message).toContain("2048");
      },
    );

    it("generateJWK rejects a weak modulusLength", async () => {
      const error = await generateJWK("RS256", { modulusLength: 512 }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    });
  });

  describe("OKP curve handling", () => {
    it.each([
      ["Ed25519", "EdDSA"],
      ["X25519", "ECDH-ES+A256KW"],
    ] as const)("imports an %s JWK on its own curve", async (crv, alg) => {
      const { privateKey, publicKey } = await okpJWKPair(crv, alg);
      expect(privateKey.crv).toBe(crv);
      const priv = await importKey(privateKey);
      const pub = await importKey(publicKey);
      expect(priv.algorithm.name).toBe(crv);
      expect(pub.algorithm.name).toBe(crv);
    });

    it.each([
      ["Ed448", "EdDSA"],
      ["X448", "ECDH-ES+A256KW"],
    ] as const)("refuses an %s JWK", async (crv, alg) => {
      const error = await importKey({
        kty: "OKP",
        crv,
        x: OKP448_FIXTURES[crv].x,
        alg,
      }).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toContain(crv);
    });

    it("rejects an unknown OKP curve for EdDSA", async () => {
      const error = await importKey({
        kty: "OKP",
        alg: "EdDSA",
        crv: "Ed99999",
        x: base64UrlStringify(new Uint8Array(32)),
      } as never).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toContain("Ed99999");
    });

    it("rejects an unknown OKP curve for ECDH-ES", async () => {
      const error = await importKey({
        kty: "OKP",
        alg: "ECDH-ES",
        crv: "X99999",
        x: base64UrlStringify(new Uint8Array(32)),
      } as never).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toContain("X99999");
    });

    it("rejects an unknown EC curve for ECDH-ES", async () => {
      const error = await importKey({
        kty: "EC",
        alg: "ECDH-ES",
        crv: "secp256k1",
        x: base64UrlStringify(new Uint8Array(32)),
        y: base64UrlStringify(new Uint8Array(32)),
      } as never).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toContain("secp256k1");
    });

    it("quotes and bounds an oversized crv in the error message", async () => {
      const crv = `P-256\n"${"x".repeat(10_000)}`;
      const error = await importKey({
        kty: "EC",
        alg: "ECDH-ES",
        crv,
        x: base64UrlStringify(new Uint8Array(32)),
        y: base64UrlStringify(new Uint8Array(32)),
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe(
        `Invalid JWK "crv" ${JSON.stringify(`${crv.slice(0, 64)}…`)}, expected P-256, P-384, P-521.`,
      );
      expect(error.message.length).toBeLessThan(200);
    });
  });

  describe("unwrapKey — attacker-controlled ECDH parameters", () => {
    it('rejects an "epk" carrying private key material', async () => {
      const recipient = await ecdhPair("P-256");
      const sender = await ecdhPair("P-256");
      const epk = await exportJWK<JWK_EC_Private>(sender.privateKey);

      const error = await unwrapKey(new Uint8Array(0), recipient.privateKey, {
        alg: "ECDH-ES",
        epk: epk,
        enc: "A128GCM",
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWE: "epk" must not contain private key material.');
    });

    it('rejects an "epk" on a different curve than the recipient key', async () => {
      const recipient = await ecdhPair("P-256");
      const sender = await ecdhPair("P-384");
      const epk = await exportJWK<JWK_EC_Public>(sender.publicKey);

      const error = await unwrapKey(new Uint8Array(0), recipient.privateKey, {
        alg: "ECDH-ES",
        epk,
        enc: "A128GCM",
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe(
        'Invalid JWE: "epk" curve "P-384" does not match recipient curve "P-256".',
      );
    });

    it('rejects an "epk" that is not an EC or OKP key', async () => {
      const recipient = await ecdhPair("P-256");

      const error = await unwrapKey(new Uint8Array(0), recipient.privateKey, {
        alg: "ECDH-ES",
        epk: {
          kty: "oct",
          k: base64UrlStringify(secureRandomBytes(32)),
        } as unknown as JWK_EC_Public,
        enc: "A128GCM",
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWE: "epk" must be an EC or OKP public key.');
    });

    it('ignores forged "alg", "key_ops" and "ext" members on the "epk"', async () => {
      const recipient = await ecdhPair("P-256");
      const sender = await ecdhPair("P-256");
      const epk = await exportJWK<JWK_EC_Public>(sender.publicKey);

      const expected = await deriveSharedSecret(recipient.publicKey, sender.privateKey, {
        enc: "A128GCM",
      });
      const unwrapped = await unwrapKey(new Uint8Array(0), recipient.privateKey, {
        alg: "ECDH-ES",
        epk: { ...epk, alg: "RS256", key_ops: ["sign"], ext: false } as unknown as JWK_EC_Public,
        enc: "A128GCM",
        format: "raw",
      });
      expect(unwrapped).toEqual(expected);
    });

    it('rejects an oversized "apu"', async () => {
      const recipient = await ecdhPair("P-256");
      const sender = await ecdhPair("P-256");
      const epk = await exportJWK<JWK_EC_Public>(sender.publicKey);

      const error = await unwrapKey(new Uint8Array(0), recipient.privateKey, {
        alg: "ECDH-ES",
        epk,
        enc: "A128GCM",
        apu: base64UrlStringify(new Uint8Array(3 * 1024 * 1024)),
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWE: "apu" must not exceed 1024 bytes (got 3145728).');
    });

    it("rejects AES-GCMKW iv and tag of the wrong length", async () => {
      const wrappingKey = await generateKey("A128GCM");
      const cek = secureRandomBytes(32);
      const wrapped = await wrapKey(cek, wrappingKey, { alg: "A128GCMKW" });

      const badIv = await unwrapKey(wrapped.encryptedKey, wrappingKey, {
        alg: "A128GCMKW",
        iv: base64UrlStringify(secureRandomBytes(16)),
        tag: wrapped.tag,
        format: "raw",
      }).catch((e) => e);
      expect(isJWTError(badIv, "ERR_JWE_INVALID")).toBe(true);
      expect(badIv.message).toBe('Invalid JWE: "iv" must be 12 bytes for A128GCMKW (got 16).');

      const badTag = await unwrapKey(wrapped.encryptedKey, wrappingKey, {
        alg: "A128GCMKW",
        iv: wrapped.iv,
        tag: base64UrlStringify(secureRandomBytes(20)),
        format: "raw",
      }).catch((e) => e);
      expect(isJWTError(badTag, "ERR_JWE_INVALID")).toBe(true);
      expect(badTag.message).toBe('Invalid JWE: "tag" must be 16 bytes for A128GCMKW (got 20).');
    });
  });
});

/**
 * OKP key pair as JWKs, generated through Web Crypto directly: these tests are
 * about the import path, not the generation surface.
 */
async function okpJWKPair(
  crv: "Ed25519" | "X25519",
  alg: JWK_OKP_SIGN | JWK_ECDH_ES,
): Promise<{ privateKey: JWK_OKP_Private; publicKey: JWK_OKP_Public }> {
  const { privateKey, publicKey } = (await crypto.subtle.generateKey(
    { name: crv },
    true,
    crv.startsWith("Ed") ? ["sign", "verify"] : ["deriveBits"],
  )) as CryptoKeyPair;

  const [priv, pub] = await Promise.all([
    exportJWK<JWK_OKP_Private>(privateKey),
    exportJWK<JWK_OKP_Public>(publicKey),
  ]);

  return { privateKey: { ...priv, alg }, publicKey: { ...pub, alg } };
}

/**
 * Public keys on the curves the library does not support, minted once with
 * Node's WebCrypto: the `x` of each JWK and its SPKI body in standard base64.
 */
const OKP448_FIXTURES = {
  Ed448: {
    x: "p_6ZAjpLN3gDMhLshcsaaQs1NnrmoRQflJUrXUucc1k0PHKCJ9K58bUDj_Rwr7trpSsIKVeenjCA",
    spki: "MEMwBQYDK2VxAzoAp/6ZAjpLN3gDMhLshcsaaQs1NnrmoRQflJUrXUucc1k0PHKCJ9K58bUDj/Rwr7trpSsIKVeenjCA",
  },
  X448: {
    x: "m_1D9zT15vlRSQFlLEjBAJ0eq4v7n9aqWGM_5UW9CImAdNL3ER5IwfSVCIyZbulyeDWRKYC_f-c",
    spki: "MEIwBQYDK2VvAzkAm/1D9zT15vlRSQFlLEjBAJ0eq4v7n9aqWGM/5UW9CImAdNL3ER5IwfSVCIyZbulyeDWRKYC/f+c=",
  },
} as const;

describe.concurrent("thumbprint (RFC 7638)", () => {
  /**
   * RFC 7638 §3.1 — the worked example, with the extra members (`alg`, `kid`)
   * the specification includes to show they take no part in the digest.
   */
  const rfcExample: JWK_RSA_Public = {
    kty: "RSA",
    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    e: "AQAB",
    alg: "RS256",
    kid: "2011-04-29",
  };

  it("matches the RFC 7638 §3.1 example", async () => {
    await expect(thumbprint(rfcExample)).resolves.toBe(
      "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    );
  });

  it("digests the EC members crv, kty, x, y", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256");
    const expected = digestOfCanonical({
      crv: publicKey.crv,
      kty: publicKey.kty,
      x: publicKey.x,
      y: publicKey.y,
    });
    await expect(thumbprint(publicKey)).resolves.toBe(expected);
    // The private members take no part: a key pair has a single thumbprint.
    await expect(thumbprint(privateKey)).resolves.toBe(expected);
  });

  it("digests the OKP members crv, kty, x", async () => {
    const { publicKey } = await generateJWK("Ed25519");
    await expect(thumbprint(publicKey)).resolves.toBe(
      digestOfCanonical({ crv: publicKey.crv, kty: publicKey.kty, x: publicKey.x }),
    );
  });

  it("digests the oct members k, kty", async () => {
    const key = await generateJWK("HS256");
    await expect(thumbprint(key)).resolves.toBe(digestOfCanonical({ k: key.k, kty: key.kty }));
  });

  it("digests under the requested hash", async () => {
    const { publicKey } = await generateJWK("ES256");
    const members = {
      crv: publicKey.crv,
      kty: publicKey.kty,
      x: publicKey.x,
      y: publicKey.y,
    };
    await expect(thumbprint(publicKey, { hash: "SHA-384" })).resolves.toBe(
      digestOfCanonical(members, "sha384"),
    );
    await expect(thumbprint(publicKey, { hash: "SHA-512" })).resolves.toBe(
      digestOfCanonical(members, "sha512"),
    );
  });

  it("rejects a key missing a required member", async () => {
    const { e: _e, ...withoutE } = rfcExample;
    const error = await thumbprint(withoutE as JWK_RSA_Public).catch((error_) => error_);
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(error.message).toBe('JWK thumbprint requires the member "e" on an RSA key.');
  });

  it("rejects an unknown key type", async () => {
    const error = await thumbprint({ kty: "XYZ", k: "abc" } as unknown as JWK_oct).catch(
      (error_) => error_,
    );
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(error.message).toBe('JWK thumbprint is not defined for kty "XYZ".');
  });

  it.each(["constructor", "__proto__", "toString", "hasOwnProperty"])(
    "rejects the inherited property name %s as a key type",
    async (kty) => {
      const error = await thumbprint({ kty, k: "abc" } as unknown as JWK_oct).catch(
        (error_) => error_,
      );
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe(`JWK thumbprint is not defined for kty "${kty}".`);
    },
  );

  it("rejects an unsupported hash", async () => {
    const error = await thumbprint(rfcExample, {
      hash: "SHA-1" as unknown as "SHA-256",
    }).catch((error_) => error_);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it.each([[null], [[]], ["SHA-256"]])(
    "rejects options that are not an object (%j) with the message verify uses",
    async (options) => {
      const error = await thumbprint(rfcExample, options as unknown as { hash?: "SHA-256" }).catch(
        (error_) => error_,
      );
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toBe('"options" must be an object.');
    },
  );
});

describe.concurrent("argument shape", () => {
  it.each([
    ["wrapKey", () => wrapKey(new Uint8Array(16), new Uint8Array(16), null as never)],
    ["exportPEM", () => exportPEM(null as never)],
  ])("%s rejects a non-object argument with the message verify uses", async (_name, run) => {
    const error = await run().catch((error_: unknown) => error_);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect((error as Error).message).toMatch(/^"(options|jwk)" must be an object\.$/);
  });

  it("verify and wrapKey word a null options bag the same way", async () => {
    const [verifyError, wrapError] = await Promise.all([
      verify("a.b.c", new Uint8Array(32), null as never).catch((error_: unknown) => error_),
      wrapKey(new Uint8Array(16), new Uint8Array(16), null as never).catch(
        (error_: unknown) => error_,
      ),
    ]);
    expect((wrapError as Error).message).toBe((verifyError as Error).message);
  });
});

describe.concurrent("thumbprint as the default kid", () => {
  it("generateJWK names a symmetric key by its thumbprint", async () => {
    const key = await generateJWK("HS256");
    expect(key.kid).toBe(await thumbprint(key));
  });

  it("generateJWK gives a pair the one thumbprint of its public key", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256");
    const expected = await thumbprint(publicKey);
    expect(publicKey.kid).toBe(expected);
    expect(privateKey.kid).toBe(expected);
  });

  it("generateJWK keeps a caller's kid", async () => {
    const { publicKey } = await generateJWK("ES256", { kid: "rotation-2026" });
    expect(publicKey.kid).toBe("rotation-2026");
  });

  it("deriveJWKFromPassword names the derived key by its thumbprint", async () => {
    const jwk = await deriveJWKFromPassword("password123", {
      alg: "PBES2-HS256+A128KW",
      salt: secureRandomBytes(16),
      iterations: 2000,
    });
    expect(jwk.kid).toBe(await thumbprint(jwk));
  });
});

describe.concurrent("kid option on generated keys", () => {
  const derivation = {
    alg: "PBES2-HS256+A128KW",
    salt: secureRandomBytes(16),
    iterations: 2000,
  } as const;

  it("generateJWK sets no kid on a symmetric key with kid: false", async () => {
    const key = await generateJWK("HS256", { kid: false });
    expect("kid" in key).toBe(false);
    expect(key.alg).toBe("HS256");
  });

  it("generateJWK sets no kid on either half of a pair with kid: false", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256", { kid: false });
    expect("kid" in privateKey).toBe(false);
    expect("kid" in publicKey).toBe(false);
  });

  it("generateJWK uses a given kid verbatim on a symmetric key", async () => {
    const key = await generateJWK("HS256", { kid: "hmac-2026" });
    expect(key.kid).toBe("hmac-2026");
  });

  it("generateJWK uses a given kid verbatim on both halves of a pair", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256", { kid: "ec-2026" });
    expect(privateKey.kid).toBe("ec-2026");
    expect(publicKey.kid).toBe("ec-2026");
  });

  it("generateKey with toJWK follows the kid option", async () => {
    const named = await generateKey("A256CBC-HS512", { toJWK: true, kid: "cbc-1" });
    const unnamed = await generateKey("A256CBC-HS512", { toJWK: true, kid: false });
    const pair = await generateKey("Ed25519", { toJWK: true, kid: false });
    expect(named.kid).toBe("cbc-1");
    expect("kid" in unnamed).toBe(false);
    expect("kid" in pair.privateKey).toBe(false);
    expect("kid" in pair.publicKey).toBe(false);
  });

  it("deriveJWKFromPassword sets no kid with kid: false", async () => {
    const jwk = await deriveJWKFromPassword("password123", { ...derivation, kid: false });
    expect("kid" in jwk).toBe(false);
    expect(jwk.alg).toBe("A128KW");
  });

  it("deriveJWKFromPassword uses a given kid verbatim", async () => {
    const jwk = await deriveJWKFromPassword("password123", { ...derivation, kid: "pw-1" });
    expect(jwk.kid).toBe("pw-1");
  });

  it("refuses a kid that is neither a string nor false", async () => {
    const generated = await generateJWK("HS256", { kid: 42 as never }).catch((error) => error);
    const derived = await deriveJWKFromPassword("password123", {
      ...derivation,
      kid: true as never,
    }).catch((error) => error);
    expect(isJWTError(generated, "ERR_INVALID_OPTION")).toBe(true);
    expect(isJWTError(derived, "ERR_INVALID_OPTION")).toBe(true);
  });
});

describe.concurrent("salt as a string", () => {
  it("derives the same key from a string and its UTF-8 bytes", async () => {
    const options = { alg: "PBES2-HS256+A128KW", iterations: 2000, toJWK: true } as const;
    const fromText = await deriveKeyFromPassword("password123", {
      ...options,
      salt: "pepper-and-salt",
    });
    const fromBytes = await deriveKeyFromPassword("password123", {
      ...options,
      salt: textEncoder.encode("pepper-and-salt"),
    });
    expect(fromText.k).toBe(fromBytes.k);
  });

  it("measures a string salt in octets, not characters", async () => {
    await expect(
      deriveKeyFromPassword("password123", {
        alg: "PBES2-HS256+A128KW",
        salt: "abc",
        iterations: 2000,
      }),
    ).rejects.toThrow("must be 8 or more octets");
  });
});

describe.concurrent("key generation and the direct JWK API", () => {
  describe("ES512 curve", () => {
    it("generates a CryptoKeyPair on P-521 that signs and verifies", async () => {
      const pair = await generateKey("ES512");
      expect((pair.privateKey.algorithm as EcKeyAlgorithm).namedCurve).toBe("P-521");
      expect((pair.publicKey.algorithm as EcKeyAlgorithm).namedCurve).toBe("P-521");

      const jws = await sign({ sub: "es512" }, pair.privateKey, { alg: "ES512" });
      const { payload } = await verify(jws, pair.publicKey, { algorithms: ["ES512"] });
      expect(payload).toEqual({ sub: "es512" });
    });

    it("generateJWK reports crv P-521 and round-trips a signature", async () => {
      const { privateKey, publicKey } = await generateJWK("ES512");
      expect(privateKey.crv).toBe("P-521");
      expect(publicKey.crv).toBe("P-521");

      const jws = await sign({ sub: "es512" }, privateKey);
      const { payload } = await verify(jws, publicKey);
      expect(payload).toEqual({ sub: "es512" });
    });
  });

  describe("AES-GCMKW generated keys", () => {
    const gcmkw = ["A128GCMKW", "A192GCMKW", "A256GCMKW"] as const;

    it.each(gcmkw)("%s is generated for encrypt/decrypt", async (alg) => {
      const kek = await generateKey(alg);
      expect(kek.usages.toSorted()).toEqual(["decrypt", "encrypt"]);
    });

    it.each(gcmkw)("%s wraps and unwraps a CEK", async (alg) => {
      const kek = await generateKey(alg);
      const cek = secureRandomBytes(32);
      const wrapped = await wrapKey(cek, kek, { alg });
      const unwrapped = await unwrapKey(wrapped.encryptedKey, kek, {
        alg,
        iv: wrapped.iv,
        tag: wrapped.tag,
        format: "raw",
      });
      expect(unwrapped).toEqual(cek);
    });

    it.each(gcmkw)("%s encrypts and decrypts a JWE", async (alg) => {
      const kek = await generateKey(alg);
      const jwe = await encrypt({ sub: "gcmkw" }, kek, { alg, enc: "A128GCM" });
      const { payload } = await decrypt(jwe, kek, { algorithms: [alg] });
      expect(payload).toEqual({ sub: "gcmkw" });
    });

    it("exports an A*GCMKW CryptoKey under the bare A*GCM name", async () => {
      const kek = await generateKey("A128GCMKW");
      const jwk = await exportJWK<JWK_oct>(kek);
      expect(jwk.alg).toBe("A128GCM");

      const error = await importKey(jwk, { alg: "A128GCMKW" }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    });
  });

  describe("keyUsage across a generated pair", () => {
    it("splits the requested usages between the two halves", async () => {
      const { privateKey, publicKey } = await generateJWK("ES256", {
        keyUsage: ["sign", "verify"],
      });
      expect(privateKey.key_ops).toEqual(["sign"]);
      expect(publicKey.key_ops).toEqual(["verify"]);

      const jws = await sign({ sub: "split" }, privateKey);
      const { payload } = await verify(jws, publicKey);
      expect(payload).toEqual({ sub: "split" });
    });

    it("refuses a narrowing that leaves the public half with no usage", async () => {
      const error = await generateJWK("ES256", { keyUsage: ["sign"] }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toContain("verify");
    });

    it("refuses a narrowing that leaves the private half with no usage", async () => {
      const error = await generateKey("RSA-OAEP-256", {
        keyUsage: ["encrypt", "wrapKey"],
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toMatch(/decrypt|unwrapKey/);
    });

    it("keeps an ECDH-ES pair whose public half carries no usage", async () => {
      const pair = await generateKey("ECDH-ES", { keyUsage: ["deriveBits"] });
      expect([...pair.privateKey.usages]).toEqual(["deriveBits"]);
      expect([...pair.publicKey.usages]).toEqual([]);
    });
  });

  describe("namedCurve on ES*", () => {
    it.each([
      ["ES256", "P-384"],
      ["ES384", "P-521"],
      ["ES512", "P-256"],
    ] as const)("%s refuses the contradicting curve %s", async (alg, namedCurve) => {
      const error = await generateKey(alg, { namedCurve }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toContain(namedCurve);
    });

    it("accepts the curve the algorithm names", async () => {
      const pair = await generateKey("ES384", { namedCurve: "P-384" });
      expect((pair.privateKey.algorithm as EcKeyAlgorithm).namedCurve).toBe("P-384");
    });
  });

  describe("generateKey publicExponent", () => {
    it.each([[3 as never], ["AQAB" as never], [null as never]])(
      "refuses a malformed publicExponent (%s)",
      async (publicExponent) => {
        const error = await generateKey("RS256", { publicExponent }).catch((e) => e);
        expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      },
    );

    it("accepts the three-byte 65537 exponent", async () => {
      const pair = await generateKey("RS256", {
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      });
      expect(pair.privateKey.type).toBe("private");
    });
  });

  describe("password derivation algorithm gate", () => {
    it.each(["HS256", "A128KW", "dir", "not-an-alg"] as const)(
      "deriveKeyFromPassword refuses %s",
      async (alg) => {
        const error = await deriveKeyFromPassword("password123", {
          alg: alg as never,
          salt: secureRandomBytes(16),
          iterations: 2000,
        }).catch((e) => e);
        expect(isJWTError(error, "ERR_JWK_UNSUPPORTED")).toBe(true);
      },
    );

    it("deriveJWKFromPassword refuses a non-PBES2 algorithm", async () => {
      const error = await deriveJWKFromPassword("password123", {
        alg: "A128KW" as never,
        salt: secureRandomBytes(16),
        iterations: 2000,
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_UNSUPPORTED")).toBe(true);
    });
  });

  describe("unwrapKey failures are one verdict", () => {
    it("reports a wrong AES-KW key as a decryption failure", async () => {
      const cek = secureRandomBytes(32);
      const [mine, theirs] = await Promise.all([generateJWK("A128KW"), generateJWK("A128KW")]);
      const { encryptedKey } = await wrapKey(cek, mine, { alg: "A128KW" });
      const error = await unwrapKey(encryptedKey, theirs, {
        alg: "A128KW",
        format: "raw",
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
    });

    it("reports a corrupt AES-GCMKW ciphertext as a decryption failure", async () => {
      const kek = await generateJWK("A128GCMKW");
      const wrapped = await wrapKey(secureRandomBytes(32), kek, { alg: "A128GCMKW" });
      wrapped.encryptedKey[0] ^= 0xff;
      const error = await unwrapKey(wrapped.encryptedKey, kek, {
        alg: "A128GCMKW",
        iv: wrapped.iv,
        tag: wrapped.tag,
        format: "raw",
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
    });

    it("reports a wrong RSA-OAEP key as a decryption failure", async () => {
      const [mine, theirs] = await Promise.all([
        generateKey("RSA-OAEP-256"),
        generateKey("RSA-OAEP-256"),
      ]);
      const { encryptedKey } = await wrapKey(secureRandomBytes(32), mine.publicKey, {
        alg: "RSA-OAEP-256",
      });
      const error = await unwrapKey(encryptedKey, theirs.privateKey, {
        alg: "RSA-OAEP-256",
        format: "raw",
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
    });

    it("reports a wrong PBES2 password as a decryption failure", async () => {
      const salt = secureRandomBytes(16);
      const wrapped = await wrapKey(secureRandomBytes(32), "password123", {
        alg: "PBES2-HS256+A128KW",
        p2s: salt,
        p2c: 2000,
      });
      const error = await unwrapKey(wrapped.encryptedKey, "wrong-password", {
        alg: "PBES2-HS256+A128KW",
        p2s: salt,
        p2c: 2000,
        format: "raw",
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
    });

    it("reports a corrupt ECDH-ES+A128KW encrypted key as a decryption failure", async () => {
      const pair = await generateKey("ECDH-ES+A128KW");
      const wrapped = await wrapKey(secureRandomBytes(32), pair.publicKey, {
        alg: "ECDH-ES+A128KW",
      });
      wrapped.encryptedKey[0] ^= 0xff;
      const error = await unwrapKey(wrapped.encryptedKey, pair.privateKey, {
        alg: "ECDH-ES+A128KW",
        epk: wrapped.epk,
        format: "raw",
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
    });
  });

  describe("arguments the direct JWK API names", () => {
    it.each([
      ["wrapKey options", () => wrapKey(secureRandomBytes(32), octKey(), null as never)],
      ["wrapKey keyToWrap", () => wrapKey(null as never, octKey(), { alg: "A128KW" })],
      [
        "unwrapKey options",
        () => unwrapKey(secureRandomBytes(40), octKey() as never, null as never),
      ],
      ["unwrapKey wrappedKey", () => unwrapKey(null as never, octKey(), { alg: "A128KW" })],
      ["deriveKeyFromPassword options", () => deriveKeyFromPassword("password123", null as never)],
      [
        "deriveKeyFromPassword password",
        () =>
          deriveKeyFromPassword(null as never, {
            alg: "PBES2-HS256+A128KW",
            salt: secureRandomBytes(16),
            iterations: 2000,
          }),
      ],
      ["deriveJWKFromPassword options", () => deriveJWKFromPassword("password123", null as never)],
      ["importPEM pem", () => importPEM(null as never, "RS256")],
      ["importPEM options", () => importPEM("-----BEGIN PUBLIC KEY-----", "RS256", null as never)],
      ["exportPEM jwk", () => exportPEM(null as never)],
      ["thumbprint jwk", () => thumbprint(null as never)],
    ])("refuses a null %s", async (_label, run) => {
      const error = await (run() as Promise<unknown>).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    });

    it("refuses a null deriveSharedSecret options", async () => {
      const pair = await generateKey("ECDH-ES");
      const error = await deriveSharedSecret(pair.publicKey, pair.privateKey, null as never).catch(
        (e) => e,
      );
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    });

    it("refuses a null thumbprint options", async () => {
      const jwk = await generateJWK("HS256");
      const error = await thumbprint(jwk, null as never).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    });
  });
});

describe("types", () => {
  type Bytes = Uint8Array<ArrayBuffer>;
  type Named<A> = { alg: A; kid: string };

  it("types generateKey after a literal alg", () => {
    expectTypeOf(() => generateKey("HS256")).returns.resolves.toEqualTypeOf<CryptoKey>();
    expectTypeOf(() => generateKey("A128KW")).returns.resolves.toEqualTypeOf<CryptoKey>();
    expectTypeOf(() => generateKey("A256GCM")).returns.resolves.toEqualTypeOf<CryptoKey>();
    expectTypeOf(() => generateKey("A128GCMKW")).returns.resolves.toEqualTypeOf<CryptoKey>();
    expectTypeOf(() => generateKey("A256CBC-HS512")).returns.resolves.toEqualTypeOf<Bytes>();
    expectTypeOf(() => generateKey("RS256")).returns.resolves.toEqualTypeOf<CryptoKeyPair>();
    expectTypeOf(() => generateKey("PS384")).returns.resolves.toEqualTypeOf<CryptoKeyPair>();
    expectTypeOf(() => generateKey("RSA-OAEP-256")).returns.resolves.toEqualTypeOf<CryptoKeyPair>();
    expectTypeOf(() => generateKey("ES256")).returns.resolves.toEqualTypeOf<CryptoKeyPair>();
    expectTypeOf(() => generateKey("Ed25519")).returns.resolves.toEqualTypeOf<CryptoKeyPair>();
    expectTypeOf(() =>
      generateKey("ECDH-ES+A128KW"),
    ).returns.resolves.toEqualTypeOf<CryptoKeyPair>();
    expectTypeOf(() =>
      generateKey("RS256", { toJWK: false, modulusLength: 2048 }),
    ).returns.resolves.toEqualTypeOf<CryptoKeyPair>();
  });

  it("types generateKey with toJWK: true after the JWK map", () => {
    expectTypeOf(() => generateKey("HS256", { toJWK: true })).returns.resolves.toEqualTypeOf<
      JWK_oct<"HS256"> & Named<"HS256">
    >();
    expectTypeOf(() =>
      generateKey("A256CBC-HS512", { toJWK: true }),
    ).returns.resolves.toEqualTypeOf<JWK_oct<"A256CBC-HS512"> & Named<"A256CBC-HS512">>();
    expectTypeOf(() => generateKey("RS256", { toJWK: true })).returns.resolves.toEqualTypeOf<{
      privateKey: JWK_RSA_Private<"RS256"> & Named<"RS256">;
      publicKey: JWK_RSA_Public<"RS256"> & Named<"RS256">;
    }>();
    expectTypeOf(() => generateKey("ES256", { toJWK: true })).returns.resolves.toEqualTypeOf<{
      privateKey: JWK_EC_Private<"ES256"> & Named<"ES256">;
      publicKey: JWK_EC_Public<"ES256"> & Named<"ES256">;
    }>();
    expectTypeOf(() => generateKey("Ed25519", { toJWK: true })).returns.resolves.toEqualTypeOf<{
      privateKey: JWK_OKP_Private<"Ed25519"> & Named<"Ed25519">;
      publicKey: JWK_OKP_Public<"Ed25519"> & Named<"Ed25519">;
    }>();
    expectTypeOf(() => generateKey("ECDH-ES", { toJWK: true })).returns.resolves.toEqualTypeOf<
      | {
          privateKey: JWK_EC_Private<"ECDH-ES"> & Named<"ECDH-ES">;
          publicKey: JWK_EC_Public<"ECDH-ES"> & Named<"ECDH-ES">;
        }
      | {
          privateKey: JWK_OKP_Private<"ECDH-ES"> & Named<"ECDH-ES">;
          publicKey: JWK_OKP_Public<"ECDH-ES"> & Named<"ECDH-ES">;
        }
    >();
  });

  it("types generateKey with a non-literal alg or toJWK as the union of its shapes", () => {
    expectTypeOf((alg: GenerateKeyAlgorithm) => generateKey(alg)).returns.resolves.toEqualTypeOf<
      CryptoKey | CryptoKeyPair | Bytes
    >();
    expectTypeOf((alg: "HS256" | "ES256") => generateKey(alg)).returns.resolves.toEqualTypeOf<
      CryptoKey | CryptoKeyPair
    >();
    expectTypeOf((alg: GenerateKeyAlgorithm) =>
      generateKey(alg, { toJWK: true }),
    ).returns.resolves.toEqualTypeOf<GeneratedJWKMap[GenerateKeyAlgorithm]>();
    expectTypeOf((toJWK: boolean) =>
      generateKey("HS256", { toJWK }),
    ).returns.resolves.toEqualTypeOf<CryptoKey | (JWK_oct<"HS256"> & Named<"HS256">)>();
    expectTypeOf((options: GenerateKeyOptions) =>
      generateKey("ES256", options),
    ).returns.resolves.toEqualTypeOf<
      GeneratedKeyMap["ES256"] | GeneratedJWKMap<string | false>["ES256"]
    >();
  });

  it("types toPublicJWK after the input family", () => {
    expectTypeOf(toPublicJWK<JWK_RSA_Private<"RS256">>).returns.toEqualTypeOf<
      JWK_RSA_Public<"RS256">
    >();
    expectTypeOf(toPublicJWK<JWK_EC_Private<"ES256"> & Named<"ES256">>).returns.toEqualTypeOf<
      JWK_EC_Public<"ES256"> & { kid: string }
    >();
    expectTypeOf(toPublicJWK<JWK_OKP_Private<"Ed25519">>).returns.toEqualTypeOf<
      JWK_OKP_Public<"Ed25519">
    >();
    expectTypeOf(toPublicJWK<JWK_EC_Public<"ES256">>).returns.toEqualTypeOf<
      JWK_EC_Public<"ES256">
    >();
    expectTypeOf(
      toPublicJWK<JWK_EC_Private<"ECDH-ES"> | JWK_OKP_Private<"ECDH-ES">>,
    ).returns.toEqualTypeOf<JWK_EC_Public<"ECDH-ES"> | JWK_OKP_Public<"ECDH-ES">>();
    // @ts-expect-error an oct JWK has no public half
    expectTypeOf(() => toPublicJWK({} as JWK_oct)).toBeFunction();
  });

  it("types generateJWK after the JWK map", () => {
    expectTypeOf(() => generateJWK("A128GCM")).returns.resolves.toEqualTypeOf<
      JWK_oct<"A128GCM"> & Named<"A128GCM">
    >();
    expectTypeOf(() => generateJWK("PS256", { kid: "k1" })).returns.resolves.toEqualTypeOf<{
      privateKey: JWK_RSA_Private<"PS256"> & Named<"PS256">;
      publicKey: JWK_RSA_Public<"PS256"> & Named<"PS256">;
    }>();
    expectTypeOf((alg: "HS256" | "ES384") => generateJWK(alg)).returns.resolves.toEqualTypeOf<
      GeneratedJWKMap["HS256"] | GeneratedJWKMap["ES384"]
    >();
    expectTypeOf<GenerateJWKReturn<"EdDSA">>().toEqualTypeOf<GeneratedJWKMap["EdDSA"]>();
    expectTypeOf<GenerateKeyReturn<"RS512", { toJWK: true }>>().toEqualTypeOf<
      GeneratedJWKMap["RS512"]
    >();
    expectTypeOf<GenerateKeyReturn<"RS512", {}>>().toEqualTypeOf<CryptoKeyPair>();
  });

  it("types the generated kid after the kid option", () => {
    expectTypeOf(() => generateJWK("HS256", { kid: false })).returns.resolves.toEqualTypeOf<
      JWK_oct<"HS256"> & { alg: "HS256" }
    >();
    expectTypeOf(() => generateJWK("ES256", { kid: false })).returns.resolves.toEqualTypeOf<{
      privateKey: JWK_EC_Private<"ES256"> & { alg: "ES256" };
      publicKey: JWK_EC_Public<"ES256"> & { alg: "ES256" };
    }>();
    expectTypeOf(() => generateJWK("HS256", { kid: "k1" })).returns.resolves.toEqualTypeOf<
      JWK_oct<"HS256"> & Named<"HS256">
    >();
    expectTypeOf((kid: string | false) =>
      generateJWK("HS256", { kid }),
    ).returns.resolves.toEqualTypeOf<JWK_oct<"HS256"> & { alg: "HS256"; kid?: string }>();
    expectTypeOf(() =>
      generateKey("HS256", { toJWK: true, kid: false }),
    ).returns.resolves.toEqualTypeOf<JWK_oct<"HS256"> & { alg: "HS256" }>();
    expectTypeOf(() =>
      generateKey("RS256", { toJWK: true, kid: "k1" }),
    ).returns.resolves.toEqualTypeOf<GeneratedJWKMap["RS256"]>();
    expectTypeOf<GenerateKeyReturn<"HS256", { toJWK: true; kid: false }>>().toEqualTypeOf<
      GeneratedJWKMap<false>["HS256"]
    >();
    expectTypeOf<GenerateJWKReturn<"ES256", false>>().toEqualTypeOf<
      GeneratedJWKMap<false>["ES256"]
    >();
  });

  it("types importKey after the kind of key it is given", () => {
    expectTypeOf((key: Bytes) => importKey(key)).returns.resolves.toEqualTypeOf<Bytes>();
    expectTypeOf((key: CryptoKey) => importKey(key)).returns.resolves.toEqualTypeOf<CryptoKey>();
    expectTypeOf((key: JWK_oct<"HS256">) => importKey(key)).returns.resolves.toEqualTypeOf<Bytes>();
    expectTypeOf((key: JWK_EC_Public) =>
      importKey(key, "ES256"),
    ).returns.resolves.toEqualTypeOf<CryptoKey>();
    expectTypeOf((key: JWK_RSA_Private) =>
      importKey(key, { alg: "RS256", expect: "private" }),
    ).returns.resolves.toEqualTypeOf<CryptoKey>();
    expectTypeOf((key: JWK_OKP_Public) =>
      importKey(key),
    ).returns.resolves.toEqualTypeOf<CryptoKey>();
    expectTypeOf((key: JWK) => importKey(key)).returns.resolves.toEqualTypeOf<CryptoKey | Bytes>();
    expectTypeOf((key: CryptoKey | JWK_oct) => importKey(key)).returns.resolves.toEqualTypeOf<
      CryptoKey | Bytes
    >();
    expectTypeOf((key: JWK_oct) =>
      importKey(key, {
        asCryptoKey: true,
        algorithm: { name: "HMAC", hash: "SHA-256" },
        usage: ["sign"],
      }),
    ).returns.resolves.toEqualTypeOf<CryptoKey>();
    expectTypeOf<ImportedKey<JWK_EC_Private>>().toEqualTypeOf<ImportedKeyMap["asymmetric"]>();
  });

  it("types exportJWK as a JWK unless the caller narrows it", () => {
    expectTypeOf((key: CryptoKey) => exportJWK(key)).returns.resolves.toEqualTypeOf<JWK>();
    expectTypeOf((key: CryptoKey) =>
      exportJWK<JWK_oct>(key, { kid: "k1" }),
    ).returns.resolves.toEqualTypeOf<JWK_oct>();
  });

  it("types the wrapKey ECDH-ES epk and ephemeral key as EC or OKP", () => {
    expectTypeOf((cek: Bytes, recipient: CryptoKey) =>
      wrapKey(cek, recipient, { alg: "ECDH-ES+A128KW" }),
    )
      .returns.resolves.toHaveProperty("epk")
      .toEqualTypeOf<JWK_EC_Public | JWK_OKP_Public>();
    expectTypeOf((cek: Bytes, recipient: JWK_OKP_Public<"ECDH-ES">, ephemeral: JWK_OKP_Private) =>
      wrapKey(cek, recipient, {
        alg: "ECDH-ES",
        ecdh: { ephemeralKey: ephemeral, enc: "A128GCM" },
      }),
    )
      .returns.resolves.toHaveProperty("epk")
      .toEqualTypeOf<JWK_EC_Public | JWK_OKP_Public>();
    expectTypeOf((cek: Bytes, recipient: CryptoKey, pub: JWK_OKP_Public, priv: JWK_OKP_Private) =>
      wrapKey(cek, recipient, {
        alg: "ECDH-ES+A256KW",
        ecdh: { ephemeralKey: { publicKey: pub, privateKey: priv } },
      }),
    )
      .returns.resolves.toHaveProperty("encryptedKey")
      .toEqualTypeOf<Bytes>();
  });
});

/**
 * The canonical form of RFC 7638 §3.2 — the required members, lexicographically
 * ordered, with no whitespace — digested through Node's `crypto` so the vector
 * is independent of the implementation under test.
 */
function digestOfCanonical(
  members: Record<string, string | undefined>,
  hash: "sha256" | "sha384" | "sha512" = "sha256",
): string {
  const canonical = `{${Object.keys(members)
    .toSorted()
    .map((name) => `${JSON.stringify(name)}:${JSON.stringify(members[name])}`)
    .join(",")}}`;
  return createHash(hash).update(canonical, "utf8").digest("base64url");
}

/** A throwaway `A128KW` JWK, for calls whose other argument is what is on trial. */
function octKey(): JWK_oct<"A128KW"> {
  return {
    kty: "oct",
    alg: "A128KW",
    k: base64UrlStringify(new Uint8Array(16).fill(7)),
  };
}

/** The cache key recipe from configureJWKCache's JSDoc and the cache guide, verbatim. */
async function thumbprintCacheKey(jwk: JWK, alg: string): Promise<string> {
  return `${await thumbprint(jwk)}:${"d" in jwk ? "private" : "public"}:${alg}`;
}

/** `n` random bytes, base64url-encoded. */
function randomB64(n: number): string {
  return base64UrlStringify(secureRandomBytes(n));
}

function pemBlock(label: string, bytes: Uint8Array<ArrayBuffer>): string {
  return `-----BEGIN ${label}-----\n${(base64Stringify(bytes).match(/.{1,64}/g) ?? []).join(
    "\n",
  )}\n-----END ${label}-----\n`;
}

async function ecdhPair(namedCurve: "P-256" | "P-384"): Promise<CryptoKeyPair> {
  return await generateKey("ECDH-ES", { namedCurve });
}

describe("JSON-only JWK input", () => {
  it("reports JWK parameters JSON cannot carry as ERR_INVALID_OPTION", async () => {
    const { publicKey } = await generateKey("ES256");
    await expect(exportJWK(publicKey, { when: new Date(0) } as never)).rejects.toMatchObject({
      code: "ERR_INVALID_OPTION",
      cause: { code: "INVALID_TYPE" },
    });
  });

  it("reports a JWK member JSON cannot carry as ERR_JWK_INVALID", async () => {
    const { privateKey } = await generateJWK("ES256");
    expect(() => toPublicJWK({ ...privateKey, when: new Date(0) } as never)).toThrowError(
      expect.objectContaining({
        code: "ERR_JWK_INVALID",
        cause: expect.objectContaining({ code: "INVALID_TYPE" }),
      }),
    );
  });
});
