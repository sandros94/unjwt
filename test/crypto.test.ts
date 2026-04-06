import { describe, it, expect } from "vitest";

import { sign, verify } from "../src/core/_crypto/_sign-verify";
import {
  encrypt,
  decrypt,
  generateIV,
  generateCEK,
  bitLengthCEK,
  aesKwWrap,
  aesKwUnwrap,
  gcmkwEncrypt,
  gcmkwDecrypt,
} from "../src/core/_crypto/_aes";
import { encryptRSAES, decryptRSAES } from "../src/core/_crypto/_rsa";
import { deriveECDHESKey } from "../src/core/_crypto/_ecdh";
import { deriveKey as deriveKeyPBES2 } from "../src/core/_crypto/_pbes2";
import { jwkTokey, keyToJWK } from "../src/core/_crypto/_key-codec";
import { fromSPKI, fromPKCS8, toPKCS8, toSPKI } from "../src/core/_crypto/_pem";
import { textEncoder } from "../src/core/utils";
import { rsa, ec } from "./keys";

describe.concurrent("_crypto primitives", () => {
  // --- _sign-verify ---
  describe("_sign-verify", () => {
    it("sign/verify roundtrip — HS256", async () => {
      const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, [
        "sign",
        "verify",
      ]);
      const data = textEncoder.encode("hello");
      const sig = await sign("HS256", key, data);
      expect(await verify("HS256", key, sig, data)).toBe(true);
    });

    it("sign/verify roundtrip — RS256", async () => {
      const kp = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
      );
      const data = textEncoder.encode("hello");
      const sig = await sign("RS256", kp.privateKey, data);
      expect(await verify("RS256", kp.publicKey, sig, data)).toBe(true);
    });

    it("sign/verify roundtrip — ES256", async () => {
      const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
        "sign",
        "verify",
      ]);
      const data = textEncoder.encode("hello");
      const sig = await sign("ES256", kp.privateKey, data);
      expect(await verify("ES256", kp.publicKey, sig, data)).toBe(true);
    });

    it("sign/verify roundtrip — Ed25519", async () => {
      const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
      const data = textEncoder.encode("hello");
      const sig = await sign("Ed25519", kp.privateKey as CryptoKey, data);
      expect(await verify("Ed25519", (kp as CryptoKeyPair).publicKey, sig, data)).toBe(true);
    });

    it("rejects tampered data", async () => {
      const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, [
        "sign",
        "verify",
      ]);
      const data = textEncoder.encode("hello");
      const sig = await sign("HS256", key, data);
      expect(await verify("HS256", key, sig, textEncoder.encode("tampered"))).toBe(false);
    });
  });

  // --- _aes ---
  describe("_aes: content encryption", () => {
    it("AES-GCM encrypt/decrypt roundtrip", async () => {
      const cek = generateCEK("A256GCM");
      const iv = generateIV("A256GCM");
      const plaintext = textEncoder.encode("secret message");
      const aad = textEncoder.encode("header");

      const { ciphertext, tag } = await encrypt("A256GCM", plaintext, cek, iv, aad);
      const result = await decrypt("A256GCM", cek, ciphertext, iv, tag, aad);
      expect(result).toEqual(plaintext);
    });

    it("AES-CBC-HS256 encrypt/decrypt roundtrip", async () => {
      const cek = generateCEK("A128CBC-HS256");
      expect(cek.length).toBe(bitLengthCEK("A128CBC-HS256") / 8);
      const iv = generateIV("A128CBC-HS256");
      const plaintext = textEncoder.encode("secret message");
      const aad = textEncoder.encode("header");

      const { ciphertext, tag } = await encrypt("A128CBC-HS256", plaintext, cek, iv, aad);
      const result = await decrypt("A128CBC-HS256", cek, ciphertext, iv, tag, aad);
      expect(result).toEqual(plaintext);
    });

    it("generateCEK produces correct bit lengths", () => {
      expect(generateCEK("A128GCM").length).toBe(16);
      expect(generateCEK("A192GCM").length).toBe(24);
      expect(generateCEK("A256GCM").length).toBe(32);
      expect(generateCEK("A128CBC-HS256").length).toBe(32);
      expect(generateCEK("A256CBC-HS512").length).toBe(64);
    });

    it("generateIV produces correct bit lengths", () => {
      expect(generateIV("A128GCM").length).toBe(12);
      expect(generateIV("A128CBC-HS256").length).toBe(16);
    });
  });

  describe("_aes: AES-KW", () => {
    it("aesKwWrap/aesKwUnwrap roundtrip — A128KW", async () => {
      const wrapKey = await crypto.subtle.generateKey({ name: "AES-KW", length: 128 }, true, [
        "wrapKey",
        "unwrapKey",
      ]);
      const cek = generateCEK("A128GCM");
      const wrapped = await aesKwWrap("A128KW", wrapKey, cek);
      const unwrapped = await aesKwUnwrap("A128KW", wrapKey, wrapped);
      expect(unwrapped).toEqual(cek);
    });

    it("aesKwWrap/aesKwUnwrap roundtrip — A256KW with Uint8Array key", async () => {
      const wrapKeyBytes = crypto.getRandomValues(new Uint8Array(32));
      const cek = generateCEK("A256GCM");
      const wrapped = await aesKwWrap("A256KW", wrapKeyBytes, cek);
      const unwrapped = await aesKwUnwrap("A256KW", wrapKeyBytes, wrapped);
      expect(unwrapped).toEqual(cek);
    });
  });

  describe("_aes: AES-GCMKW", () => {
    it("gcmkwEncrypt/gcmkwDecrypt roundtrip", async () => {
      const wrapKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 128 }, true, [
        "encrypt",
        "decrypt",
      ]);
      const cek = generateCEK("A128GCM");
      const { encryptedKey, iv, tag } = await gcmkwEncrypt("A128GCMKW", wrapKey, cek);

      const ivBytes = Uint8Array.from(
        atob(iv.replace(/-/g, "+").replace(/_/g, "/")),
        (c) => c.codePointAt(0)!,
      );
      const tagBytes = Uint8Array.from(
        atob(tag.replace(/-/g, "+").replace(/_/g, "/")),
        (c) => c.codePointAt(0)!,
      );

      const unwrapped = await gcmkwDecrypt("A128GCMKW", wrapKey, encryptedKey, ivBytes, tagBytes);
      expect(unwrapped).toEqual(cek);
    });
  });

  // --- _rsa ---
  describe("_rsa: RSA-OAEP", () => {
    it("encryptRSAES/decryptRSAES roundtrip", async () => {
      const kp = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"],
      );
      const cek = generateCEK("A256GCM");
      const encrypted = await encryptRSAES("RSA-OAEP-256", kp.publicKey, cek);
      const decrypted = await decryptRSAES("RSA-OAEP-256", kp.privateKey, encrypted);
      expect(decrypted).toEqual(cek);
    });
  });

  // --- _ecdh ---
  describe("_ecdh: ECDH-ES key derivation", () => {
    it("deriveECDHESKey roundtrip — P-256", async () => {
      const recipientKP = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
      );
      const ephemeralKP = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
      );

      const senderDerived = await deriveECDHESKey(
        recipientKP.publicKey,
        ephemeralKP.privateKey,
        "ECDH-ES+A128KW",
        128,
      );
      const recipientDerived = await deriveECDHESKey(
        ephemeralKP.publicKey,
        recipientKP.privateKey,
        "ECDH-ES+A128KW",
        128,
      );

      expect(senderDerived).toEqual(recipientDerived);
      expect(senderDerived.length).toBe(16);
    });

    it("deriveECDHESKey roundtrip — X25519", async () => {
      const recipientKP = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
      const ephemeralKP = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);

      const senderDerived = await deriveECDHESKey(
        (recipientKP as CryptoKeyPair).publicKey,
        (ephemeralKP as CryptoKeyPair).privateKey,
        "A256GCM",
        256,
      );
      const recipientDerived = await deriveECDHESKey(
        (ephemeralKP as CryptoKeyPair).publicKey,
        (recipientKP as CryptoKeyPair).privateKey,
        "A256GCM",
        256,
      );

      expect(senderDerived).toEqual(recipientDerived);
      expect(senderDerived.length).toBe(32);
    });
  });

  // --- _pbes2 ---
  describe("_pbes2: PBES2 key derivation", () => {
    it("deriveKeyPBES2 is deterministic with same inputs", async () => {
      const password = textEncoder.encode("hunter2");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const alg = "PBES2-HS256+A128KW";
      const p2c = 1000;

      const [first, second] = await Promise.all([
        deriveKeyPBES2(salt, alg, p2c, password),
        deriveKeyPBES2(salt, alg, p2c, password),
      ]);

      expect(first).toEqual(second);
      expect(first.length).toBe(16);
    });

    it("deriveKeyPBES2 produces different output for different salts", async () => {
      const password = textEncoder.encode("hunter2");
      const salt1 = crypto.getRandomValues(new Uint8Array(16));
      const salt2 = crypto.getRandomValues(new Uint8Array(16));
      const alg = "PBES2-HS256+A128KW";

      const [d1, d2] = await Promise.all([
        deriveKeyPBES2(salt1, alg, 1000, password),
        deriveKeyPBES2(salt2, alg, 1000, password),
      ]);

      expect(d1).not.toEqual(d2);
    });
  });

  // --- _key-codec ---
  describe("_key-codec: JWK ↔ CryptoKey", () => {
    it("jwkTokey / keyToJWK roundtrip — EC private", async () => {
      const cryptoKey = await jwkTokey(ec.jwk.private);
      expect(cryptoKey).toBeInstanceOf(CryptoKey);
      expect(cryptoKey.type).toBe("private");

      const exported = await keyToJWK(cryptoKey);
      expect(exported.kty).toBe("EC");
      expect((exported as any).d).toBe(ec.jwk.private.d);
    });

    it("jwkTokey / keyToJWK roundtrip — RSA public", async () => {
      const cryptoKey = await jwkTokey(rsa.jwk.public);
      expect(cryptoKey).toBeInstanceOf(CryptoKey);
      expect(cryptoKey.type).toBe("public");

      const exported = await keyToJWK(cryptoKey);
      expect(exported.kty).toBe("RSA");
      expect((exported as any).n).toBe(rsa.jwk.public.n);
    });

    it("keyToJWK — Uint8Array produces oct JWK", async () => {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      const jwk = await keyToJWK(raw);
      expect(jwk.kty).toBe("oct");
      expect(typeof (jwk as any).k).toBe("string");
    });
  });

  // --- _pem ---
  describe("_pem: PEM import/export", () => {
    it("fromSPKI / toSPKI roundtrip — RSA public", async () => {
      const cryptoKey = await fromSPKI(rsa.pem.spki, "RS256");
      expect(cryptoKey.type).toBe("public");
      const pem = await toSPKI(cryptoKey);
      expect(pem).toContain("-----BEGIN PUBLIC KEY-----");
    });

    it("fromPKCS8 / toPKCS8 roundtrip — RSA private", async () => {
      const cryptoKey = await fromPKCS8(rsa.pem.pkcs8, "RS256", { extractable: true });
      expect(cryptoKey.type).toBe("private");
      const pem = await toPKCS8(cryptoKey);
      expect(pem).toContain("-----BEGIN PRIVATE KEY-----");
    });

    it("fromSPKI / toSPKI roundtrip — EC public", async () => {
      const cryptoKey = await fromSPKI(ec.pem.spki, "ES256");
      expect(cryptoKey.type).toBe("public");
      const pem = await toSPKI(cryptoKey);
      expect(pem).toContain("-----BEGIN PUBLIC KEY-----");
    });

    it("fromPKCS8 / toPKCS8 roundtrip — EC private", async () => {
      const cryptoKey = await fromPKCS8(ec.pem.pkcs8, "ES256", { extractable: true });
      expect(cryptoKey.type).toBe("private");
      const pem = await toPKCS8(cryptoKey);
      expect(pem).toContain("-----BEGIN PRIVATE KEY-----");
    });
  });
});
