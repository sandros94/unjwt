import * as jose from "jose";
import { describe, it, expect, beforeAll } from "vitest";
import { encrypt, decrypt, JWTError, isJWTError } from "../src/core/jwe";
import { generateKey, generateJWK, exportKey, unwrapKey, wrapKey } from "../src/core/jwk";
import {
  randomBytes,
  textEncoder,
  textDecoder,
  base64UrlEncode,
  base64UrlDecode,
} from "../src/core/utils";
import type {
  JWK,
  JWK_Symmetric,
  JWK_Public,
  JWK_Private,
  JWK_EC_Public,
  JWTClaims,
  JWKLookupFunction,
  JWEHeaderParameters,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
} from "../src/core/types";

describe.concurrent("JWE Utilities", () => {
  const plaintextObj: JWTClaims = {
    sub: "1234567890",
    name: "John Doe",
    iat: 1_516_239_022,
  };
  const plaintextString = "This is a plaintext string.";
  const plaintextBytes = textEncoder.encode("This is a plaintext as Uint8Array.");

  interface TestKeySet {
    key?: CryptoKey | CryptoKeyPair | string; // string for password
    publicKey?: CryptoKey | JWK_Symmetric | JWK_Public;
    privateKey?: CryptoKey | JWK_Symmetric | JWK_Private;
    password?: string;
  }
  const keys: Record<string, TestKeySet> = {};

  beforeAll(async () => {
    const [
      a128kw,
      a192kw,
      a256kw,
      a128gcm,
      a192gcm,
      a256gcm,
      rsaOaepPair,
      rsaOaep256Pair,
      rsaOaep384Pair,
      rsaOaep512Pair,
      ecdhKeyPair,
    ] = await Promise.all([
      generateKey("A128KW"),
      generateKey("A192KW"),
      generateKey("A256KW"),
      generateKey("A128GCM"),
      generateKey("A192GCM"),
      generateKey("A256GCM"),
      generateKey("RSA-OAEP", { modulusLength: 2048 }),
      generateKey("RSA-OAEP-256", {
        modulusLength: 2048,
      }),
      generateKey("RSA-OAEP-384", {
        modulusLength: 2048,
      }),
      generateKey("RSA-OAEP-512", {
        modulusLength: 2048,
      }),
      generateKey("ECDH-ES+A128KW", { namedCurve: "P-256" }),
    ]);

    keys["A128KW"] = { key: a128kw };
    keys["A192KW"] = { key: a192kw };
    keys["A256KW"] = { key: a256kw };

    keys["A128GCMKW"] = { key: a128gcm };
    keys["A192GCMKW"] = { key: a192gcm };
    keys["A256GCMKW"] = { key: a256gcm };

    keys["RSA-OAEP"] = {
      key: rsaOaepPair,
      publicKey: rsaOaepPair.publicKey,
      privateKey: rsaOaepPair.privateKey,
    };
    keys["RSA-OAEP-256"] = {
      key: rsaOaep256Pair,
      publicKey: rsaOaep256Pair.publicKey,
      privateKey: rsaOaep256Pair.privateKey,
    };
    keys["RSA-OAEP-384"] = {
      key: rsaOaep384Pair,
      publicKey: rsaOaep384Pair.publicKey,
      privateKey: rsaOaep384Pair.privateKey,
    };
    keys["RSA-OAEP-512"] = {
      key: rsaOaep512Pair,
      publicKey: rsaOaep512Pair.publicKey,
      privateKey: rsaOaep512Pair.privateKey,
    };

    keys["PBES2-HS256+A128KW"] = { password: "securepassword123" };

    keys["ECDH-ES+A128KW"] = {
      key: ecdhKeyPair,
      publicKey: ecdhKeyPair.publicKey,
      privateKey: ecdhKeyPair.privateKey,
    };
  });

  const testScenarios: {
    alg: KeyManagementAlgorithm;
    enc: ContentEncryptionAlgorithm;
    plaintext: Record<string, unknown> | string | Uint8Array<ArrayBuffer>;
    desc: string;
  }[] = [
    {
      alg: "A128KW",
      enc: "A128GCM",
      plaintext: plaintextObj,
      desc: "A128KW with A128GCM (Object)",
    },
    {
      alg: "A192KW",
      enc: "A192GCM",
      plaintext: plaintextString,
      desc: "A192KW with A192GCM (String)",
    },
    {
      alg: "A256KW",
      enc: "A256GCM",
      plaintext: plaintextBytes,
      desc: "A256KW with A256GCM (Bytes)",
    },
    {
      alg: "A128GCMKW",
      enc: "A128CBC-HS256",
      plaintext: plaintextObj,
      desc: "A128GCMKW with A128CBC-HS256",
    },
    {
      alg: "A256GCMKW",
      enc: "A256GCM",
      plaintext: plaintextString,
      desc: "A256GCMKW with A256GCM",
    },
    {
      alg: "RSA-OAEP",
      enc: "A128GCM",
      plaintext: plaintextObj,
      desc: "RSA-OAEP with A128GCM",
    },
    {
      alg: "RSA-OAEP-256",
      enc: "A128CBC-HS256",
      plaintext: plaintextBytes,
      desc: "RSA-OAEP-256 with A128CBC-HS256",
    },
    {
      alg: "RSA-OAEP-384",
      enc: "A192CBC-HS384",
      plaintext: plaintextBytes,
      desc: "RSA-OAEP-384 with A192CBC-HS384",
    },
    {
      alg: "RSA-OAEP-512",
      enc: "A256CBC-HS512",
      plaintext: plaintextBytes,
      desc: "RSA-OAEP-512 with A256CBC-HS512",
    },
    {
      alg: "PBES2-HS256+A128KW",
      enc: "A128GCM",
      plaintext: plaintextString,
      desc: "PBES2-HS256+A128KW with A128GCM",
    },
  ];

  for (const { alg, enc, plaintext, desc } of testScenarios) {
    describe(desc, () => {
      it(`should encrypt and decrypt successfully`, async () => {
        let encryptionKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>;
        let decryptionKey:
          | CryptoKey
          | JWK_Symmetric
          | JWK_Private
          | string
          | Uint8Array<ArrayBuffer>
          | JWKLookupFunction;
        let plaintextBuffer: Uint8Array;

        const keySet = keys[alg as string];
        if (!keySet) throw new Error(`Key for ${alg} not found`);

        if (alg.startsWith("RSA-") || alg.startsWith("ECDH-ES")) {
          encryptionKey = keySet.publicKey!;
          decryptionKey = keySet.privateKey!;
        } else if (alg.startsWith("PBES2")) {
          const password = keySet.password!;
          encryptionKey = textEncoder.encode(password);
          decryptionKey = textEncoder.encode(password);
        } else {
          encryptionKey = keySet.key as CryptoKey;
          decryptionKey = keySet.key as CryptoKey;
        }

        if (typeof plaintext === "string") {
          plaintextBuffer = textEncoder.encode(plaintext);
        } else if (plaintext instanceof Uint8Array) {
          plaintextBuffer = plaintext;
        } else {
          plaintextBuffer = textEncoder.encode(JSON.stringify(plaintext));
        }

        const jwe = await encrypt(plaintext, encryptionKey, {
          alg,
          enc,
        });

        // jose doesn't support PBES2-HS256+A128KW alg header
        if (alg !== "PBES2-HS256+A128KW") {
          const { plaintext: decryptedByJose } = await jose.compactDecrypt(jwe, decryptionKey);
          expect(decryptedByJose).toEqual(plaintextBuffer);
        }

        const jweFromJose = await new jose.CompactEncrypt(plaintextBuffer)
          .setProtectedHeader({ alg, enc, cty: "application/json" })
          .encrypt(encryptionKey);

        const { payload: decrypted } = await decrypt(jweFromJose, decryptionKey);

        if (typeof plaintext === "object" && !(plaintext instanceof Uint8Array)) {
          expect(decrypted).toEqual(plaintext);
        } else if (typeof plaintext === "string") {
          expect(decrypted).toEqual(plaintext);
        } else {
          expect(textEncoder.encode(decrypted as any)).toEqual(plaintext);
        }
      });
    });
  }

  describe("encrypt specific options", () => {
    it("should encrypt and decrypt while only providing a password", async () => {
      const t = "Hello, World!";
      const p = "password";

      const jwe = await encrypt(t, p);
      const { payload } = await decrypt(jwe, p);

      expect(payload).toBe(t);

      // jose doesn't support PBES2-HS256+A128KW alg header
    });

    it("should encrypt and decrypt while only providing a JWK", async () => {
      const t = "Hello, World!";
      const jwk: JWK = {
        key_ops: ["wrapKey", "unwrapKey", "encrypt", "decrypt"],
        ext: true,
        kty: "oct",
        k: "mzR5rkgr41d-4e_fVMYQ1g",
        alg: "A128KW",
      };

      const jwe = await encrypt(t, jwk);
      const { payload } = await decrypt(jwe, jwk);

      expect(payload).toBe(t);

      const joseKey = await jose.importJWK(jwk);
      const { plaintext: josePlaintext } = await jose.compactDecrypt(jwe, joseKey);
      expect(textDecoder.decode(josePlaintext)).toBe(t);
    });

    // M13: `alg` is inferred from the JWK verbatim; no silent `A*GCM → A*GCMKW` coercion.
    it("encrypts a GCMKW oct JWK via its declared alg without coercion", async () => {
      const jwk = await generateJWK("A256GCMKW");
      expect(jwk.alg).toBe("A256GCMKW"); // generateJWK now preserves KW suffix
      const jwe = await encrypt("payload", jwk, { enc: "A256GCM" });
      const header = JSON.parse(base64UrlDecode(jwe.split(".")[0]));
      expect(header.alg).toBe("A256GCMKW");
      const { payload } = await decrypt(jwe, jwk);
      expect(payload).toBe("payload");
    });

    it("rejects an oct JWK with alg=A256GCM used for key wrap without explicit alg", async () => {
      // The library no longer rewrites `A256GCM` on an oct JWK into `A256GCMKW`.
      // Callers who want key wrap must supply `alg` explicitly.
      const jwk = await generateJWK("A256GCM");
      expect(jwk.alg).toBe("A256GCM");
      await expect(encrypt("payload", jwk)).rejects.toThrow(/Invalid or unsupported "alg"/i);
      // With explicit alg, the caller's intent is honoured.
      const jwe = await encrypt("payload", jwk, { alg: "A256GCMKW", enc: "A256GCM" });
      const header = JSON.parse(base64UrlDecode(jwe.split(".")[0]));
      expect(header.alg).toBe("A256GCMKW");
    });

    it("should use provided CEK and contentEncryptionIV", async () => {
      const alg: KeyManagementAlgorithm = "A128KW";
      const enc: ContentEncryptionAlgorithm = "A128GCM";
      const key = keys[alg]!.key as CryptoKey;

      const customCek = randomBytes(128 / 8); // 128 bits for A128GCM
      const customIv = randomBytes(96 / 8); // 96 bits for A128GCM

      const jwe = await encrypt(plaintextString, key, {
        alg,
        enc,
        cek: customCek,
        contentEncryptionIV: customIv,
      });

      const { payload: decryptedPayload } = await decrypt(jwe, key);
      expect(decryptedPayload).toBe(plaintextString);
      // Note: We can't directly compare the CEK after it's been wrapped and unwrapped
      // unless we unwrap it manually here. But we can check the IV.
      const jweParts = jwe.split(".");
      const decodedIv = base64UrlDecode(jweParts[2], false);
      expect(decodedIv).toEqual(customIv);
    });

    it("should decrypt with explicit unwrappedKeyAlgorithm option", async () => {
      const alg: KeyManagementAlgorithm = "A128KW";
      const enc: ContentEncryptionAlgorithm = "A128GCM";
      const key = keys[alg]!.key as CryptoKey;

      const jwe = await encrypt(plaintextObj, key, { alg, enc });
      const { payload } = await decrypt(jwe, key, {
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(payload).toEqual(plaintextObj);
    });

    it("should throw if alg is missing", async () => {
      const key = keys["A128KW"]!.key as CryptoKey;
      await expect(encrypt(plaintextString, key, { enc: "A128GCM" } as any)).rejects.toThrow(
        'JWE "alg" (Key Management Algorithm) must be provided in options',
      );
    });

    it("should throw for invalid payload type (null)", async () => {
      const key = keys["A128KW"]!.key as CryptoKey;
      await expect(
        // @ts-expect-error intentionally invalid payload
        encrypt(null, key, { alg: "A128KW", enc: "A128GCM" }),
      ).rejects.toThrow(/Plaintext must be/i);
    });

    // M11: entry points pin `expect` so wrong-direction asymmetric keys fail at import.
    it("rejects a private recipient JWK passed to encrypt()", async () => {
      const { privateKey, publicKey } = await generateJWK(
        "RSA-OAEP-256",
        {},
        { modulusLength: 2048 },
      );
      // Sanity: public key encrypts normally.
      await expect(
        encrypt(plaintextObj, publicKey, { alg: "RSA-OAEP-256", enc: "A256GCM" }),
      ).resolves.toBeTypeOf("string");
      // Passing the private JWK to encrypt is the threat M11 closes.
      await expect(
        encrypt(plaintextObj, privateKey, { alg: "RSA-OAEP-256", enc: "A256GCM" }),
      ).rejects.toThrow(expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }));
    });

    it("rejects a public recipient JWK passed to decrypt()", async () => {
      const { privateKey, publicKey } = await generateJWK(
        "RSA-OAEP-256",
        {},
        { modulusLength: 2048 },
      );
      const jwe = await encrypt(plaintextObj, publicKey, {
        alg: "RSA-OAEP-256",
        enc: "A256GCM",
      });
      // Sanity: private key decrypts normally.
      await expect(decrypt(jwe, privateKey)).resolves.toBeDefined();
      // Public JWK on the decrypt side is already rejected by `decrypt`'s TS union;
      // cast past it to exercise the runtime M11 guard for callers that use `as any`.
      await expect(decrypt(jwe, publicKey as any)).rejects.toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
      );
    });
  });

  describe("PBES2 p2c bounds", () => {
    const password = textEncoder.encode("securepassword123");
    const alg: KeyManagementAlgorithm = "PBES2-HS256+A128KW";

    it("rejects p2c below the default minimum of 1000 iterations", async () => {
      const cek = randomBytes(32);
      const p2s = randomBytes(16);
      const { encryptedKey } = await wrapKey(alg, cek, password, { p2c: 500, p2s });
      await expect(
        unwrapKey(alg, encryptedKey, password, { p2c: 500, p2s, format: "raw" }),
      ).rejects.toThrow(/"p2c" below the minimum of 1000/);
    });

    it("rejects p2c above the default maximum of 1_000_000 iterations", async () => {
      // The bounds check fires before PBKDF2, so no need to actually wrap at that iteration count.
      const p2s = randomBytes(16);
      await expect(
        unwrapKey(alg, randomBytes(40), password, {
          p2c: 1_000_001,
          p2s,
          format: "raw",
        }),
      ).rejects.toThrow(/"p2c" above the maximum of 1000000/);
    });

    it("accepts p2c at the default floor of 1000 iterations", async () => {
      const cek = randomBytes(32);
      const p2s = randomBytes(16);
      const { encryptedKey } = await wrapKey(alg, cek, password, { p2c: 1000, p2s });
      const unwrapped = await unwrapKey(alg, encryptedKey, password, {
        p2c: 1000,
        p2s,
        format: "raw",
      });
      expect(unwrapped).toEqual(cek);
    });

    it("honours caller-supplied minIterations override", async () => {
      const cek = randomBytes(32);
      const p2s = randomBytes(16);
      const { encryptedKey } = await wrapKey(alg, cek, password, { p2c: 500, p2s });
      // Below default floor (1000), but a caller-supplied floor of 100 accepts it.
      const unwrapped = await unwrapKey(alg, encryptedKey, password, {
        p2c: 500,
        p2s,
        format: "raw",
        minIterations: 100,
      });
      expect(unwrapped).toEqual(cek);
    });
  });

  describe("dir (direct key agreement)", () => {
    it("encrypt/decrypt roundtrip with AES-GCM content encryption", async () => {
      const key = await generateKey("A256GCM");
      const plaintext = "direct encryption test";

      const jwe = await encrypt(plaintext, key, { alg: "dir", enc: "A256GCM" });
      const parts = jwe.split(".");
      expect(parts[1]).toBe(""); // encrypted key field is empty

      const { payload } = await decrypt(jwe, key);
      expect(payload).toBe(plaintext);
    });

    it("encrypt/decrypt roundtrip with AES-CBC content encryption", async () => {
      const cek = randomBytes(32); // A128CBC-HS256 needs 256-bit key
      const plaintext = "direct CBC test";

      const jwe = await encrypt(plaintext, cek, { alg: "dir", enc: "A128CBC-HS256" });
      const { payload } = await decrypt(jwe, cek);
      expect(payload).toBe(plaintext);
    });

    it("encrypt/decrypt roundtrip with a JWK_oct key", async () => {
      const jwk = await generateJWK("A256GCM");
      const plaintext = "JWK dir test";

      const jwe = await encrypt(plaintext, jwk, { alg: "dir", enc: "A256GCM" });
      const { payload } = await decrypt(jwe, jwk);
      expect(payload).toBe(plaintext);
    });

    it("enc is inferred from the JWK_oct enc field when not provided in options", async () => {
      const jwk = { ...(await generateJWK("A256GCM")), enc: "A256GCM" as const };
      const plaintext = "JWK dir enc inference";

      // enc not specified in options — should be read from jwk.enc
      const jwe = await encrypt(plaintext, jwk, { alg: "dir" });
      const { payload } = await decrypt(jwe, jwk);
      expect(payload).toBe(plaintext);
    });

    it("throws when enc is not provided for dir", async () => {
      const key = await generateKey("A128GCM");
      await expect(
        // @ts-expect-error intentionally missing enc
        encrypt("test", key, { alg: "dir" }),
      ).rejects.toThrow('"enc" must be provided');
    });
  });

  describe("decrypt specific options and errors", () => {
    let jwe: string;
    const alg: KeyManagementAlgorithm = "A128KW";
    const enc: ContentEncryptionAlgorithm = "A128GCM";
    let key: CryptoKey;
    let joseKey: jose.CryptoKey | Uint8Array;

    beforeAll(async () => {
      key = keys[alg]!.key as CryptoKey;
      joseKey = await jose.importJWK(await exportKey(key));
      jwe = await encrypt(plaintextObj, key, { alg, enc });
    });

    it("should decrypt with JWKSet from lookup by trying multiple keys when no kid is present", async () => {
      // Two AES-KW keys without kid — encrypt with key2, set has key1 first so retry is exercised
      const [rawKey1, rawKey2] = await Promise.all([generateKey("A256KW"), generateKey("A256KW")]);
      const token = await encrypt(plaintextObj, rawKey2, { alg: "A256KW", enc: "A256GCM" });
      const [jwk1, jwk2] = await Promise.all([
        exportKey(rawKey1, { alg: "A256KW" }),
        exportKey(rawKey2, { alg: "A256KW" }),
      ]);
      const set = { keys: [jwk1, jwk2] };
      const { payload } = await decrypt(token, set);
      expect(payload).toEqual(plaintextObj);
    });

    // Unwrap / AEAD failures are "try next"; malformed JWKs must surface immediately.
    it("surfaces malformed JWK errors instead of silently skipping to a valid candidate", async () => {
      const rawValid = await generateKey("A256KW");
      const validJwk = await exportKey(rawValid, { alg: "A256KW" });
      // kty=RSA with alg=A256KW is nonsensical — `subtleMapping` rejects the combination.
      // The fake `d` field satisfies M11's `expect: "private"` intent check so the alg
      // mismatch surfaces (rather than the intent check short-circuiting first).
      const malformedJwk = { kty: "RSA", alg: "A256KW", d: "fake" } as unknown as JWK;
      const token = await encrypt(plaintextObj, rawValid, { alg: "A256KW", enc: "A256GCM" });

      const set = { keys: [malformedJwk, validJwk] };
      await expect(decrypt(token, set)).rejects.toThrow(/Invalid or unsupported JWK "alg"/);
    });

    it("should decrypt with a key lookup function", async () => {
      const keyLookup: JWKLookupFunction = (header) => {
        if (header.alg === alg) return key;
        throw new Error("Key not found");
      };
      const { payload } = await decrypt(jwe, keyLookup);
      expect(payload).toEqual(plaintextObj);

      const { payload: josePayload } = await jose.jwtDecrypt(jwe, joseKey);
      expect(josePayload).toEqual(plaintextObj);
    });

    it("should throw if JWE has incorrect number of parts", async () => {
      await expect(decrypt("a.b.c.d", key)).rejects.toThrow(
        "Invalid JWE: Must contain five sections (RFC7516, section-3).",
      );
    });

    it("should throw if protected header is not valid Base64URL", async () => {
      const parts = jwe.split(".");
      parts[0] = "not-base64!";
      await expect(decrypt(parts.join("."), key)).rejects.toThrow(
        "Protected header could not be decoded",
      );
    });

    it("should throw if protected header is not valid JSON", async () => {
      const parts = jwe.split(".");
      parts[0] = base64UrlEncode("not json");
      await expect(decrypt(parts.join("."), key)).rejects.toThrow(
        "Protected header could not be decoded",
      );
    });

    it("should throw if protected header is missing alg or enc", async () => {
      const invalidHeader = base64UrlEncode(JSON.stringify({ foo: "bar" }));
      const parts = jwe.split(".");
      parts[0] = invalidHeader;
      await expect(decrypt(parts.join("."), key)).rejects.toThrow(
        'Invalid JWE: Protected header must be an object with "alg" and "enc" properties.',
      );
    });

    it("should throw if key management algorithm not allowed", async () => {
      await expect(decrypt(jwe, key, { algorithms: ["A256KW"] })).rejects.toThrow(
        `Key management algorithm not allowed: ${alg}`,
      );

      await expect(
        jose.compactDecrypt(jwe, joseKey, {
          keyManagementAlgorithms: ["A256KW"],
        }),
      ).rejects.toThrow('"alg" (Algorithm) Header Parameter value not allowed');
    });

    // Absent `options.algorithms` falls back to inference from the key shape.
    // The token's declared `alg` must be in the inferred set or decryption fails closed.
    it("infers the algorithm allowlist from a JWK when options.algorithms is absent", async () => {
      const kwJwk = await exportKey<JWK_Symmetric>(await generateKey("A128KW"), { alg: "A128KW" });
      const token = await encrypt(plaintextObj, kwJwk, { alg: "A128KW", enc: "A128GCM" });
      // JWK with alg: "A128KW" infers to ["A128KW", "dir"].
      await expect(decrypt(token, kwJwk)).resolves.toBeDefined();
      // A forged header claiming a different key management alg is rejected.
      const [, encKeyPart, ivPart, ctPart, tagPart] = token.split(".");
      const forgedHeader = base64UrlEncode(JSON.stringify({ alg: "A256KW", enc: "A128GCM" }));
      await expect(
        decrypt(`${forgedHeader}.${encKeyPart}.${ivPart}.${ctPart}.${tagPart}`, kwJwk),
      ).rejects.toThrow("Key management algorithm not allowed: A256KW");
    });

    it("should throw if content encryption algorithm not allowed", async () => {
      await expect(decrypt(jwe, key, { encryptionAlgorithms: ["A256GCM"] })).rejects.toThrow(
        `Content encryption algorithm not allowed: ${enc}`,
      );

      await expect(
        jose.compactDecrypt(jwe, joseKey, {
          contentEncryptionAlgorithms: ["A256GCM"],
        }),
      ).rejects.toThrow('"enc" (Encryption Algorithm) Header Parameter value not allowed');
    });

    it("should throw for decryption failure (e.g., wrong key)", async () => {
      const wrongKey = await generateKey("A128KW");
      await expect(decrypt(jwe, wrongKey)).rejects.toThrow();

      const wrongJoseKey = await jose.importJWK(await exportKey(wrongKey));
      await expect(jose.compactDecrypt(jwe, wrongJoseKey)).rejects.toThrow();
    });

    it("should handle critical headers correctly", async () => {
      const jweCrit = await encrypt(plaintextString, key, {
        alg,
        enc,
        protectedHeader: { crit: ["exp"], exp: 1_234_567_890 },
      });

      // Decrypts fine if "exp" is understood (e.g. by being in options.critical)
      await expect(decrypt(jweCrit, key, { recognizedHeaders: ["exp"] })).resolves.toBeDefined();
      await expect(
        jose.compactDecrypt(jweCrit, joseKey, { crit: { exp: true } }),
      ).resolves.toBeDefined();

      // Throws if "exp" is critical but not in options.critical
      const jweUnknownCrit = await encrypt(plaintextString, key, {
        alg,
        enc,
        protectedHeader: { crit: ["unknownParam"], unknownParam: true },
      });
      await expect(decrypt(jweUnknownCrit, key)).rejects.toThrow(
        "Unprocessed critical header parameters: unknownParam",
      );
      await expect(jose.compactDecrypt(jweUnknownCrit, joseKey)).rejects.toThrow(
        'Extension Header Parameter "unknownParam" is not recognized',
      );
    });

    // RFC 7516 §4.1.13 — registered params the library does not process must not be treated as
    // implicitly understood. `jwk`/`jku`/`x5c`/`x5t`/`x5u` require explicit `recognizedHeaders`.
    it.each(["jwk", "jku", "x5c", "x5t", "x5u"])(
      "rejects '%s' in crit without explicit recognizedHeaders",
      async (param) => {
        const jweCrit = await encrypt(plaintextString, key, {
          alg,
          enc,
          protectedHeader: { crit: [param], [param]: "irrelevant" },
        });
        await expect(decrypt(jweCrit, key)).rejects.toThrow(
          `Unprocessed critical header parameters: ${param}`,
        );
        await expect(decrypt(jweCrit, key, { recognizedHeaders: [param] })).resolves.toBeDefined();
      },
    );

    it("should correctly parse plaintext as JSON or string based on typ/cty", async () => {
      // 1. typ: "JWT"
      const jweJwt = await encrypt(plaintextObj, key, {
        alg,
        enc,
        protectedHeader: { typ: "JWT" },
      });
      const resJwt = await decrypt<JWTClaims>(jweJwt, key);
      expect(resJwt.payload).toEqual(plaintextObj);
      expect(typeof resJwt.payload).toBe("object");

      // 2. cty: "application/json"
      const jweJsonCty = await encrypt(plaintextObj, key, {
        alg,
        enc,
        protectedHeader: { cty: "application/json" },
      });
      const resJsonCty = await decrypt<JWTClaims>(jweJsonCty, key);
      expect(resJsonCty.payload).toEqual(plaintextObj);
      expect(typeof resJsonCty.payload).toBe("object");

      // 3. No typ/cty, should be string
      const jweBytesPlain = await encrypt(textEncoder.encode(plaintextString), key, { alg, enc });
      const resString = await decrypt<string>(jweBytesPlain, key);
      expect(resString.payload).toBeTypeOf("string");
      expect(resString.payload).toEqual(plaintextString);

      // 4. typ: "JWT" but plaintext is not valid JSON
      const jweMalformedJwt = await encrypt("not a json object", key, {
        alg,
        enc,
        protectedHeader: { typ: "JWT" },
      });
      const resMalformedJwt = await decrypt<string>(jweMalformedJwt, key);
      expect(resMalformedJwt.payload).toBe("not a json object"); // Falls back to string
      expect(typeof resMalformedJwt.payload).toBe("string");
    });

    describe("claims and header defaults", () => {
      const alg: KeyManagementAlgorithm = "A128KW";
      const enc: ContentEncryptionAlgorithm = "A128GCM";

      it("computes iat/exp during encrypt when expiresIn provided and no exp present", async () => {
        const key = keys[alg]!.key as CryptoKey;
        const baseClaims: JWTClaims = { sub: "abc" };

        const jwe = await encrypt(baseClaims, key, {
          alg,
          enc,
          expiresIn: "1m", // 1 minute
          currentDate: new Date(0), // epoch
        });

        const { payload, protectedHeader } = await decrypt<JWTClaims>(jwe, key, {
          currentDate: new Date(30_000), // 30 seconds in
        });
        expect(protectedHeader.typ).toBe("JWT");
        expect(protectedHeader.cty).toBe("application/json");
        expect(payload.sub).toBe("abc");
        expect(payload.iat).toBe(0);
        expect(payload.exp).toBe(60);
      });

      it("does not override existing exp claim when provided", async () => {
        const key = keys[alg]!.key as CryptoKey;
        const claimsWithExp: JWTClaims = { sub: "abc", exp: 999 };

        const jwe = await encrypt(claimsWithExp, key, {
          alg,
          enc,
          expiresIn: 60, // should be ignored because exp already set
          currentDate: new Date(0), // epoch
        });

        const { payload } = await decrypt<JWTClaims>(jwe, key, {
          currentDate: new Date(30_000),
        });
        expect(payload.exp).toBe(999);
      });

      it("defaults typ/cty when encrypting object and leaves typ undefined for string", async () => {
        const key = keys[alg]!.key as CryptoKey;
        const obj = { hello: "world" };

        const jweObj = await encrypt(obj, key, { alg, enc });
        const resObj = await decrypt<JWTClaims>(jweObj, key);
        expect(resObj.protectedHeader.typ).toBe("JWT");
        expect(resObj.protectedHeader.cty).toBe("application/json");
        expect(resObj.payload).toEqual(obj);

        const jweStr = await encrypt("hello", key, { alg, enc });
        const resStr = await decrypt<string>(jweStr, key);
        expect(resStr.protectedHeader.typ).toBeUndefined();
        expect(resStr.payload).toBe("hello");
      });

      it("accepts critical headers via requiredHeaders option", async () => {
        const key = keys[alg]!.key as CryptoKey;
        const jweCrit = await encrypt(plaintextString, key, {
          alg,
          enc,
          protectedHeader: { crit: ["exp"], exp: 1_234_567_890 },
        });

        await expect(decrypt(jweCrit, key, { recognizedHeaders: ["exp"] })).resolves.toBeDefined();
      });

      it("it does have an expired claim but validation is skipped", async () => {
        const key = keys[alg]!.key as CryptoKey;
        const claimsWithExp: JWTClaims = { sub: "abc" };

        const jwe = await encrypt(claimsWithExp, key, {
          alg,
          enc,
          expiresIn: 60,
          currentDate: new Date(0), // epoch
        });

        const { payload } = await decrypt<JWTClaims>(jwe, key, {
          currentDate: new Date(61_000), // 61 seconds after epoch
          validateClaims: false,
        });
        expect(payload.exp).toBe(60);
      });

      it("rejects expired token even when typ header is absent", async () => {
        // Encrypting a plain JSON string as Uint8Array bypasses `applyTypCtyDefaults`
        // so the protected header has no `typ`. Prior to v0.7.0 this silently skipped
        // claim validation because the condition was typ-gated.
        const key = keys[alg]!.key as CryptoKey;
        const expiredPayload = {
          sub: "abc",
          exp: Math.floor(Date.now() / 1000) - 60,
        };
        const jwe = await encrypt(textEncoder.encode(JSON.stringify(expiredPayload)), key, {
          alg,
          enc,
          protectedHeader: { cty: "application/json" },
        });

        await expect(decrypt<JWTClaims>(jwe, key)).rejects.toThrow("Token has expired");
      });

      it("rejects non-numeric exp as ERR_JWT_CLAIM_INVALID", async () => {
        const key = keys[alg]!.key as CryptoKey;
        const jwe = await encrypt({ sub: "abc", exp: "never" }, key, { alg, enc });

        try {
          await decrypt(jwe, key);
          expect.fail("decrypt should have thrown");
        } catch (err) {
          expect(isJWTError(err)).toBe(true);
          if (isJWTError(err)) expect(err.code).toBe("ERR_JWT_CLAIM_INVALID");
          expect((err as Error).message).toContain(
            '"exp" (Expiration Time) Claim must be a number',
          );
        }
      });

      it("should throw if JWT has expired", async () => {
        const key = keys[alg]!.key as CryptoKey;
        const claimsWithExp: JWTClaims = { sub: "abc" };

        const jwe = await encrypt(claimsWithExp, key, {
          alg,
          enc,
          expiresIn: 60,
          currentDate: new Date(0), // epoch
        });

        await expect(
          decrypt<JWTClaims>(jwe, key, {
            currentDate: new Date(61_000),
          }),
        ).rejects.toThrow(
          `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: 1970-01-01T00:01:00.000Z)`,
        );
      });

      it("should throw JWTError with ERR_JWT_EXPIRED code and cause for expired `exp`", async () => {
        const key = keys[alg]!.key as CryptoKey;
        const jwe = await encrypt({ sub: "test-subject", jti: "test-jti-exp" }, key, {
          alg,
          enc,
          expiresIn: 60,
          currentDate: new Date(0),
        });

        const error = await decrypt<JWTClaims>(jwe, key, {
          currentDate: new Date(61_000),
        }).catch((e) => e);

        expect(error).toBeInstanceOf(JWTError);
        expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
        if (isJWTError(error, "ERR_JWT_EXPIRED")) {
          expect(error.cause).toMatchObject({ jti: "test-jti-exp", exp: 60 });
        }
      });
    });
  });

  describe("ECDH-ES specific parameters", () => {
    const ecdhAlg: KeyManagementAlgorithm = "ECDH-ES+A128KW";
    const enc: ContentEncryptionAlgorithm = "A128GCM";
    let recipientKeyPair: CryptoKeyPair;
    let recipientPublicKeyJwk: JWK_EC_Public;

    beforeAll(async () => {
      recipientKeyPair = keys[ecdhAlg]!.key as CryptoKeyPair;
      recipientPublicKeyJwk = (await exportKey(recipientKeyPair.publicKey)) as JWK_EC_Public;
    });

    it("should encrypt and decrypt with ECDH-ES and include epk", async () => {
      const apu = randomBytes(16);
      const apv = randomBytes(16);

      const jwe = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
        alg: ecdhAlg,
        enc,
        ecdh: {
          partyUInfo: apu,
          partyVInfo: apv,
        },
      });

      const parts = jwe.split(".");
      const protectedHeaderEncoded = parts[0];
      const encryptedKeyEncoded = parts[1];
      const protectedHeader = JSON.parse(
        base64UrlDecode(protectedHeaderEncoded),
      ) as JWEHeaderParameters;

      expect(protectedHeader.alg).toBe(ecdhAlg);
      expect(protectedHeader.enc).toBe(enc);
      expect(protectedHeader.epk).toBeDefined();
      expect(protectedHeader.epk?.kty).toBe("EC");
      expect(protectedHeader.epk?.crv).toBe(recipientPublicKeyJwk.crv);
      expect(protectedHeader.apu).toBe(base64UrlEncode(apu));
      expect(protectedHeader.apv).toBe(base64UrlEncode(apv));

      const encryptedKeyBytes = base64UrlDecode(encryptedKeyEncoded, false);
      expect(encryptedKeyBytes).toBeInstanceOf(Uint8Array);
      expect(encryptedKeyBytes.length).toBeGreaterThan(0);

      const expectedCek = await unwrapKey(ecdhAlg, encryptedKeyBytes, recipientKeyPair.privateKey, {
        epk: protectedHeader.epk!,
        apu: protectedHeader.apu,
        apv: protectedHeader.apv,
        enc,
        format: "raw",
      });
      expect(expectedCek).toBeInstanceOf(Uint8Array);

      const {
        payload: decryptedPayload,
        cek,
        aad,
      } = await decrypt(jwe, recipientKeyPair.privateKey, {
        returnCek: true,
      });

      expect(base64UrlDecode(protectedHeader.apu!, false)).toEqual(apu);
      expect(base64UrlDecode(protectedHeader.apv!, false)).toEqual(apv);
      expect(cek).toEqual(expectedCek);
      expect(aad).toEqual(textEncoder.encode(protectedHeaderEncoded));
      expect(decryptedPayload).toEqual(plaintextObj);
    });

    it("should honor provided ECDH ephemeral public key", async () => {
      const providedEphemeral = (await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
        keyUsage: ["deriveBits"],
      })) as CryptoKeyPair;
      const providedEphemeralJwk = (await exportKey(providedEphemeral.publicKey)) as JWK_EC_Public;
      const apu = randomBytes(16);
      const apv = randomBytes(16);

      expect(providedEphemeral.privateKey.usages).toContain("deriveBits");

      const jwe = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
        alg: ecdhAlg,
        enc,
        ecdh: {
          ephemeralKey: providedEphemeral,
          partyUInfo: apu,
          partyVInfo: apv,
        },
      });

      const [protectedHeaderEncoded, encryptedKeyEncoded] = jwe.split(".");
      const protectedHeader = JSON.parse(
        base64UrlDecode(protectedHeaderEncoded),
      ) as JWEHeaderParameters;

      expect(protectedHeader.epk).toBeDefined();
      expect(protectedHeader.epk?.kty).toBe("EC");
      expect(protectedHeader.epk?.x).toBe(providedEphemeralJwk.x);
      expect(protectedHeader.epk?.y).toBe(providedEphemeralJwk.y);
      expect(protectedHeader.epk?.crv).toBe(providedEphemeralJwk.crv);
      expect(protectedHeader.apu).toBe(base64UrlEncode(apu));
      expect(protectedHeader.apv).toBe(base64UrlEncode(apv));

      const decryptResult = await decrypt(jwe, recipientKeyPair.privateKey, {
        returnCek: true,
      });
      expect(decryptResult.payload).toEqual(plaintextObj);

      const derivedCek = await unwrapKey(
        ecdhAlg,
        base64UrlDecode(encryptedKeyEncoded, false),
        recipientKeyPair.privateKey,
        {
          epk: protectedHeader.epk!,
          apu: protectedHeader.apu,
          apv: protectedHeader.apv,
          enc,
          format: "raw",
        },
      );

      expect(decryptResult.cek).toEqual(derivedCek);
    });

    it("should reject ECDH ephemeral material missing private key", async () => {
      const providedEphemeral = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      });

      await expect(
        encrypt(plaintextObj, recipientKeyPair.publicKey, {
          alg: ecdhAlg,
          enc,
          ecdh: {
            // deliberately only provide the public component
            ephemeralKey: providedEphemeral.publicKey,
          },
        }),
      ).rejects.toThrow(/private key material/i);
    });

    it("should accept a JWK (with d) as ephemeral key", async () => {
      const ephemeralJwk = (await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
        toJWK: true,
      })) as { privateKey: Record<string, any>; publicKey: Record<string, any> };

      // A JWK_EC_Private has "d" - should be accepted as the ephemeral key.
      // Encrypt covers the JWK branch in parseEphemeralKey; decrypt is not tested
      // here because the epk embedded in the header retains "d" in this code path.
      const jwe = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
        alg: ecdhAlg,
        enc,
        ecdh: { ephemeralKey: ephemeralJwk.privateKey as any },
      });

      expect(typeof jwe).toBe("string");
      expect(jwe.split(".")).toHaveLength(5);
    });

    it("should accept a plain object {publicKey, privateKey} of JWKs as ephemeral key", async () => {
      const ephemeralJwk = (await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
        toJWK: true,
      })) as { privateKey: Record<string, any>; publicKey: Record<string, any> };

      const jwe = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
        alg: ecdhAlg,
        enc,
        ecdh: {
          ephemeralKey: {
            publicKey: ephemeralJwk.publicKey as any,
            privateKey: ephemeralJwk.privateKey as any,
          },
        },
      });

      const { payload } = await decrypt(jwe, recipientKeyPair.privateKey);
      expect(payload).toEqual(plaintextObj);
    });

    it("should throw when plain object ephemeral key is missing privateKey", async () => {
      await expect(
        encrypt(plaintextObj, recipientKeyPair.publicKey, {
          alg: ecdhAlg,
          enc,
          ecdh: {
            ephemeralKey: { publicKey: recipientKeyPair.publicKey, privateKey: null } as any,
          },
        }),
      ).rejects.toThrow(/publicKey and privateKey/i);
    });

    it("should accept a private CryptoKey directly as ephemeral key", async () => {
      const ephemeralPair = (await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      })) as CryptoKeyPair;

      // Passing just the private CryptoKey (not a pair) covers the CryptoKey branch
      const jwe = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
        alg: ecdhAlg,
        enc,
        ecdh: { ephemeralKey: ephemeralPair.privateKey as any },
      });

      expect(typeof jwe).toBe("string");
      expect(jwe.split(".")).toHaveLength(5);
    });

    it("should throw when JWK ephemeral key has no private parameter d", async () => {
      const ephemeralPair = (await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
        toJWK: true,
      })) as { privateKey: Record<string, any>; publicKey: Record<string, any> };

      await expect(
        encrypt(plaintextObj, recipientKeyPair.publicKey, {
          alg: ecdhAlg,
          enc,
          ecdh: { ephemeralKey: ephemeralPair.publicKey as any }, // public JWK — no "d"
        }),
      ).rejects.toThrow(/private parameter "d"/i);
    });

    it("should throw for unsupported ephemeral key type", async () => {
      await expect(
        encrypt(plaintextObj, recipientKeyPair.publicKey, {
          alg: ecdhAlg,
          enc,
          // @ts-expect-error intentionally invalid type
          ecdh: { ephemeralKey: 42 },
        }),
      ).rejects.toThrow(/Unsupported ECDH-ES ephemeral key material/i);
    });
  });

  describe("JWTError error codes", () => {
    let aesKey: CryptoKey;
    beforeAll(async () => {
      aesKey = await generateKey("A256KW");
    });

    it("ERR_JWE_INVALID — malformed compact serialization", async () => {
      const error = await decrypt("only.two.parts", aesKey).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
    });

    it("ERR_JWE_ALG_NOT_ALLOWED — key management algorithm rejected by policy", async () => {
      const jwe = await encrypt(plaintextObj, aesKey, { alg: "A256KW", enc: "A256GCM" });
      const error = await decrypt(jwe, aesKey, { algorithms: ["A128KW"] }).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
    });

    it("ERR_JWE_DECRYPTION_FAILED — wrong decryption key", async () => {
      const jwe = await encrypt(plaintextObj, aesKey, { alg: "A256KW", enc: "A256GCM" });
      const otherKey = await generateKey("A256KW");
      const error = await decrypt(jwe, otherKey).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
    });

    it("ERR_JWE_ALG_MISSING — encrypt without inferable alg", async () => {
      // CryptoKey is neither Uint8Array (→ PBES2 default) nor a JWK (→ alg field);
      // TS types enforce `alg` on the CryptoKey overload, so cast to exercise the runtime guard.
      const key = await generateKey("A256KW");
      const error = await (encrypt as (p: unknown, k: unknown) => Promise<string>)(
        "payload",
        key,
      ).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWE_ALG_MISSING")).toBe(true);
    });

    it("ERR_JWE_ENC_MISSING — encrypt with alg:'dir' and no enc", async () => {
      const key = await generateKey("A256GCM");
      // @ts-expect-error intentionally omitting enc
      const error = await encrypt("payload", key, { alg: "dir" }).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWE_ENC_MISSING")).toBe(true);
    });
  });
});
