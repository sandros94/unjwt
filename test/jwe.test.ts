import * as jose from "jose";
import { describe, it, expect, expectTypeOf, beforeAll } from "vitest";
import { encrypt, decrypt, JWTError, isJWTError, isUnsecureError } from "../src/core/jwe/index.ts";
import type {
  JOSEPayloadTypeMap,
  JWEDecryptOptions,
  JWEDecryptResult,
  PayloadOf,
} from "../src/core/jwe/index.ts";
import { generateKey, generateJWK, exportJWK, unwrapKey, wrapKey } from "../src/core/jwk/index.ts";
import { secureRandomBytes, textEncoder, textDecoder } from "unsecure";
import { base64UrlStringify, base64UrlParse } from "../src/utils/base64.ts";
import { DEFAULT_PBES2_ITERATIONS } from "../src/core/_internal/limits.ts";
import type {
  JWK,
  JWK_oct,
  JWK_Pair,
  JWK_EC_Public,
  JWK_EC_Private,
  JWEEncryptJWK,
  JWEDecryptJWK,
  JWTClaims,
  JOSEPayloadMode,
  JWKLookupFunction,
  JWEHeaderParameters,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
} from "../src/core/types/index.ts";

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
    publicKey?: CryptoKey | JWEEncryptJWK;
    privateKey?: CryptoKey | JWEDecryptJWK;
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
    // eslint-disable-next-line vitest/valid-title -- data-driven suite: title comes from the scenario table
    describe(desc, () => {
      it(`should encrypt and decrypt successfully`, async () => {
        let encryptionKey: CryptoKey | JWEEncryptJWK | string | Uint8Array<ArrayBuffer>;
        let decryptionKey:
          | CryptoKey
          | JWEDecryptJWK
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

        let payloadMode: JOSEPayloadMode;
        if (typeof plaintext === "string") {
          plaintextBuffer = textEncoder.encode(plaintext);
          payloadMode = "string";
        } else if (plaintext instanceof Uint8Array) {
          plaintextBuffer = plaintext;
          payloadMode = "bytes";
        } else {
          plaintextBuffer = textEncoder.encode(JSON.stringify(plaintext));
          payloadMode = "json";
        }

        const jwe = await encrypt(plaintext, encryptionKey, {
          alg,
          enc,
          ...(alg.startsWith("PBES2") ? { p2c: 1000 } : {}),
        });

        // jose doesn't support PBES2-HS256+A128KW alg header
        if (alg !== "PBES2-HS256+A128KW") {
          const { plaintext: decryptedByJose } = await jose.compactDecrypt(jwe, decryptionKey);
          // eslint-disable-next-line vitest/no-conditional-expect -- data-driven: jose can't decrypt PBES2, so this cross-check is intentionally skipped for that alg
          expect(decryptedByJose).toEqual(plaintextBuffer);
        }

        const jweFromJose = await new jose.CompactEncrypt(plaintextBuffer)
          .setProtectedHeader({ alg, enc, cty: "application/json" })
          .encrypt(encryptionKey);

        const { payload: decrypted } = await decrypt(jweFromJose, decryptionKey, {
          payload: payloadMode,
          // A password passed as raw bytes names no algorithm of its own.
          algorithms: [alg],
        });

        expect(decrypted).toEqual(plaintext);
      });
    });
  }

  describe("encrypt specific options", () => {
    it("should encrypt and decrypt while only providing a password", async () => {
      const t = "Hello, World!";
      const p = "password";

      const jwe = await encrypt(t, p);
      const { payload } = await decrypt(jwe, p, { payload: "string" });

      expect(payload).toBe(t);

      // jose doesn't support PBES2-HS256+A128KW alg header
    });

    it("should encrypt and decrypt while only providing a JWK", async () => {
      const t = "Hello, World!";
      const jwk = {
        key_ops: ["wrapKey", "unwrapKey", "encrypt", "decrypt"],
        ext: true,
        kty: "oct",
        k: "mzR5rkgr41d-4e_fVMYQ1g",
        alg: "A128KW",
      } as const satisfies JWK;

      const jwe = await encrypt(t, jwk);
      const { payload } = await decrypt(jwe, jwk, { payload: "string" });

      expect(payload).toBe(t);

      const joseKey = await jose.importJWK(jwk);
      const { plaintext: josePlaintext } = await jose.compactDecrypt(jwe, joseKey);
      expect(textDecoder.decode(josePlaintext)).toBe(t);
    });

    // `alg` is inferred from the JWK verbatim — no silent `A*GCM → A*GCMKW` coercion.
    it("encrypts a GCMKW oct JWK via its declared alg without coercion", async () => {
      const jwk = await generateJWK("A256GCMKW");
      expect(jwk.alg).toBe("A256GCMKW");
      const jwe = await encrypt("payload", jwk, { enc: "A256GCM" });
      const header = JSON.parse(base64UrlParse(jwe.split(".")[0]));
      expect(header.alg).toBe("A256GCMKW");
      const { payload } = await decrypt(jwe, jwk, { payload: "string" });
      expect(payload).toBe("payload");
    });

    // An oct JWK with `alg: "A256GCM"` is a CEK; the library never rewrites
    // `A256GCM` into `A256GCMKW`, with or without an explicit `alg`.
    it("reads an oct JWK with alg=A256GCM as a dir CEK, never as a wrapping key", async () => {
      const jwk = await generateJWK("A256GCM");
      expect(jwk.alg).toBe("A256GCM");

      const jwe = await encrypt("payload", jwk);
      const header = JSON.parse(base64UrlParse(jwe.split(".")[0]));
      expect(header).toMatchObject({ alg: "dir", enc: "A256GCM" });

      await expect(encrypt("payload", jwk, { alg: "A256GCMKW", enc: "A256GCM" })).rejects.toThrow(
        'JWK "alg" is "A256GCM" but the operation requires "A256GCMKW".',
      );
    });

    it("should use provided CEK and contentEncryptionIV", async () => {
      const alg: KeyManagementAlgorithm = "A128KW";
      const enc: ContentEncryptionAlgorithm = "A128GCM";
      const key = keys[alg].key as CryptoKey;

      const customCek = secureRandomBytes(128 / 8);
      const customIv = secureRandomBytes(96 / 8);

      const jwe = await encrypt(plaintextString, key, {
        alg,
        enc,
        cek: customCek,
        contentEncryptionIV: customIv,
      });

      const { payload: decryptedPayload } = await decrypt(jwe, key, { payload: "string" });
      expect(decryptedPayload).toBe(plaintextString);
      // Only the IV is verifiable here; the CEK is wrapped so its bytes aren't visible
      // without a manual unwrap.
      const jweParts = jwe.split(".");
      const decodedIv = base64UrlParse(jweParts[2], { returnAs: "uint8array" });
      expect(decodedIv).toEqual(customIv);
    });

    it("should decrypt with explicit unwrappedKeyAlgorithm option", async () => {
      const alg: KeyManagementAlgorithm = "A128KW";
      const enc: ContentEncryptionAlgorithm = "A128GCM";
      const key = keys[alg].key as CryptoKey;

      const jwe = await encrypt(plaintextObj, key, { alg, enc });
      const { payload } = await decrypt(jwe, key, {
        unwrappedKeyAlgorithm: { name: "AES-GCM" },
      });
      expect(payload).toEqual(plaintextObj);
    });

    it("should throw if alg is missing", async () => {
      const key = keys["A128KW"].key as CryptoKey;
      await expect(encrypt(plaintextString, key, { enc: "A128GCM" } as never)).rejects.toThrow(
        'JWE "alg" must be provided in options',
      );
    });

    it("should throw for invalid payload type (null)", async () => {
      const key = keys["A128KW"].key as CryptoKey;
      await expect(
        // @ts-expect-error intentionally invalid payload
        encrypt(null, key, { alg: "A128KW", enc: "A128GCM" }),
      ).rejects.toThrow(/Plaintext must be/i);
    });

    // `encrypt` / `decrypt` pin `expect: "public" | "private"` on import, so a
    // wrong-direction asymmetric JWK fails fast instead of being silently accepted.
    it("rejects a private recipient JWK passed to encrypt()", async () => {
      const { privateKey, publicKey } = await generateJWK("RSA-OAEP-256", {
        modulusLength: 2048,
      });
      await expect(
        encrypt(plaintextObj, publicKey, { alg: "RSA-OAEP-256", enc: "A256GCM" }),
      ).resolves.toBeTypeOf("string");
      await expect(
        encrypt(plaintextObj, privateKey, { alg: "RSA-OAEP-256", enc: "A256GCM" }),
      ).rejects.toThrow(expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }));
    });

    it("rejects a public recipient JWK passed to decrypt()", async () => {
      const { privateKey, publicKey } = await generateJWK("RSA-OAEP-256", {
        modulusLength: 2048,
      });
      const jwe = await encrypt(plaintextObj, publicKey, {
        alg: "RSA-OAEP-256",
        enc: "A256GCM",
      });
      await expect(decrypt(jwe, privateKey)).resolves.toBeDefined();
      // `decrypt`'s TS union already rejects `JWK_Public`; the cast exercises the
      // runtime guard for callers that use `as any`.
      await expect(decrypt(jwe, publicKey as never)).rejects.toThrow(
        expect.objectContaining({ name: "JWTError", code: "ERR_JWK_INVALID" }),
      );
    });
  });

  describe("PBES2 p2c bounds", () => {
    const password = textEncoder.encode("securepassword123");
    const alg = "PBES2-HS256+A128KW" as const;

    /**
     * A wrapped key at an iteration count the library itself refuses to mint:
     * the PBES2 key is derived with WebCrypto (RFC 7518 §4.8.1.1 salt) and the
     * CEK AES-KW wrapped with it, which is exactly what the PBES2 branch does
     * once it has its parameters.
     */
    async function wrapBelowFloor(cek: Uint8Array<ArrayBuffer>, p2s: Uint8Array<ArrayBuffer>) {
      const salt = new Uint8Array([...textEncoder.encode(alg), 0, ...p2s]);
      const base = await crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt, iterations: 500 },
        base,
        128,
      );
      const derived = await crypto.subtle.importKey("raw", bits, "AES-KW", false, ["wrapKey"]);
      return wrapKey(cek, derived, { alg: "A128KW" });
    }

    it("rejects p2c below the default minimum of 1000 iterations", async () => {
      const cek = secureRandomBytes(32);
      const p2s = secureRandomBytes(16);
      const { encryptedKey } = await wrapBelowFloor(cek, p2s);
      await expect(
        unwrapKey(encryptedKey, password, { alg, p2c: 500, p2s, format: "raw" }),
      ).rejects.toThrow(/"p2c" below the minimum of 1000/);
    });

    it("refuses to mint a p2c outside the bounds it enforces on unwrap", async () => {
      const cek = secureRandomBytes(32);
      const p2s = secureRandomBytes(16);
      const optionError = expect.objectContaining({
        name: "JWTError",
        code: "ERR_INVALID_OPTION",
      });
      await expect(wrapKey(cek, password, { alg, p2c: 500, p2s })).rejects.toThrow(optionError);
      await expect(wrapKey(cek, password, { alg, p2c: 0, p2s })).rejects.toThrow(optionError);
      await expect(
        wrapKey(cek, password, { alg, p2c: 1000, p2s: secureRandomBytes(4) }),
      ).rejects.toThrow(optionError);
    });

    it("rejects p2c above the default maximum, the iteration count encrypt mints by default", async () => {
      // The bounds check fires before PBKDF2, so no need to actually wrap at that iteration count.
      const p2s = secureRandomBytes(16);
      await expect(
        unwrapKey(secureRandomBytes(40), password, {
          alg,
          p2c: DEFAULT_PBES2_ITERATIONS + 1,
          p2s,
          format: "raw",
        }),
      ).rejects.toThrow(`"p2c" above the maximum of ${DEFAULT_PBES2_ITERATIONS}`);
    });

    it("refuses to mint a p2c above the default maximum", async () => {
      const error = await encrypt(plaintextObj, "a password", {
        alg,
        enc: "A128GCM",
        p2c: DEFAULT_PBES2_ITERATIONS + 1,
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    });

    it("opens a token minted at the default p2c under the default maximum", async () => {
      const jwe = await encrypt(plaintextObj, "a password", { alg, enc: "A128GCM" });
      const header = JSON.parse(base64UrlParse(jwe.split(".")[0]));
      expect(header.p2c).toBe(DEFAULT_PBES2_ITERATIONS);
      await expect(decrypt(jwe, "a password")).resolves.toBeDefined();
    });

    it("opens a token one iteration above the default maximum only when maxIterations is raised", async () => {
      const p2c = DEFAULT_PBES2_ITERATIONS + 1;
      const jwe = await new jose.CompactEncrypt(textEncoder.encode(JSON.stringify(plaintextObj)))
        .setProtectedHeader({ alg, enc: "A128GCM" })
        .setKeyManagementParameters({ p2c })
        .encrypt(textEncoder.encode("a password"));

      const error = await decrypt(jwe, "a password").catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toContain(`above the maximum of ${DEFAULT_PBES2_ITERATIONS}`);

      await expect(decrypt(jwe, "a password", { maxIterations: p2c })).resolves.toBeDefined();
    });

    it("accepts p2c at the default floor of 1000 iterations", async () => {
      const cek = secureRandomBytes(32);
      const p2s = secureRandomBytes(16);
      const { encryptedKey } = await wrapKey(cek, password, { alg, p2c: 1000, p2s });
      const unwrapped = await unwrapKey(encryptedKey, password, {
        alg,
        p2c: 1000,
        p2s,
        format: "raw",
      });
      expect(unwrapped).toEqual(cek);
    });

    it("honours caller-supplied minIterations override", async () => {
      const cek = secureRandomBytes(32);
      const p2s = secureRandomBytes(16);
      const { encryptedKey } = await wrapBelowFloor(cek, p2s);
      // Below default floor (1000), but a caller-supplied floor of 100 accepts it.
      const unwrapped = await unwrapKey(encryptedKey, password, {
        alg,
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

      const { payload } = await decrypt(jwe, key, { payload: "string" });
      expect(payload).toBe(plaintext);
    });

    it("encrypt/decrypt roundtrip with AES-CBC content encryption", async () => {
      const cek = secureRandomBytes(32); // A128CBC-HS256 needs 256-bit key
      const plaintext = "direct CBC test";

      // Raw bytes declare no role of their own, so the reading side names the alg.
      const jwe = await encrypt(plaintext, cek, { alg: "dir", enc: "A128CBC-HS256" });
      const { payload } = await decrypt(jwe, cek, { payload: "string", algorithms: ["dir"] });
      expect(payload).toBe(plaintext);
    });

    it("raw key bytes must be paired with an explicit algorithms option on decrypt", async () => {
      const cek = secureRandomBytes(32);
      const jwe = await encrypt("roles come from the caller", cek, {
        alg: "A256KW",
        enc: "A256GCM",
      });

      const error = await decrypt(jwe, cek).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
      expect(error.message).toContain("Cannot infer");

      const { payload } = await decrypt(jwe, cek, {
        payload: "string",
        algorithms: ["A256KW"],
      });
      expect(payload).toBe("roles come from the caller");
    });

    it("encrypt/decrypt roundtrip with a JWK_oct key", async () => {
      const jwk = await generateJWK("A256GCM");
      const plaintext = "JWK dir test";

      const jwe = await encrypt(plaintext, jwk, { alg: "dir", enc: "A256GCM" });
      const { payload } = await decrypt(jwe, jwk, { payload: "string" });
      expect(payload).toBe(plaintext);
    });

    it("enc is inferred from the JWK_oct enc field when not provided in options", async () => {
      const jwk = { ...(await generateJWK("A256GCM")), enc: "A256GCM" as const };
      const plaintext = "JWK dir enc inference";

      // enc not specified in options — should be read from jwk.enc
      const jwe = await encrypt(plaintext, jwk, { alg: "dir" });
      const { payload } = await decrypt(jwe, jwk, { payload: "string" });
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

  describe("symmetric JWK roles", () => {
    it("a content-encryption oct JWK is a CEK for its own enc", async () => {
      const jwk = await generateJWK("A256GCM");
      const jwe = await encrypt("cek role", jwk, { alg: "dir", enc: "A256GCM" });
      const { payload } = await decrypt(jwe, jwk, { payload: "string" });
      expect(payload).toBe("cek role");
    });

    it("a content-encryption oct JWK is refused when the token's enc differs", async () => {
      const jwk = await generateJWK("A256GCM");
      const jwe = await encrypt("other enc", secureRandomBytes(32), {
        alg: "dir",
        enc: "A128CBC-HS256",
      });

      const error = await decrypt(jwe, jwk).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toBe(
        'JWK "alg" is "A256GCM" but "dir" requires "dir" or the token\'s "enc".',
      );
    });

    it('an oct JWK declared "dir" serves any enc whose CEK length matches', async () => {
      const jwk = { ...(await generateJWK("A256GCM")), alg: "dir" as const };
      const jwe = await encrypt("dir role", jwk, { alg: "dir", enc: "A256GCM" });
      const { payload } = await decrypt(jwe, jwk, { payload: "string" });
      expect(payload).toBe("dir role");

      const shortJwk = { ...(await generateJWK("A128GCM")), alg: "dir" as const };
      const error = await decrypt(jwe, shortJwk).catch((e) => e);
      expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      expect(error.message).toContain("A256GCM requires a key of exactly 32 bytes");
    });

    it("a key wrapping oct JWK is never accepted as a CEK", async () => {
      const kw = await generateJWK("A256KW");
      const jwe = await encrypt("not a cek", secureRandomBytes(32), {
        alg: "dir",
        enc: "A256GCM",
      });

      const error = await decrypt(jwe, kw).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
      expect(error.message).toBe("Key management algorithm not allowed: dir");

      const encryptError = await encrypt("not a cek", kw, {
        alg: "dir",
        enc: "A256GCM",
      }).catch((e) => e);
      expect(isJWTError(encryptError, "ERR_JWK_INVALID")).toBe(true);
      expect(encryptError.message).toBe('JWK "alg" is "A256KW" but the operation requires "dir".');
    });

    it("a content-encryption oct JWK is never accepted as a GCMKW wrapping key", async () => {
      const jwk = await generateJWK("A256GCM");

      const encryptError = await encrypt("not a kek", jwk, {
        alg: "A256GCMKW",
        enc: "A256GCM",
      }).catch((e) => e);
      expect(isJWTError(encryptError, "ERR_JWK_INVALID")).toBe(true);
      expect(encryptError.message).toBe(
        'JWK "alg" is "A256GCM" but the operation requires "A256GCMKW".',
      );

      const kw = await generateJWK("A256GCMKW");
      const jwe = await encrypt("not a kek", kw, { alg: "A256GCMKW", enc: "A256GCM" });
      const error = await decrypt(jwe, jwk).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
      expect(error.message).toBe("Key management algorithm not allowed: A256GCMKW");
    });
  });

  describe("JWK Set candidate policy", () => {
    it("skips a key the header cannot use and reports every candidate on failure", async () => {
      const [a, b] = await Promise.all([
        generateJWK("RSA-OAEP-256", { modulusLength: 2048 }),
        generateJWK("RSA-OAEP-256", { modulusLength: 2048 }),
      ]);
      const jwe = await encrypt(
        plaintextObj,
        { ...a.publicKey, kid: undefined },
        {
          alg: "RSA-OAEP-256",
          enc: "A256GCM",
        },
      );

      const set = {
        keys: [
          { ...a.privateKey, kid: undefined, use: "sig" },
          { ...a.privateKey, kid: undefined },
        ],
      } as unknown as { keys: JWK[] };
      await expect(decrypt(jwe, set)).resolves.toBeDefined();

      const failing = {
        keys: [
          { kty: "RSA", alg: "RSA-OAEP-256", n: "!!", e: "AQAB", d: "!!" },
          { ...b.privateKey, kid: undefined },
        ],
      } as unknown as { keys: JWK[] };
      const error = await decrypt(jwe, failing).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
      expect(error.message).toBe("JWE decryption failed.");
      const causes = error.cause as JWTError[];
      expect(Array.isArray(causes)).toBe(true);
      expect(causes).toHaveLength(2);
      expect(causes.every((c) => c instanceof JWTError)).toBe(true);
      expect(causes.map((c) => c.code)).toEqual(["ERR_JWK_INVALID", "ERR_JWE_DECRYPTION_FAILED"]);
    });

    it("ignores oct entries unless the caller admits symmetric material", async () => {
      const kw = await generateJWK("A256KW");
      const jwe = await encrypt(plaintextObj, kw, { alg: "A256KW", enc: "A256GCM" });
      const set = { keys: [kw] } as unknown as { keys: JWK[] };

      const error = await decrypt(jwe, set).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);

      await expect(decrypt(jwe, set, { allowSymmetricJWKSet: true })).resolves.toBeDefined();
    });

    it('treats a non-oct entry carrying "k" as symmetric material', async () => {
      const kw = await generateJWK("A256KW");
      const jwe = await encrypt(plaintextObj, kw, { alg: "A256KW", enc: "A256GCM" });
      const disguised = { kty: "EC", alg: "A256KW", kid: kw.kid, k: kw.k } as unknown as JWK;
      const set = { keys: [disguised] };

      const error = await decrypt(jwe, set).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);

      const admitted = await decrypt(jwe, set, { allowSymmetricJWKSet: true }).catch((e) => e);
      expect(isJWTError(admitted, "ERR_JWE_DECRYPTION_FAILED")).toBe(true);
      expect(admitted.cause.map((c: JWTError) => c.code)).toEqual(["ERR_JWK_INVALID"]);
    });

    it('matches an "oct" content key tagged with its "enc" to a "dir" token', async () => {
      const previous = await generateJWK("A256GCM");
      const current = await generateJWK("A256GCM");
      const jwe = await encrypt(plaintextObj, current, { alg: "dir", enc: "A256GCM" });
      const set = { keys: [previous, current] };

      const { payload } = await decrypt(jwe, set, { allowSymmetricJWKSet: true });
      expect(payload).toEqual(plaintextObj);
      await expect(
        decrypt(jwe, { keys: [previous] }, { allowSymmetricJWKSet: true }),
      ).rejects.toHaveProperty("code", "ERR_JWK_KEY_NOT_FOUND");
    });
  });

  describe("decrypt specific options and errors", () => {
    let jwe: string;
    const alg: KeyManagementAlgorithm = "A128KW";
    const enc: ContentEncryptionAlgorithm = "A128GCM";
    let key: CryptoKey;
    let joseKey: jose.CryptoKey | Uint8Array;

    beforeAll(async () => {
      key = keys[alg].key as CryptoKey;
      joseKey = await jose.importJWK(await exportJWK(key));
      jwe = await encrypt(plaintextObj, key, { alg, enc });
    });

    it("should decrypt with JWKSet from lookup by trying multiple keys when no kid is present", async () => {
      // Two AES-KW keys without kid — encrypt with key2, set has key1 first so retry is exercised
      const [rawKey1, rawKey2] = await Promise.all([generateKey("A256KW"), generateKey("A256KW")]);
      const token = await encrypt(plaintextObj, rawKey2, { alg: "A256KW", enc: "A256GCM" });
      const [jwk1, jwk2] = await Promise.all([exportJWK(rawKey1), exportJWK(rawKey2)]);
      const set = { keys: [jwk1, jwk2] };
      const { payload } = await decrypt(token, set, { allowSymmetricJWKSet: true });
      expect(payload).toEqual(plaintextObj);
    });

    // A candidate that cannot open the token only means "try the next one".
    it("skips a malformed JWK and decrypts with a later candidate", async () => {
      const rawValid = await generateKey("A256KW");
      const validJwk = await exportJWK(rawValid);
      // `kty: "RSA"` with `alg: "A256KW"` is nonsensical — `subtleMapping` rejects
      // the combination. The fake `d` field satisfies the `expect: "private"` intent
      // check so the alg mismatch surfaces rather than the intent guard short-circuiting.
      const malformedJwk = { kty: "RSA", alg: "A256KW", d: "fake" } as unknown as JWK;
      const token = await encrypt(plaintextObj, rawValid, { alg: "A256KW", enc: "A256GCM" });

      const set = { keys: [malformedJwk, validJwk] };
      const { payload } = await decrypt(token, set, { allowSymmetricJWKSet: true });
      expect(payload).toEqual(plaintextObj);
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
        "Invalid JWE: Must contain five sections.",
      );
    });

    it("should throw if protected header is missing alg or enc", async () => {
      const invalidHeader = base64UrlStringify(JSON.stringify({ foo: "bar" }));
      const parts = jwe.split(".");
      parts[0] = invalidHeader;
      await expect(decrypt(parts.join("."), key)).rejects.toThrow(
        'Invalid JWE: Protected header must carry "alg" and "enc".',
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
      const kwJwk = await generateJWK("A128KW");
      const token = await encrypt(plaintextObj, kwJwk, { alg: "A128KW", enc: "A128GCM" });
      // JWK with alg: "A128KW" infers to ["A128KW", "dir"].
      await expect(decrypt(token, kwJwk)).resolves.toBeDefined();
      // A forged header claiming a different key management alg is rejected.
      const [, encKeyPart, ivPart, ctPart, tagPart] = token.split(".");
      const forgedHeader = base64UrlStringify(JSON.stringify({ alg: "A256KW", enc: "A128GCM" }));
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
      await expect(decrypt(jwe, wrongKey)).rejects.toThrow(JWTError);

      const wrongJoseKey = await jose.importJWK(await exportJWK(wrongKey));
      // eslint-disable-next-line vitest/require-to-throw-message -- cross-check that jose also rejects the wrong key; its error type/message is jose-internal
      await expect(jose.compactDecrypt(jwe, wrongJoseKey)).rejects.toThrow();
    });

    it("should handle critical headers correctly", async () => {
      const jweCrit = await encrypt(plaintextString, key, {
        alg,
        enc,
        protectedHeader: { crit: ["exp"], exp: 1_234_567_890 },
      });

      // Decrypts fine if "exp" is understood (e.g. by being in options.critical)
      await expect(
        decrypt(jweCrit, key, { payload: "string", recognizedHeaders: ["exp"] }),
      ).resolves.toBeDefined();
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
        'Unprocessed critical header parameters: "unknownParam"',
      );
      await expect(jose.compactDecrypt(jweUnknownCrit, joseKey)).rejects.toThrow(
        'Extension Header Parameter "unknownParam" is not recognized',
      );
    });

    // RFC 7516 §4.1.13 — `crit` lists extensions only; parameters registered by the JOSE
    // specs are rejected outright and `recognizedHeaders` cannot opt back into them.
    it.each(["jwk", "jku", "x5c", "x5t", "x5u"])(
      "rejects the registered parameter '%s' in crit",
      async (param) => {
        const jweCrit = withProtectedHeader(await encrypt(plaintextString, key, { alg, enc }), {
          crit: [param],
          [param]: "irrelevant",
        });
        const message = 'Invalid JWE: "crit" must not list registered header parameters.';
        await expect(decrypt(jweCrit, key)).rejects.toThrow(message);
        await expect(decrypt(jweCrit, key, { recognizedHeaders: [param] })).rejects.toThrow(
          message,
        );
      },
    );

    it("decodes the plaintext by the payload option, never by typ/cty", async () => {
      // 1. An object payload comes back as claims under the default mode.
      const jweJwt = await encrypt(plaintextObj, key, {
        alg,
        enc,
        protectedHeader: { typ: "JWT" },
      });
      const resJwt = await decrypt(jweJwt, key);
      expect(resJwt.payload).toEqual(plaintextObj);

      // 2. `cty: "application/json"` does not make a string payload a JSON object.
      const jweJsonCty = await encrypt(plaintextString, key, {
        alg,
        enc,
        protectedHeader: { cty: "application/json" },
      });
      const resJsonCty = await decrypt(jweJsonCty, key, { payload: "string" });
      expect(resJsonCty.payload).toBe(plaintextString);

      // 3. A JSON object stays claims even with no typ/cty on the header.
      const jweBare = await encrypt(JSON.stringify(plaintextObj), key, { alg, enc });
      const resBare = await decrypt(jweBare, key);
      expect(resBare.payload).toEqual(plaintextObj);

      // 4. `typ: "JWT"` over a non-JSON plaintext is rejected, not silently downgraded.
      const jweMalformedJwt = await encrypt("not a json object", key, {
        alg,
        enc,
        protectedHeader: { typ: "JWT" },
      });
      const error = await decrypt(jweMalformedJwt, key).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Payload is not a JSON object.");
    });

    describe("claims and header defaults", () => {
      it("computes iat/exp during encrypt when expiresIn provided and no exp present", async () => {
        const baseClaims: JWTClaims = { sub: "abc" };

        const token = await encrypt(baseClaims, key, {
          alg,
          enc,
          expiresIn: "1m", // 1 minute
          currentDate: new Date(0), // epoch
        });

        const { payload, protectedHeader } = await decrypt(token, key, {
          currentDate: new Date(30_000), // 30 seconds in
        });
        expect(protectedHeader.typ).toBe("JWT");
        expect(protectedHeader.cty).toBeUndefined();
        expect(payload.sub).toBe("abc");
        expect(payload.iat).toBe(0);
        expect(payload.exp).toBe(60);
      });

      it("does not override existing exp claim when provided", async () => {
        const claimsWithExp: JWTClaims = { sub: "abc", exp: 999 };

        const token = await encrypt(claimsWithExp, key, {
          alg,
          enc,
          expiresIn: 60, // should be ignored because exp already set
          currentDate: new Date(0), // epoch
        });

        const { payload } = await decrypt(token, key, {
          currentDate: new Date(30_000),
        });
        expect(payload.exp).toBe(999);
      });

      it("sets exp from expiresAt (absolute expiry)", async () => {
        const expiresAt = new Date("2030-01-01T00:00:00Z");
        const token = await encrypt({ sub: "abc" }, key, {
          alg,
          enc,
          expiresAt,
          currentDate: new Date(0),
        });

        const { payload } = await decrypt(token, key, {
          currentDate: new Date(0),
        });
        expect(payload.exp).toBe(Math.floor(expiresAt.getTime() / 1000));
        expect(payload.iat).toBe(0);
      });

      it("throws when both expiresIn and expiresAt are set", async () => {
        await expect(
          encrypt({ sub: "abc" }, key, {
            alg,
            enc,
            expiresIn: 60,
            expiresAt: new Date("2030-01-01T00:00:00Z"),
          }),
        ).rejects.toThrow(/mutually exclusive/i);
      });

      it("defaults typ, not cty, for an object and leaves typ undefined for a string", async () => {
        const obj = { hello: "world" };

        const jweObj = await encrypt(obj, key, { alg, enc });
        const resObj = await decrypt(jweObj, key);
        expect(resObj.protectedHeader.typ).toBe("JWT");
        expect(resObj.protectedHeader.cty).toBeUndefined();
        expect(resObj.payload).toEqual(obj);

        const jweStr = await encrypt("hello", key, { alg, enc });
        const resStr = await decrypt(jweStr, key, { payload: "string" });
        expect(resStr.protectedHeader.typ).toBeUndefined();
        expect(resStr.payload).toBe("hello");
      });

      it("accepts critical headers via requiredHeaders option", async () => {
        const jweCrit = await encrypt(plaintextString, key, {
          alg,
          enc,
          protectedHeader: { crit: ["exp"], exp: 1_234_567_890 },
        });

        await expect(
          decrypt(jweCrit, key, { payload: "string", recognizedHeaders: ["exp"] }),
        ).resolves.toBeDefined();
      });

      it("does have an expired claim but validation is skipped", async () => {
        const claimsWithExp: JWTClaims = { sub: "abc" };

        const token = await encrypt(claimsWithExp, key, {
          alg,
          enc,
          expiresIn: 60,
          currentDate: new Date(0), // epoch
        });

        const { payload } = await decrypt(token, key, {
          currentDate: new Date(61_000), // 61 seconds after epoch
          validateClaims: false,
        });
        expect(payload.exp).toBe(60);
      });

      it("rejects expired token even when typ header is absent", async () => {
        // Encrypting a plain JSON string as Uint8Array bypasses `applyTypDefault`
        // so the protected header has no `typ`. Prior to v0.7.0 this silently skipped
        // claim validation because the condition was typ-gated.
        const expiredPayload = {
          sub: "abc",
          exp: Math.floor(Date.now() / 1000) - 60,
        };
        const token = await encrypt(textEncoder.encode(JSON.stringify(expiredPayload)), key, {
          alg,
          enc,
          protectedHeader: { cty: "application/json" },
        });

        await expect(decrypt(token, key)).rejects.toThrow('JWT "exp" is in the past');
      });

      it("rejects non-numeric exp as ERR_JWT_CLAIM_INVALID", async () => {
        const token = await encrypt({ sub: "abc", exp: "never" }, key, { alg, enc });

        const err = await decrypt(token, key).catch((e) => e);
        expect(isJWTError(err)).toBe(true);
        expect((err as JWTError).code).toBe("ERR_JWT_CLAIM_INVALID");
        expect((err as Error).message).toContain('JWT "exp" must be a number');
      });

      it("should throw if JWT has expired", async () => {
        const claimsWithExp: JWTClaims = { sub: "abc" };

        const token = await encrypt(claimsWithExp, key, {
          alg,
          enc,
          expiresIn: 60,
          currentDate: new Date(0), // epoch
        });

        await expect(
          decrypt(token, key, {
            currentDate: new Date(61_000),
          }),
        ).rejects.toThrow(`JWT "exp" is in the past (1970-01-01T00:01:00.000Z)`);
      });

      it("should throw JWTError with ERR_JWT_EXPIRED code and cause for expired `exp`", async () => {
        const token = await encrypt({ sub: "test-subject", jti: "test-jti-exp" }, key, {
          alg,
          enc,
          expiresIn: 60,
          currentDate: new Date(0),
        });

        const error = await decrypt(token, key, {
          currentDate: new Date(61_000),
        }).catch((e) => e);

        expect(error).toBeInstanceOf(JWTError);
        expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
        expect((error as JWTError).cause).toMatchObject({ jti: "test-jti-exp", exp: 60 });
      });
    });
  });

  describe("ECDH-ES specific parameters", () => {
    const ecdhAlg: KeyManagementAlgorithm = "ECDH-ES+A128KW";
    const enc: ContentEncryptionAlgorithm = "A128GCM";
    let recipientKeyPair: CryptoKeyPair;
    let recipientPublicKeyJwk: JWK_EC_Public;

    beforeAll(async () => {
      recipientKeyPair = keys[ecdhAlg].key as CryptoKeyPair;
      recipientPublicKeyJwk = await exportJWK<JWK_EC_Public>(recipientKeyPair.publicKey);
    });

    it("should encrypt and decrypt with ECDH-ES and include epk", async () => {
      const apu = secureRandomBytes(16);
      const apv = secureRandomBytes(16);

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
        base64UrlParse(protectedHeaderEncoded),
      ) as JWEHeaderParameters;

      expect(protectedHeader.alg).toBe(ecdhAlg);
      expect(protectedHeader.enc).toBe(enc);
      expect(protectedHeader.epk).toBeDefined();
      expect(protectedHeader.epk?.kty).toBe("EC");
      expect(protectedHeader.epk?.crv).toBe(recipientPublicKeyJwk.crv);
      expect(protectedHeader.apu).toBe(base64UrlStringify(apu));
      expect(protectedHeader.apv).toBe(base64UrlStringify(apv));

      const encryptedKeyBytes = base64UrlParse(encryptedKeyEncoded, { returnAs: "uint8array" });
      expect(encryptedKeyBytes).toBeInstanceOf(Uint8Array);
      expect(encryptedKeyBytes.length).toBeGreaterThan(0);

      const expectedCek = await unwrapKey(encryptedKeyBytes, recipientKeyPair.privateKey, {
        alg: ecdhAlg,
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

      expect(base64UrlParse(protectedHeader.apu!, { returnAs: "uint8array" })).toEqual(apu);
      expect(base64UrlParse(protectedHeader.apv!, { returnAs: "uint8array" })).toEqual(apv);
      expect(cek).toEqual(expectedCek);
      expect(aad).toEqual(textEncoder.encode(protectedHeaderEncoded));
      expect(decryptedPayload).toEqual(plaintextObj);
    });

    it("should honor provided ECDH ephemeral public key", async () => {
      const providedEphemeral = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
        keyUsage: ["deriveBits"],
      });
      const providedEphemeralJwk = await exportJWK<JWK_EC_Public>(providedEphemeral.publicKey);
      const apu = secureRandomBytes(16);
      const apv = secureRandomBytes(16);

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
        base64UrlParse(protectedHeaderEncoded),
      ) as JWEHeaderParameters;

      const epk = protectedHeader.epk as JWK_EC_Public | undefined;
      expect(epk).toBeDefined();
      expect(epk?.kty).toBe("EC");
      expect(epk?.x).toBe(providedEphemeralJwk.x);
      expect(epk?.y).toBe(providedEphemeralJwk.y);
      expect(epk?.crv).toBe(providedEphemeralJwk.crv);
      expect(protectedHeader.apu).toBe(base64UrlStringify(apu));
      expect(protectedHeader.apv).toBe(base64UrlStringify(apv));

      const decryptResult = await decrypt(jwe, recipientKeyPair.privateKey, {
        returnCek: true,
      });
      expect(decryptResult.payload).toEqual(plaintextObj);

      const derivedCek = await unwrapKey(
        base64UrlParse(encryptedKeyEncoded, { returnAs: "uint8array" }),
        recipientKeyPair.privateKey,
        {
          alg: ecdhAlg,
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
      const ephemeralJwk = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
        toJWK: true,
      });

      // A JWK_EC_Private has "d" - should be accepted as the ephemeral key.
      // Encrypt covers the JWK branch in parseEphemeralKey; decrypt is not tested
      // here because the epk embedded in the header retains "d" in this code path.
      const jwe = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
        alg: ecdhAlg,
        enc,
        ecdh: { ephemeralKey: ephemeralJwk.privateKey },
      });

      expect(typeof jwe).toBe("string");
      expect(jwe.split(".")).toHaveLength(5);
    });

    it("should accept a plain object {publicKey, privateKey} of JWKs as ephemeral key", async () => {
      const ephemeralJwk = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
        toJWK: true,
      });

      const jwe = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
        alg: ecdhAlg,
        enc,
        ecdh: {
          ephemeralKey: {
            publicKey: ephemeralJwk.publicKey,
            privateKey: ephemeralJwk.privateKey,
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
            ephemeralKey: { publicKey: recipientKeyPair.publicKey, privateKey: null } as never,
          },
        }),
      ).rejects.toThrow(/publicKey and privateKey/i);
    });

    it("should accept a private CryptoKey directly as ephemeral key", async () => {
      const ephemeralPair = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
      });

      // Passing just the private CryptoKey (not a pair) covers the CryptoKey branch
      const jwe = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
        alg: ecdhAlg,
        enc,
        ecdh: { ephemeralKey: ephemeralPair.privateKey },
      });

      expect(typeof jwe).toBe("string");
      expect(jwe.split(".")).toHaveLength(5);
    });

    it("should throw when JWK ephemeral key has no private parameter d", async () => {
      const ephemeralPair = await generateKey("ECDH-ES+A128KW", {
        namedCurve: "P-256",
        toJWK: true,
      });

      await expect(
        encrypt(plaintextObj, recipientKeyPair.publicKey, {
          alg: ecdhAlg,
          enc,
          ecdh: { ephemeralKey: ephemeralPair.publicKey as never }, // public JWK — no "d"
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

    it("writes an OKP epk with no y coordinate for an X25519 recipient", async () => {
      const recipient = await generateJWK("ECDH-ES+A128KW", { namedCurve: "X25519" });
      const jwe = await encrypt(plaintextObj, recipient.publicKey, { enc });
      const epk = JSON.parse(base64UrlParse(jwe.split(".")[0])).epk;
      expect(epk).toEqual({ kty: "OKP", crv: "X25519", x: expect.any(String) });
      const { payload } = await decrypt(jwe, recipient.privateKey);
      expect(payload).toEqual(plaintextObj);
    });

    it("encrypts with an explicit X25519 ephemeral key pair and decrypts", async () => {
      const recipient = await generateJWK("ECDH-ES+A128KW", { namedCurve: "X25519" });
      const ephemeral = await generateJWK("ECDH-ES+A128KW", { namedCurve: "X25519" });

      for (const ephemeralKey of [ephemeral, ephemeral.privateKey]) {
        const jwe = await encrypt(plaintextObj, recipient.publicKey, {
          alg: "ECDH-ES+A128KW",
          enc,
          ecdh: { ephemeralKey },
        });
        const { epk } = JSON.parse(base64UrlParse(jwe.split(".")[0])) as JWEHeaderParameters;
        expect(epk).toEqual({ kty: "OKP", crv: "X25519", x: ephemeral.publicKey.x });
        const { payload } = await decrypt(jwe, recipient.privateKey);
        expect(payload).toEqual(plaintextObj);
      }
    });

    it("refuses an ephemeral public JWK whose coordinates are not strings", async () => {
      const ephemeral = await generateJWK("ECDH-ES+A128KW", { namedCurve: "P-256" });
      for (const publicKey of [
        { ...ephemeral.publicKey, x: 42 },
        { ...ephemeral.publicKey, y: undefined },
        { ...ephemeral.publicKey, crv: ["P-256"] },
      ]) {
        const error = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
          alg: ecdhAlg,
          enc,
          ecdh: {
            ephemeralKey: {
              publicKey: publicKey as unknown as JWK_EC_Public,
              privateKey: ephemeral.privateKey as JWK_EC_Private,
            },
          },
        }).catch((e) => e);
        expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
      }
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

  describe("codec failures wrap into JWTError", () => {
    let aesKey: CryptoKey;
    beforeAll(async () => {
      aesKey = await generateKey("A256KW");
    });

    async function tamperedCompact(index: number): Promise<string> {
      const jwe = await encrypt(plaintextObj, aesKey, { alg: "A256KW", enc: "A256GCM" });
      const parts = jwe.split(".");
      parts[index] = `${parts[index]}=`;
      return parts.join(".");
    }

    it.each([
      [1, "Invalid JWE: Encrypted key could not be decoded."],
      [2, "Invalid JWE: Initialization vector could not be decoded."],
      [3, "Invalid JWE: Ciphertext could not be decoded."],
      [4, "Invalid JWE: Authentication tag could not be decoded."],
    ])(
      "ERR_JWE_INVALID — malformed segment %i carries the UnsecureError cause",
      async (index, message) => {
        const error = await decrypt(await tamperedCompact(index), aesKey).catch((e) => e);
        expect(error).toBeInstanceOf(JWTError);
        expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
        expect(error.message).toBe(message);
        expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
      },
    );

    it("ERR_JWE_INVALID — malformed protected header carries the UnsecureError cause", async () => {
      const error = await decrypt(await tamperedCompact(0), aesKey).catch((e) => e);
      expect(error).toBeInstanceOf(JWTError);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Protected header could not be decoded.");
      expect(isUnsecureError(error.cause, "MALFORMED")).toBe(true);
    });
  });

  describe("RFC 7516 strictness — headers and segments", () => {
    let kwKey: CryptoKey;
    let dirKey: CryptoKey;
    let cbcKey: CryptoKey;
    let ecdhPair: CryptoKeyPair;

    beforeAll(async () => {
      const [kw, dir, cbc, ecdh] = await Promise.all([
        generateKey("A256KW"),
        generateKey("A256GCM"),
        generateKey("A128GCM"),
        generateKey("ECDH-ES", { namedCurve: "P-256" }),
      ]);
      kwKey = kw;
      dirKey = dir;
      cbcKey = cbc;
      ecdhPair = ecdh;
    });

    it("rejects a non-empty encrypted key for dir", async () => {
      const token = await encrypt(plaintextObj, dirKey, { alg: "dir", enc: "A256GCM" });
      const parts = token.split(".");
      parts[1] = base64UrlStringify(secureRandomBytes(40));
      const error = await decrypt(parts.join("."), dirKey, { algorithms: ["dir"] }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Encrypted key must be empty for dir.");
    });

    it("rejects a non-empty encrypted key for ECDH-ES", async () => {
      const token = await encrypt(plaintextObj, ecdhPair.publicKey, {
        alg: "ECDH-ES",
        enc: "A256GCM",
      });
      const parts = token.split(".");
      parts[1] = base64UrlStringify(secureRandomBytes(40));
      const error = await decrypt(parts.join("."), ecdhPair.privateKey, {
        algorithms: ["ECDH-ES"],
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Encrypted key must be empty for ECDH-ES.");
    });

    it("rejects an authentication tag grown out of the ciphertext", async () => {
      const token = await encrypt(plaintextObj, kwKey, { alg: "A256KW", enc: "A256GCM" });
      const parts = token.split(".");
      const ciphertext = base64UrlParse(parts[3], { returnAs: "uint8array" });
      const tag = base64UrlParse(parts[4], { returnAs: "uint8array" });
      const shifted = ciphertext.subarray(ciphertext.length - 4);
      parts[3] = base64UrlStringify(ciphertext.subarray(0, ciphertext.length - 4));
      parts[4] = base64UrlStringify(new Uint8Array([...shifted, ...tag]));
      const error = await decrypt(parts.join("."), kwKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe(
        "Invalid JWE: Authentication tag must be 16 bytes for A256GCM (got 20).",
      );
    });

    it("rejects an initialization vector of the wrong length", async () => {
      const token = await encrypt(plaintextObj, kwKey, { alg: "A256KW", enc: "A256GCM" });
      const parts = token.split(".");
      parts[2] = base64UrlStringify(secureRandomBytes(16));
      const error = await decrypt(parts.join("."), kwKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe(
        "Invalid JWE: Initialization vector must be 12 bytes for A256GCM (got 16).",
      );
    });

    it("rejects a truncated CBC authentication tag", async () => {
      const token = await encrypt(plaintextObj, cbcKey, {
        alg: "A128GCMKW",
        enc: "A128CBC-HS256",
      });
      const parts = token.split(".");
      const tag = base64UrlParse(parts[4], { returnAs: "uint8array" });
      parts[4] = base64UrlStringify(tag.subarray(0, 8));
      const error = await decrypt(parts.join("."), cbcKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe(
        "Invalid JWE: Authentication tag must be 16 bytes for A128CBC-HS256 (got 8).",
      );
    });

    it("rejects a protected header carrying zip", async () => {
      const token = await encrypt(plaintextObj, kwKey, { alg: "A256KW", enc: "A256GCM" });
      const tampered = replaceHeader(token, { ...readHeader(token), zip: "DEF" });
      const error = await decrypt(tampered, kwKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: compression is not supported.");
    });

    it("refuses zip on encrypt", async () => {
      const error = await encrypt(plaintextObj, kwKey, {
        alg: "A256KW",
        enc: "A256GCM",
        // @ts-expect-error `zip` is not an accepted protected header parameter
        protectedHeader: { zip: "DEF" },
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    });

    it("validates crit before key management", async () => {
      const token = await encrypt(plaintextObj, kwKey, { alg: "A256KW", enc: "A256GCM" });
      const tampered = replaceHeader(token, { ...readHeader(token), crit: ["myparam"] });
      const wrongKey = await generateKey("A256KW");
      const error = await decrypt(tampered, wrongKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toMatch(/"myparam"/);
    });

    it("rejects an unsupported enc before key management", async () => {
      const token = await encrypt(plaintextObj, kwKey, { alg: "A256KW", enc: "A256GCM" });
      const tampered = replaceHeader(token, { alg: "A256KW", enc: "A256CBC" });
      const wrongKey = await generateKey("A256KW");
      const error = await decrypt(tampered, wrongKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe('Invalid JWE: unsupported "enc" "A256CBC"');
    });

    it("quotes and bounds an unsupported enc in the error message", async () => {
      const token = await encrypt(plaintextObj, kwKey, { alg: "A256KW", enc: "A256GCM" });
      const enc = `A256CBC\n"${"x".repeat(10_000)}`;
      const tampered = replaceHeader(token, { alg: "A256KW", enc });
      const error = await decrypt(tampered, kwKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe(
        `Invalid JWE: unsupported "enc" ${JSON.stringify(`${enc.slice(0, 64)}…`)}`,
      );
    });

    it('rejects alg "none" even when allowlisted', async () => {
      const token = await encrypt(plaintextObj, kwKey, { alg: "A256KW", enc: "A256GCM" });
      const tampered = replaceHeader(token, { alg: "none", enc: "A256GCM" });
      const error = await decrypt(tampered, kwKey, {
        algorithms: ["none" as KeyManagementAlgorithm],
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
    });

    it("rejects an unknown key management alg even when allowlisted", async () => {
      const token = await encrypt(plaintextObj, kwKey, { alg: "A256KW", enc: "A256GCM" });
      const tampered = replaceHeader(token, { alg: "A256KW+HACK", enc: "A256GCM" });
      const error = await decrypt(tampered, kwKey, {
        algorithms: ["A256KW+HACK" as KeyManagementAlgorithm],
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
      expect(error.message).toBe('Key management algorithm not supported: "A256KW+HACK"');
    });

    it("quotes and bounds an unsupported key management alg in the error message", async () => {
      const token = await encrypt(plaintextObj, kwKey, { alg: "A256KW", enc: "A256GCM" });
      const alg = `A256KW\n"${"x".repeat(10_000)}`;
      const tampered = replaceHeader(token, { alg, enc: "A256GCM" });
      const error = await decrypt(tampered, kwKey).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_ALG_NOT_ALLOWED")).toBe(true);
      expect(error.message).toBe(
        `Key management algorithm not supported: ${JSON.stringify(`${alg.slice(0, 64)}…`)}`,
      );
    });

    it("compares typ under media-type normalization", async () => {
      const token = await encrypt(plaintextObj, kwKey, {
        alg: "A256KW",
        enc: "A256GCM",
        protectedHeader: { typ: "application/AT+JWT" },
      });
      await expect(decrypt(token, kwKey, { typ: "at+jwt" })).resolves.toBeDefined();
      const error = await decrypt(token, kwKey, { typ: "other+jwt" }).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toMatch(/"typ"/);
    });

    it("reports a protected header without typ as carrying none", async () => {
      const token = await encrypt("payload", kwKey, { alg: "A256KW", enc: "A256GCM" });
      const error = await decrypt(token, kwKey, { typ: "at+jwt", payload: "string" }).catch(
        (e) => e,
      );
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe(
        'Invalid JWE: the protected header carries no "typ", expected "at+jwt".',
      );
    });
  });
});

describe.concurrent("JWE payload typing", () => {
  let key: CryptoKey;

  beforeAll(async () => {
    key = await generateKey("A256KW");
  });

  const opts = { alg: "A256KW", enc: "A256GCM" } as const;

  it("returns the claims object by default", async () => {
    const jwe = await encrypt({ sub: "u" }, key, opts);
    const { payload } = await decrypt(jwe, key);
    expect(payload).toEqual({ sub: "u" });
  });

  it.each(["[1,2]", "123", '"str"', "null", "not json at all"])(
    'rejects payload "%s" under the default mode',
    async (raw) => {
      const jwe = await encrypt(raw, key, opts);
      const error = await decrypt(jwe, key).catch((e) => e);
      expect(isJWTError(error, "ERR_JWE_INVALID")).toBe(true);
      expect(error.message).toBe("Invalid JWE: Payload is not a JSON object.");
    },
  );

  it('returns a JSON-shaped string verbatim under payload: "string"', async () => {
    const jwe = await encrypt('{"sub":"admin"}', key, opts);
    const { payload } = await decrypt(jwe, key, { payload: "string" });
    expect(payload).toBe('{"sub":"admin"}');
  });

  it('forceUint8Array matches payload: "bytes"', async () => {
    const jwe = await encrypt(textEncoder.encode("raw bytes"), key, opts);
    const aliased = await decrypt(jwe, key, { forceUint8Array: true });
    const explicit = await decrypt(jwe, key, { payload: "bytes" });
    expect(aliased.payload).toBeInstanceOf(Uint8Array);
    expect(aliased.payload).toEqual(explicit.payload);
  });

  it("rejects forceUint8Array contradicting payload", async () => {
    const jwe = await encrypt({ sub: "u" }, key, opts);
    const error = await decrypt(jwe, key, {
      forceUint8Array: false,
      payload: "bytes",
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it('rejects validateClaims: true outside payload: "json"', async () => {
    const jwe = await encrypt("plain", key, opts);
    const error = await decrypt(jwe, key, {
      payload: "bytes",
      validateClaims: true,
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"validateClaims" requires payload: "json".');
  });

  it("validates claims of a payload that was encrypted as a string", async () => {
    const jwe = await encrypt(JSON.stringify({ sub: "u", exp: 1_000_000 }), key, opts);
    const error = await decrypt(jwe, key).catch((e) => e);
    expect(isJWTError(error, "ERR_JWT_EXPIRED")).toBe(true);
  });
});

describe.concurrent("JWE string keys are passwords only", () => {
  const message = "Key must be a JWK, CryptoKey or Uint8Array, not a string.";

  it("derives a PBES2 key from a password on both sides", async () => {
    const jwe = await encrypt({ sub: "u" }, "correct horse battery staple", {
      alg: "PBES2-HS256+A128KW",
      enc: "A128GCM",
      p2c: 1000,
    });
    const { payload } = await decrypt(jwe, "correct horse battery staple");
    expect(payload).toEqual({ sub: "u" });
  });

  it("rejects a string key under a non-PBES2 alg on encrypt", async () => {
    const error = await encrypt({ sub: "u" }, "a-256-bit-secret-value-as-string", {
      alg: "dir",
      enc: "A256GCM",
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(error.message).toBe(message);
  });

  it("rejects a string key under a non-PBES2 alg on decrypt", async () => {
    const key = await generateKey("A256GCM");
    const jwe = await encrypt({ sub: "u" }, key, { alg: "dir", enc: "A256GCM" });
    const error = await decrypt(jwe, "a-256-bit-secret-value-as-string", {
      algorithms: ["dir"],
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(error.message).toBe(message);
  });
});

describe.concurrent("JWE producer option gates", () => {
  let aesKey: JWK_oct<"A256KW">;
  let ecdhKey: JWK_Pair<"ECDH-ES+A256KW">;

  beforeAll(async () => {
    [aesKey, ecdhKey] = await Promise.all([generateJWK("A256KW"), generateJWK("ECDH-ES+A256KW")]);
  });

  it('types an object payload as "JWT" without a "cty"', async () => {
    const { protectedHeader } = await decrypt(await encrypt({ sub: "u1" }, aesKey), aesKey);
    expect(protectedHeader.typ).toBe("JWT");
    expect(protectedHeader).not.toHaveProperty("cty");
  });

  it('defaults "enc" to A256GCM for a JWK whose "enc" member is undefined', async () => {
    const jwe = await encrypt({ sub: "u1" }, { ...aesKey, enc: undefined });
    const { protectedHeader } = await decrypt(jwe, aesKey);
    expect(protectedHeader).toMatchObject({ alg: "A256KW", enc: "A256GCM" });
  });

  it('keeps a "cty" set in protectedHeader', async () => {
    const jwe = await encrypt({ sub: "u1" }, aesKey, {
      protectedHeader: { cty: "application/json" },
    });
    const { protectedHeader } = await decrypt(jwe, aesKey);
    expect(protectedHeader).toMatchObject({ typ: "JWT", cty: "application/json" });
  });

  it.each([
    ["an empty array", []],
    ["a string", "app"],
    ["an array with a non-string entry", ["app", 1]],
  ])("refuses a crit that is %s", async (_label, crit) => {
    const error = await encrypt("payload", aesKey, {
      protectedHeader: { crit, app: "web" } as never,
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it.each(["alg", "enc", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c"])(
    "refuses the registered parameter %s in crit",
    async (param) => {
      const error = await encrypt("payload", aesKey, {
        protectedHeader: { crit: [param], [param]: "irrelevant" },
      }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    },
  );

  it.each([
    ["a string", "abc"],
    ["an array", ["typ"]],
    ["null", null],
  ])("refuses a protected header that is %s", async (_label, protectedHeader) => {
    const error = await encrypt("payload", aesKey, { protectedHeader } as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"options.protectedHeader" must be an object.');
  });

  it("refuses a crit naming a parameter the header does not carry", async () => {
    const error = await encrypt("payload", aesKey, {
      protectedHeader: { crit: ["app"] },
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("app");
  });

  it("accepts a crit whose parameters the header carries", async () => {
    const jwe = await encrypt("payload", aesKey, {
      protectedHeader: { crit: ["app"], app: "web" },
    });
    const { payload } = await decrypt(jwe, aesKey, {
      payload: "string",
      recognizedHeaders: ["app"],
    });
    expect(payload).toBe("payload");
  });

  it("refuses a protected header that cannot be serialized", async () => {
    const circular: Record<string, unknown> = { app: "web" };
    circular.self = circular;

    for (const header of [{ n: 1n } as never, circular as never]) {
      const error = await encrypt("payload", aesKey, { protectedHeader: header }).catch((e) => e);
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toContain("protected header");
    }
  });

  it.each(["partyUInfo", "partyVInfo"] as const)("refuses a %s that is not bytes", async (name) => {
    const error = await encrypt("payload", ecdhKey.publicKey, {
      enc: "A128GCM",
      ecdh: { [name]: "not-bytes" },
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain(name === "partyUInfo" ? "apu" : "apv");
  });

  it.each(["partyUInfo", "partyVInfo"] as const)("refuses a %s over 1024 bytes", async (name) => {
    const error = await encrypt("payload", ecdhKey.publicKey, {
      enc: "A128GCM",
      ecdh: { [name]: secureRandomBytes(1025) },
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain("1024");
  });

  it("accepts party info at the bound", async () => {
    const jwe = await encrypt("payload", ecdhKey.publicKey, {
      enc: "A128GCM",
      ecdh: { partyUInfo: secureRandomBytes(1024) },
    });
    const { payload } = await decrypt(jwe, ecdhKey.privateKey, { payload: "string" });
    expect(payload).toBe("payload");
  });

  it("omits empty party info from the header", async () => {
    const jwe = await encrypt("payload", ecdhKey.publicKey, {
      enc: "A128GCM",
      ecdh: { partyUInfo: new Uint8Array(0), partyVInfo: new Uint8Array(0) },
    });
    const header = JSON.parse(base64UrlParse(jwe.split(".")[0]));
    expect(header).not.toHaveProperty("apu");
    expect(header).not.toHaveProperty("apv");
    const { payload } = await decrypt(jwe, ecdhKey.privateKey, { payload: "string" });
    expect(payload).toBe("payload");
  });

  it("refuses an ephemeral key on another curve than the recipient key", async () => {
    const ephemeral = await generateJWK("ECDH-ES+A256KW", { namedCurve: "X25519" });
    const error = await encrypt("payload", ecdhKey.publicKey, {
      enc: "A128GCM",
      ecdh: { ephemeralKey: ephemeral.privateKey },
    }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(error.message).toBe(
      'ECDH-ES ephemeral key curve "X25519" does not match recipient curve "P-256".',
    );
  });

  it.each([[123], [null], [["JWT"]]])("refuses a protected header typ of %j", async (typ) => {
    for (const payload of [{ sub: "u" }, "payload"]) {
      const error = await encrypt(payload, aesKey, { protectedHeader: { typ } as never }).catch(
        (e) => e,
      );
      expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
      expect(error.message).toBe('"typ" must be a string.');
    }
  });
});

describe.concurrent("JWE decryption option gates", () => {
  let key: JWK_oct<"A256KW">;
  let token: string;

  beforeAll(async () => {
    key = await generateJWK("A256KW");
    token = await encrypt({ sub: "u", aud: "a" }, key, {
      enc: "A256GCM",
      protectedHeader: { typ: "at+jwt" },
    });
  });

  it.each([
    ["an empty typ", { typ: "" }],
    ["a typ that is not a string", { typ: 123 }],
    ["an algorithms allowlist that is not an array", { algorithms: "A256KW-disabled" }],
    [
      "an encryptionAlgorithms allowlist that is not an array",
      { encryptionAlgorithms: "A256GCM-disabled" },
    ],
    ["an empty audience", { audience: "" }],
    ["maxTokenAge: 0", { maxTokenAge: 0 }],
  ])("refuses %s", async (_label, options) => {
    const error = await decrypt(token, key, options as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
  });

  it("refuses options that are not an object", async () => {
    const error = await decrypt(token, key, null as never).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toBe('"options" must be an object.');
  });

  it("quotes and bounds a header kid echoed in a key-not-found message", async () => {
    const kid = `evil\nInjected: yes ${"x".repeat(200)}`;
    const encrypted = await encrypt({ sub: "u" }, { ...key, kid }, { enc: "A256GCM" });
    const set = { keys: [{ ...key, kid: "other" }] };
    const error = await decrypt(encrypted, set, { allowSymmetricJWKSet: true }).catch((e) => e);
    expect(isJWTError(error, "ERR_JWK_KEY_NOT_FOUND")).toBe(true);
    expect(error.message).not.toContain("\n");
    expect(error.message).toContain(String.raw`with kid "evil\nInjected: yes x`);
    expect(error.message.length).toBeLessThan(120);
  });

  it("honours extractable: false for the unwrapped content encryption key", async () => {
    const { cek } = await decrypt(token, key, { returnCek: true });
    expect(cek).toBeInstanceOf(Uint8Array);
    const error = await decrypt(token, key, { returnCek: true, extractable: false }).catch(
      (e) => e,
    );
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain('"returnCek"');
  });

  it("refuses returnCek over a dir key that is not extractable", async () => {
    const cekKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ]);
    const encrypted = await encrypt({ sub: "u" }, cekKey, { alg: "dir", enc: "A256GCM" });
    await expect(decrypt(encrypted, cekKey)).resolves.toHaveProperty("payload", { sub: "u" });
    const error = await decrypt(encrypted, cekKey, { returnCek: true }).catch((e) => e);
    expect(isJWTError(error, "ERR_INVALID_OPTION")).toBe(true);
    expect(error.message).toContain('"returnCek"');
  });
});

describe("types", () => {
  type MyClaims = { sub: string; role: "admin" | "user" };
  const key = new Uint8Array(32);
  interface MyClaimsInterface {
    sub: string;
    role: "admin" | "user";
  }

  it("accepts an interface as the claims type", () => {
    expectTypeOf(() => decrypt<MyClaimsInterface>("", key)).returns.resolves.toEqualTypeOf<
      JWEDecryptResult<MyClaimsInterface>
    >();
  });

  it("returns the claims for the default and json payload modes", () => {
    expectTypeOf(() => decrypt("", key)).returns.resolves.toEqualTypeOf<
      JWEDecryptResult<JWTClaims>
    >();
    expectTypeOf(() => decrypt("", key, { payload: "json" })).returns.resolves.toEqualTypeOf<
      JWEDecryptResult<JWTClaims>
    >();
    expectTypeOf(() => decrypt<MyClaims>("", key)).returns.resolves.toEqualTypeOf<
      JWEDecryptResult<MyClaims>
    >();
    expectTypeOf(() =>
      decrypt<MyClaims>("", "password", { payload: "json" }),
    ).returns.resolves.toEqualTypeOf<JWEDecryptResult<MyClaims>>();
  });

  it("returns a string or bytes payload for the string and bytes modes", () => {
    expectTypeOf(() => decrypt("", key, { payload: "string" })).returns.resolves.toEqualTypeOf<
      JWEDecryptResult<string>
    >();
    expectTypeOf(() => decrypt("", key, { payload: "bytes" })).returns.resolves.toEqualTypeOf<
      JWEDecryptResult<Uint8Array<ArrayBuffer>>
    >();
  });

  it("returns the union of payloads for a mode that is not a literal", () => {
    expectTypeOf((payload: JOSEPayloadMode) =>
      decrypt("", key, { payload }),
    ).returns.resolves.toEqualTypeOf<
      JWEDecryptResult<JWTClaims | string | Uint8Array<ArrayBuffer>>
    >();
    expectTypeOf((options: JWEDecryptOptions) =>
      decrypt("", key, options),
    ).returns.resolves.toEqualTypeOf<
      JWEDecryptResult<JWTClaims | string | Uint8Array<ArrayBuffer>>
    >();
  });

  it("keeps the deprecated forceUint8Array overload returning bytes", () => {
    expectTypeOf(() => decrypt("", key, { forceUint8Array: true })).returns.resolves.toEqualTypeOf<
      JWEDecryptResult<Uint8Array<ArrayBuffer>>
    >();
  });

  it("rejects an unknown payload mode and a claims type outside the json mode", () => {
    // @ts-expect-error not a payload mode
    expectTypeOf(() => decrypt("", key, { payload: "nonsense" }));
    // @ts-expect-error a claims type implies payload: "json"
    expectTypeOf(() => decrypt<MyClaims>("", key, { payload: "bytes" }));
  });

  it("exports the payload map from unjwt/jwe", () => {
    expectTypeOf<PayloadOf<"string">>().toEqualTypeOf<string>();
    expectTypeOf<JOSEPayloadTypeMap<MyClaims>["json"]>().toEqualTypeOf<MyClaims>();
  });
});

/**
 * A JWE whose protected header carries members the producer refuses to write.
 * The header gates run before key management, so the token never needs to open.
 */
function withProtectedHeader(token: string, members: Record<string, unknown>): string {
  const parts = token.split(".");
  const header = JSON.parse(base64UrlParse(parts[0])) as Record<string, unknown>;
  parts[0] = base64UrlStringify(JSON.stringify({ ...header, ...members }));
  return parts.join(".");
}

function replaceHeader(token: string, header: Record<string, unknown>): string {
  const parts = token.split(".");
  parts[0] = base64UrlStringify(JSON.stringify(header));
  return parts.join(".");
}

function readHeader(token: string): Record<string, unknown> {
  return JSON.parse(base64UrlParse(token.split(".")[0]));
}

describe("JSON-only header input", () => {
  it("reports a protectedHeader value JSON cannot carry as ERR_INVALID_OPTION", async () => {
    const key = await generateJWK("A256GCM");
    await expect(
      encrypt({ a: 1 }, key, {
        alg: "dir",
        enc: "A256GCM",
        protectedHeader: { when: new Date(0) },
      }),
    ).rejects.toMatchObject({ code: "ERR_INVALID_OPTION", cause: { code: "INVALID_TYPE" } });
    expect(await encrypt({ when: new Date(0) }, key, { alg: "dir", enc: "A256GCM" })).toEqual(
      expect.any(String),
    );
  });
});
