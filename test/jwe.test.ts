import * as jose from "jose";
import { describe, it, expect, beforeAll } from "vitest";
import { encrypt, decrypt } from "../src/core/jwe";
import { generateKey, exportKey, unwrapKey } from "../src/core/jwk";
import {
  randomBytes,
  textEncoder,
  textDecoder,
  base64UrlEncode,
  base64UrlDecode,
} from "../src/core/utils";
import type {
  JWK,
  JWK_EC_Public,
  JWTClaims,
  JWEKeyLookupFunction,
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
  const plaintextBytes = textEncoder.encode(
    "This is a plaintext as Uint8Array.",
  );

  interface TestKeySet {
    key?: CryptoKey | CryptoKeyPair | string; // string for password
    publicKey?: CryptoKey | JWK;
    privateKey?: CryptoKey | JWK;
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
    plaintext: object | string | Uint8Array;
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
          | JWK
          | string
          | Uint8Array<ArrayBuffer>
          | JWEKeyLookupFunction;
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
          const { plaintext: decryptedByJose } = await jose.compactDecrypt(
            jwe,
            decryptionKey,
          );
          expect(decryptedByJose).toEqual(plaintextBuffer);
        }

        const jweFromJose = await new jose.CompactEncrypt(plaintextBuffer)
          .setProtectedHeader({ alg, enc, cty: "application/json" })
          .encrypt(encryptionKey);

        const { payload: decrypted } = await decrypt(
          jweFromJose,
          decryptionKey,
        );

        if (
          typeof plaintext === "object" &&
          !(plaintext instanceof Uint8Array)
        ) {
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
      const { plaintext: josePlaintext } = await jose.compactDecrypt(
        jwe,
        joseKey,
      );
      expect(textDecoder.decode(josePlaintext)).toBe(t);
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

    it("should throw if alg is missing", async () => {
      const key = keys["A128KW"]!.key as CryptoKey;
      await expect(
        encrypt(plaintextString, key, { enc: "A128GCM" } as any),
      ).rejects.toThrow(
        'JWE "alg" (Key Management Algorithm) must be provided in options',
      );
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

    it("should decrypt with a key lookup function", async () => {
      const keyLookup: JWEKeyLookupFunction = (header) => {
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
        "Protected header is not valid Base64URL or JSON",
      );
    });

    it("should throw if protected header is not valid JSON", async () => {
      const parts = jwe.split(".");
      parts[0] = base64UrlEncode("not json");
      await expect(decrypt(parts.join("."), key)).rejects.toThrow(
        "Protected header is not valid Base64URL or JSON",
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
      await expect(
        decrypt(jwe, key, { algorithms: ["A256KW"] }),
      ).rejects.toThrow(`Key management algorithm not allowed: ${alg}`);

      await expect(
        jose.compactDecrypt(jwe, joseKey, {
          keyManagementAlgorithms: ["A256KW"],
        }),
      ).rejects.toThrow('"alg" (Algorithm) Header Parameter value not allowed');
    });

    it("should throw if content encryption algorithm not allowed", async () => {
      await expect(
        decrypt(jwe, key, { encryptionAlgorithms: ["A256GCM"] }),
      ).rejects.toThrow(`Content encryption algorithm not allowed: ${enc}`);

      await expect(
        jose.compactDecrypt(jwe, joseKey, {
          contentEncryptionAlgorithms: ["A256GCM"],
        }),
      ).rejects.toThrow(
        '"enc" (Encryption Algorithm) Header Parameter value not allowed',
      );
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
      await expect(
        decrypt(jweCrit, key, { critical: ["exp"] }),
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
        "Unprocessed critical header parameters: unknownParam",
      );
      await expect(
        jose.compactDecrypt(jweUnknownCrit, joseKey),
      ).rejects.toThrow(
        'Extension Header Parameter "unknownParam" is not recognized',
      );
    });

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
      const jweBytesPlain = await encrypt(
        textEncoder.encode(plaintextString),
        key,
        { alg, enc },
      );
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

        const { payload, protectedHeader } = await decrypt<JWTClaims>(
          jwe,
          key,
          {
            currentDate: new Date(30_000), // 30 seconds in
          },
        );
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

        await expect(
          decrypt(jweCrit, key, { requiredHeaders: ["exp"] }),
        ).resolves.toBeDefined();
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
          validateJWT: false,
        });
        expect(payload.exp).toBe(60);
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
          `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: 1970-01-01T00:01:00.000Z`,
        );
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
      recipientPublicKeyJwk = (await exportKey(
        recipientKeyPair.publicKey,
      )) as JWK_EC_Public;
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

      const expectedCek = await unwrapKey(
        ecdhAlg,
        encryptedKeyBytes,
        recipientKeyPair.privateKey,
        {
          epk: protectedHeader.epk!,
          apu: protectedHeader.apu,
          apv: protectedHeader.apv,
          enc,
          returnAs: false,
        },
      );
      expect(expectedCek).toBeInstanceOf(Uint8Array);

      const {
        payload: decryptedPayload,
        cek,
        aad,
      } = await decrypt(jwe, recipientKeyPair.privateKey);

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
      const providedEphemeralJwk = (await exportKey(
        providedEphemeral.publicKey,
      )) as JWK_EC_Public;
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

      const decryptResult = await decrypt(jwe, recipientKeyPair.privateKey);
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
          returnAs: false,
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
  });
});
