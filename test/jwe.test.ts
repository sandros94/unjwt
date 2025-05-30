import { describe, it, expect, beforeAll } from "vitest";
import { encrypt, decrypt } from "../src/jwe";
import { generateKey /* exportKey */ } from "../src/jwk";
import {
  randomBytes,
  textEncoder,
  textDecoder,
  base64UrlEncode,
  base64UrlDecode,
} from "../src/utils";
import type {
  JWK,
  JWTClaims,
  // JWK_EC_Public,
  // JWEHeaderParameters,
  JWEKeyLookupFunction,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
} from "../src/types";

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
      generateKey("ES256"), // P-256 for ECDH-ES
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
    plaintext: any;
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
    // TODO: not working
    /*     {
      alg: "RSA-OAEP-256",
      enc: "A256CBC-HS512",
      plaintext: plaintextBytes,
      desc: "RSA-OAEP-256 with A256CBC-HS512",
    }, */
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
        let encryptionKey: CryptoKey | JWK | string | Uint8Array;
        let decryptionKey:
          | CryptoKey
          | JWK
          | string
          | Uint8Array
          | JWEKeyLookupFunction;

        const keySet = keys[alg as string];
        if (!keySet) throw new Error(`Key for ${alg} not found`);

        if (alg.startsWith("RSA-")) {
          encryptionKey = keySet.publicKey!;
          decryptionKey = keySet.privateKey!;
        } else if (alg.startsWith("ECDH-ES")) {
          encryptionKey = keySet.publicKey!; // Recipient's public key
          decryptionKey = keySet.privateKey!; // Recipient's private key
        } else if (alg.startsWith("PBES2")) {
          encryptionKey = keySet.password!;
          decryptionKey = keySet.password!;
        } else {
          encryptionKey = keySet.key as CryptoKey;
          decryptionKey = keySet.key as CryptoKey;
        }

        const p2s = alg.startsWith("PBES2") ? randomBytes(16) : undefined;
        const p2c = alg.startsWith("PBES2") ? 2000 : undefined; // Low for tests

        const jwe = await encrypt(plaintext, encryptionKey, {
          alg,
          enc,
          p2s,
          p2c,
          protectedHeader: { kid: `test-${alg}-${enc}` },
        });

        expect(jwe).toBeTypeOf("string");
        const parts = jwe.split(".");
        expect(parts.length).toBe(5);

        const {
          payload: decryptedPayload,
          protectedHeader,
          cek,
        } = await decrypt(jwe, decryptionKey, {
          algorithms: [alg],
          encryptionAlgorithms: [enc],
        });

        expect(protectedHeader.alg).toBe(alg);
        expect(protectedHeader.enc).toBe(enc);
        expect(protectedHeader.kid).toBe(`test-${alg}-${enc}`);
        expect(cek).toBeInstanceOf(Uint8Array);

        if (typeof plaintext === "string") {
          expect(decryptedPayload).toBe(plaintext);
        } else if (plaintext instanceof Uint8Array) {
          expect(decryptedPayload).toEqual(textDecoder.decode(plaintext));
        } else {
          expect(decryptedPayload).toEqual(plaintext);
          expect(protectedHeader.typ).toBe("JWT");
        }

        if (alg.startsWith("PBES2")) {
          expect(protectedHeader.p2s).toBeDefined();
          expect(protectedHeader.p2c).toBe(p2c);
        }
        if (alg.includes("GCMKW")) {
          expect(protectedHeader.iv).toBeDefined();
          expect(protectedHeader.tag).toBeDefined();
        }
        if (alg.startsWith("ECDH-ES")) {
          expect(protectedHeader.epk).toBeDefined();
          expect(protectedHeader.epk?.kty).toBe("EC");
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
    });

    it("should encrypt and decrypt while only providing a JWK", async () => {
      const t = "Hello, World!";
      const jwk: JWK = {
        key_ops: ["wrapKey", "unwrapKey"],
        ext: true,
        kty: "oct",
        k: "mzR5rkgr41d-4e_fVMYQ1g",
        alg: "A128KW",
      };

      const jwe = await encrypt(t, jwk);
      const { payload } = await decrypt(jwe, jwk);

      expect(payload).toBe(t);
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

    beforeAll(async () => {
      key = keys[alg]!.key as CryptoKey;
      jwe = await encrypt(plaintextObj, key, { alg, enc });
    });

    it("should decrypt with a key lookup function", async () => {
      const keyLookup: JWEKeyLookupFunction = (header) => {
        if (header.alg === alg) return key;
        throw new Error("Key not found");
      };
      const { payload } = await decrypt(jwe, keyLookup);
      expect(payload).toEqual(plaintextObj);
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
    });

    it("should throw if content encryption algorithm not allowed", async () => {
      await expect(
        decrypt(jwe, key, { encryptionAlgorithms: ["A256GCM"] }),
      ).rejects.toThrow(`Content encryption algorithm not allowed: ${enc}`);
    });

    it("should throw for decryption failure (e.g., wrong key)", async () => {
      const wrongKey = await generateKey("A128KW");
      await expect(decrypt(jwe, wrongKey)).rejects.toThrow();
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
        decrypt(jweUnknownCrit, key, { critical: ["anotherParam"] }),
      ).rejects.toThrow(
        "Critical header parameter not understood: unknownParam",
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
  });

  // TODO: not working
  // describe("ECDH-ES specific parameters", () => {
  //   const ecdhAlg: KeyManagementAlgorithm = "ECDH-ES+A128KW";
  //   const enc: ContentEncryptionAlgorithm = "A128GCM";
  //   let recipientKeyPair: CryptoKeyPair;
  //   let recipientPublicKeyJwk: JWK;

  //   beforeAll(async () => {
  //     recipientKeyPair = keys[ecdhAlg]!.key as CryptoKeyPair;
  //     recipientPublicKeyJwk = await exportKey(recipientKeyPair.publicKey);
  //   });

  //   it("should encrypt and decrypt with ECDH-ES and include epk", async () => {
  //     const apu = randomBytes(16);
  //     const apv = randomBytes(16);

  //     const jwe = await encrypt(plaintextObj, recipientKeyPair.publicKey, {
  //       // Encrypt with recipient's public key
  //       alg: ecdhAlg,
  //       enc,
  //       ecdhPartyUInfo: apu,
  //       ecdhPartyVInfo: apv,
  //     });

  //     const parts = jwe.split(".");
  //     const protectedHeaderEncoded = parts[0];
  //     const protectedHeader = JSON.parse(
  //       base64UrlDecode(protectedHeaderEncoded),
  //     ) as JWEHeaderParameters;

  //     expect(protectedHeader.alg).toBe(ecdhAlg);
  //     expect(protectedHeader.enc).toBe(enc);
  //     expect(protectedHeader.epk).toBeDefined();
  //     expect(protectedHeader.epk?.kty).toBe("EC");
  //     expect(protectedHeader.epk?.crv).toBe(
  //       (recipientPublicKeyJwk as JWK_EC_Public).crv,
  //     );
  //     expect(protectedHeader.apu).toBe(base64UrlEncode(apu));
  //     expect(protectedHeader.apv).toBe(base64UrlEncode(apv));

  //     const { payload: decryptedPayload } = await decrypt(
  //       jwe,
  //       recipientKeyPair.privateKey, // Decrypt with recipient's private key
  //     );
  //     expect(decryptedPayload).toEqual(plaintextObj);
  //   });
  // });
});
