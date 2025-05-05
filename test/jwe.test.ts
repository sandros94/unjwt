import { describe, it, expect, beforeAll, vi } from "vitest";
import { encrypt, decrypt } from "../src/jwe";
import { generateKey, exportKey, importKey } from "../src/jwk";
import {
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
  textEncoder,
} from "../src/utils";
import type {
  JWK,
  JWEHeaderParameters,
  AesGcmAlgorithm,
  RsaWrapAlgorithm,
  HmacWrapAlgorithm,
} from "../src/types";

// --- Test Data ---
const plaintextString = "This is the plaintext message.";
const plaintextObject = {
  iss: "test-issuer",
  aud: "test-audience",
  exp: 1_700_000_000,
};
const plaintextBytes = textEncoder.encode(plaintextString);
const plaintextBuffer = plaintextBytes.buffer as ArrayBuffer;

// --- Keys (Generated once for efficiency) ---
let a128kwKey: CryptoKey;
let a128kwJwk: JWK;
let a256kwKey: CryptoKey;
let a256kwJwk: JWK;
let rsaOaepKeyPair: CryptoKeyPair;
let rsaOaepPublicJwk: JWK;
let rsaOaepPrivateJwk: JWK;
let rsaOaep256KeyPair: CryptoKeyPair;
let rsaOaep256PublicJwk: JWK;
let rsaOaep256PrivateJwk: JWK;

// Supported alg/enc combinations for testing
const testCombinations: {
  alg: RsaWrapAlgorithm | HmacWrapAlgorithm;
  enc: AesGcmAlgorithm;
}[] = [
  { alg: "A128KW", enc: "A128GCM" },
  { alg: "A256KW", enc: "A256GCM" },
  { alg: "RSA-OAEP", enc: "A128GCM" },
  { alg: "RSA-OAEP-256", enc: "A256GCM" },
];

beforeAll(async () => {
  // AES-KW Keys
  a128kwKey = await generateKey("A128KW");
  a128kwJwk = await exportKey(a128kwKey);
  a256kwKey = await generateKey("A256KW");
  a256kwJwk = await exportKey(a256kwKey);

  // RSA-OAEP Keys
  rsaOaepKeyPair = await generateKey("RSA-OAEP");
  rsaOaepPublicJwk = await exportKey(rsaOaepKeyPair.publicKey);
  rsaOaepPrivateJwk = await exportKey(rsaOaepKeyPair.privateKey);

  // RSA-OAEP-256 Keys
  rsaOaep256KeyPair = await generateKey("RSA-OAEP-256");
  rsaOaep256PublicJwk = await exportKey(rsaOaep256KeyPair.publicKey);
  rsaOaep256PrivateJwk = await exportKey(rsaOaep256KeyPair.privateKey);
});

// --- Helper to get keys based on alg ---
const getKeysForAlg = (alg: RsaWrapAlgorithm | HmacWrapAlgorithm) => {
  switch (alg) {
    case "A128KW": {
      return {
        wrapKey: a128kwKey,
        wrapJwk: a128kwJwk,
        unwrapKey: a128kwKey,
        unwrapJwk: a128kwJwk,
      };
    }
    case "A256KW": {
      return {
        wrapKey: a256kwKey,
        wrapJwk: a256kwJwk,
        unwrapKey: a256kwKey,
        unwrapJwk: a256kwJwk,
      };
    }
    case "RSA-OAEP": {
      return {
        wrapKey: rsaOaepKeyPair?.publicKey,
        wrapJwk: rsaOaepPublicJwk,
        unwrapKey: rsaOaepKeyPair?.privateKey,
        unwrapJwk: rsaOaepPrivateJwk,
      };
    }
    case "RSA-OAEP-256": {
      return {
        wrapKey: rsaOaep256KeyPair?.publicKey,
        wrapJwk: rsaOaep256PublicJwk,
        unwrapKey: rsaOaep256KeyPair?.privateKey,
        unwrapJwk: rsaOaep256PrivateJwk,
      };
    }
    default: {
      throw new Error(`Unsupported test algorithm: ${alg}`);
    }
  }
};

// --- Helper to Decode JWE for Inspection ---
const decodeJwe = (jwe: string) => {
  const parts = jwe.split(".");
  if (parts.length !== 5) throw new Error("Invalid JWE format");
  const [header, encryptedKey, iv, ciphertext, tag] = parts;
  return {
    header: JSON.parse(base64UrlDecode(header)),
    encryptedKeyBytes: base64UrlDecode(encryptedKey, false),
    ivBytes: base64UrlDecode(iv, false),
    ciphertextBytes: base64UrlDecode(ciphertext, false),
    tagBytes: base64UrlDecode(tag, false),
    headerRaw: header,
    encryptedKeyRaw: encryptedKey,
    ivRaw: iv,
    ciphertextRaw: ciphertext,
    tagRaw: tag,
  };
};

describe.concurrent("JWE Utilities", () => {
  describe("encrypt", () => {
    for (const { alg, enc } of testCombinations) {
      it(`should encrypt with ${alg}/${enc} using CryptoKey`, async () => {
        const keys = getKeysForAlg(alg);
        const jwe = await encrypt(plaintextString, keys.wrapKey, {
          protectedHeader: { alg, enc },
        });
        const decoded = decodeJwe(jwe);
        expect(decoded.header.alg).toBe(alg);
        expect(decoded.header.enc).toBe(enc);
        expect(decoded.encryptedKeyBytes.length).toBeGreaterThan(0);
        expect(decoded.ivBytes.length).toBeGreaterThan(0); // Typically 12 for GCM
        expect(decoded.ciphertextBytes.length).toBeGreaterThan(0);
        expect(decoded.tagBytes.length).toBeGreaterThan(0); // Typically 16 for GCM
      });

      it(`should encrypt with ${alg}/${enc} using JWK`, async () => {
        const keys = getKeysForAlg(alg);
        const jwe = await encrypt(
          JSON.stringify(plaintextObject),
          keys.wrapJwk,
          { protectedHeader: { alg, enc, typ: "JWT" } },
        );
        const decoded = decodeJwe(jwe);
        expect(decoded.header.alg).toBe(alg);
        expect(decoded.header.enc).toBe(enc);
        expect(decoded.header.typ).toBe("JWT"); // Check extra header param
      });
    }

    it("should encrypt Uint8Array payload", async () => {
      const { alg, enc } = testCombinations[0]!; // Use first combination
      const keys = getKeysForAlg(alg);
      const jwe = await encrypt(plaintextBytes, keys.wrapKey, {
        protectedHeader: { alg, enc },
      });
      const decoded = decodeJwe(jwe);
      expect(decoded.header.alg).toBe(alg);
      expect(decoded.header.enc).toBe(enc);
      // Decrypt to verify content later
      const { plaintext } = await decrypt(jwe, keys.unwrapKey, {
        toString: false,
      });
      expect(plaintext).toEqual(plaintextBytes);
    });

    it("should encrypt ArrayBuffer payload", async () => {
      const { alg, enc } = testCombinations[1]!; // Use second combination
      const keys = getKeysForAlg(alg);
      const jwe = await encrypt(plaintextBuffer, keys.wrapJwk, {
        protectedHeader: { alg, enc },
      });
      const decoded = decodeJwe(jwe);
      expect(decoded.header.alg).toBe(alg);
      expect(decoded.header.enc).toBe(enc);
      // Decrypt to verify content later
      const { plaintext } = await decrypt(jwe, keys.unwrapJwk, {
        toString: false,
      });
      expect(new Uint8Array(plaintext)).toEqual(
        new Uint8Array(plaintextBuffer),
      );
    });

    it("should encrypt empty string payload", async () => {
      const { alg, enc } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = await encrypt("", keys.wrapKey, {
        protectedHeader: { alg, enc },
      });
      const decoded = decodeJwe(jwe);
      expect(decoded.header.alg).toBe(alg);
      expect(decoded.header.enc).toBe(enc);
      const { plaintext } = await decrypt(jwe, keys.unwrapKey);
      expect(plaintext).toBe("");
    });

    // --- Error Handling ---

    it("should throw if alg is missing in protectedHeader", async () => {
      const { enc } = testCombinations[0]!;
      const keys = getKeysForAlg(testCombinations[0]!.alg);
      await expect(
        encrypt(plaintextString, keys.wrapKey, {
          // @ts-expect-error - Testing missing alg
          protectedHeader: { enc },
        }),
      ).rejects.toThrow(/Algorithm \('alg'\) must be specified/);
    });

    it("should throw if enc is missing in protectedHeader", async () => {
      const { alg } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      await expect(
        encrypt(plaintextString, keys.wrapKey, {
          // @ts-expect-error - Testing missing enc
          protectedHeader: { alg },
        }),
      ).rejects.toThrow(/Encryption algorithm \('enc'\) must be specified/);
    });

    it("should throw for unsupported alg", async () => {
      const { enc } = testCombinations[0]!;
      const keys = getKeysForAlg(testCombinations[0]!.alg);
      await expect(
        encrypt(plaintextString, keys.wrapKey, {
          protectedHeader: { alg: "UnsupportedAlg", enc },
        }),
      ).rejects.toThrow(
        "Algorithm ('alg') must be specified in protectedHeader and must be a supported JWE key wrapping algorithm. Got: UnsupportedAlg",
      );
    });

    it("should throw for unsupported enc", async () => {
      const { alg } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      await expect(
        encrypt(plaintextString, keys.wrapKey, {
          protectedHeader: { alg, enc: "UnsupportedEnc" },
        }),
      ).rejects.toThrow(
        "Encryption algorithm ('enc') must be specified in protectedHeader and must be a supported JWE content encryption algorithm. Got: UnsupportedEnc",
      );
    });

    it("should throw for invalid key type", async () => {
      const { alg, enc } = testCombinations[0]!;
      await expect(
        // @ts-expect-error - Testing invalid type
        encrypt(plaintextString, "not-a-key", {
          protectedHeader: { alg, enc },
        }),
      ).rejects.toThrow(/Invalid key type for wrapping/);
      await expect(
        // @ts-expect-error - Testing invalid type
        encrypt(plaintextString, {}, { protectedHeader: { alg, enc } }),
      ).rejects.toThrow(/Invalid key type for wrapping/);
      await expect(
        // @ts-expect-error - Testing invalid type
        encrypt(plaintextString, null, { protectedHeader: { alg, enc } }),
      ).rejects.toThrow(/Invalid key type for wrapping/);
    });

    it("should throw if JWK alg mismatches header alg", async () => {
      const { enc } = testCombinations[0]!; // A128GCM
      const { wrapJwk } = getKeysForAlg("A128KW"); // JWK with alg: A128KW
      await expect(
        encrypt(plaintextString, wrapJwk, {
          protectedHeader: { alg: "A256KW", enc }, // Header requests A256KW
        }),
      ).rejects.toThrow(
        /JWE header algorithm 'A256KW' does not match JWK algorithm 'A128KW'/,
      );
    });

    it("should throw if CryptoKey lacks 'wrapKey' usage", async () => {
      const { alg, enc } = testCombinations[0]!; // A128KW, A128GCM
      const keyNoWrap = await importKey(a128kwJwk, {
        keyUsages: ["unwrapKey"],
      }); // Import without wrapKey usage

      await expect(
        encrypt(plaintextString, keyNoWrap, {
          protectedHeader: { alg, enc },
        }),
      ).rejects.toThrow(
        "Provided CryptoKey for wrapping does not have 'wrapKey' usage.",
      );
    });

    // Note: PBES2 tests are limited as full derivation isn't implemented internally yet.
    // We test the header checks.
    it("should throw for PBES2 alg if p2s is missing", async () => {
      const pbesAlg = "PBES2-HS256+A128KW";
      const enc = "A128GCM";
      // Need a key suitable for AES-KW unwrapping, as PBES2 itself isn't handled
      const dummyKey = await generateKey("A128KW");

      await expect(
        encrypt(plaintextString, dummyKey, {
          protectedHeader: { alg: pbesAlg, enc, p2c: 2048 }, // Missing p2s
        }),
      ).rejects.toThrow(
        /PBES2 algorithms require 'p2s' \(salt\) and 'p2c' \(count\)/,
      );
    });

    it("should throw for PBES2 alg if p2c is missing", async () => {
      const pbesAlg = "PBES2-HS256+A128KW";
      const enc = "A128GCM";
      const dummyKey = await generateKey("A128KW");

      await expect(
        encrypt(plaintextString, dummyKey, {
          protectedHeader: { alg: pbesAlg, enc, p2s: "some-salt" }, // Missing p2c
        }),
      ).rejects.toThrow(
        /PBES2 algorithms require 'p2s' \(salt\) and 'p2c' \(count\)/,
      );
    });

    it("should warn for PBES2 wrapping assuming pre-derived key", async () => {
      const pbesAlg = "PBES2-HS256+A128KW";
      const enc = "A128GCM";
      const dummyKey = await generateKey("A128KW"); // Key suitable for AES-KW
      const warnSpy = vi.spyOn(console, "warn");

      await encrypt(plaintextString, dummyKey, {
        protectedHeader: { alg: pbesAlg, enc, p2s: "some-salt", p2c: 2048 },
      });

      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "PBES2 wrapping assumes the provided key is already derived",
        ),
      );
      warnSpy.mockRestore();
    });
  });

  describe("decrypt", () => {
    let jweMap: Map<string, string>; // Map<alg/enc, jweString>

    beforeAll(async () => {
      jweMap = new Map();
      for (const { alg, enc } of testCombinations) {
        const keys = getKeysForAlg(alg);
        const jwe = await encrypt(plaintextString, keys.wrapKey, {
          protectedHeader: { alg, enc },
        });
        jweMap.set(`${alg}/${enc}`, jwe);
      }
    });

    for (const { alg, enc } of testCombinations) {
      it(`should decrypt ${alg}/${enc} using CryptoKey (default string)`, async () => {
        const keys = getKeysForAlg(alg);
        const jwe = jweMap.get(`${alg}/${enc}`)!;
        const { plaintext, protectedHeader } = await decrypt(
          jwe,
          keys.unwrapKey!,
        );

        expect(protectedHeader.alg).toBe(alg);
        expect(protectedHeader.enc).toBe(enc);
        expect(plaintext).toBe(plaintextString);
      });

      it(`should decrypt ${alg}/${enc} using JWK (request Uint8Array)`, async () => {
        const keys = getKeysForAlg(alg);
        const jwe = jweMap.get(`${alg}/${enc}`)!;
        const { plaintext, protectedHeader } = await decrypt(
          jwe,
          keys.unwrapJwk,
          { toString: false },
        );

        expect(protectedHeader.alg).toBe(alg);
        expect(protectedHeader.enc).toBe(enc);
        expect(plaintext).toBeInstanceOf(Uint8Array);
        expect(plaintext).toEqual(plaintextBytes);
      });
    }

    it("should decrypt using a key retrieval function (JWK)", async () => {
      const { alg, enc } = testCombinations[0]!; // A128KW/A128GCM
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${enc}`)!;

      const keyResolver = async (header: JWEHeaderParameters) => {
        expect(header.alg).toBe(alg);
        expect(header.enc).toBe(enc);
        await new Promise((r) => setTimeout(r, 5)); // Simulate async
        return keys.unwrapJwk;
      };

      const { plaintext } = await decrypt(jwe, keyResolver);
      expect(plaintext).toBe(plaintextString);
    });

    it("should decrypt using a key retrieval function (CryptoKey)", async () => {
      const { alg, enc } = testCombinations[2]!; // RSA-OAEP/A128GCM
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${enc}`)!;

      const keyResolver = async (header: JWEHeaderParameters) => {
        expect(header.alg).toBe(alg);
        expect(header.enc).toBe(enc);
        return keys.unwrapKey!; // Return CryptoKey
      };

      const { plaintext } = await decrypt(jwe, keyResolver, {
        toString: false,
      });
      expect(plaintext).toEqual(plaintextBytes);
    });

    // --- Error Handling ---

    it("should throw for invalid JWE format (too few parts)", async () => {
      const { alg } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      await expect(decrypt("a.b.c.d", keys.unwrapKey)).rejects.toThrow(
        "Invalid JWE format: Must contain five parts separated by dots.",
      );
    });

    it("should throw for invalid JWE format (too many parts)", async () => {
      const { alg } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      await expect(decrypt("a.b.c.d.e.f", keys.unwrapKey)).rejects.toThrow(
        "Invalid JWE format: Must contain five parts separated by dots.",
      );
    });

    it("should throw for invalid header encoding", async () => {
      const { alg, enc } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const parts = jwe.split(".");
      const invalidJwe = `!not-base64.${parts[1]}.${parts[2]}.${parts[3]}.${parts[4]}`;
      await expect(decrypt(invalidJwe, keys.unwrapKey)).rejects.toThrow(
        /Invalid JWE: Failed to decode or parse protected header/,
      );
    });

    it("should throw for invalid header JSON", async () => {
      const { alg, enc } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const parts = jwe.split(".");
      const invalidJsonHeader = base64UrlEncode("{not json");
      const invalidJwe = `${invalidJsonHeader}.${parts[1]}.${parts[2]}.${parts[3]}.${parts[4]}`;
      await expect(decrypt(invalidJwe, keys.unwrapKey)).rejects.toThrow(
        /Invalid JWE: Failed to decode or parse protected header/,
      );
    });

    it("should throw for unsupported alg in header", async () => {
      const { alg, enc } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const parts = jwe.split(".");
      const badHeader = base64UrlEncode(
        JSON.stringify({ alg: "Unsupported", enc }),
      );
      const invalidJwe = `${badHeader}.${parts[1]}.${parts[2]}.${parts[3]}.${parts[4]}`;
      await expect(decrypt(invalidJwe, keys.unwrapKey!)).rejects.toThrow(
        /Unsupported or missing key wrapping algorithm.*Unsupported/,
      );
    });

    it("should throw for missing alg in header", async () => {
      const { alg, enc } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const parts = jwe.split(".");
      const badHeader = base64UrlEncode(JSON.stringify({ enc })); // Missing alg
      const invalidJwe = `${badHeader}.${parts[1]}.${parts[2]}.${parts[3]}.${parts[4]}`;
      await expect(decrypt(invalidJwe, keys.unwrapKey)).rejects.toThrow(
        /Unsupported or missing key wrapping algorithm.*undefined/,
      );
    });

    it("should throw for unsupported enc in header", async () => {
      const { alg } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${testCombinations[0]!.enc}`)!;
      const parts = jwe.split(".");
      const badHeader = base64UrlEncode(
        JSON.stringify({ alg, enc: "Unsupported" }),
      );
      const invalidJwe = `${badHeader}.${parts[1]}.${parts[2]}.${parts[3]}.${parts[4]}`;
      await expect(decrypt(invalidJwe, keys.unwrapKey)).rejects.toThrow(
        /Unsupported or missing content encryption algorithm.*Unsupported/,
      );
    });

    it("should throw for missing enc in header", async () => {
      const { alg } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${testCombinations[0]!.enc}`)!;
      const parts = jwe.split(".");
      const badHeader = base64UrlEncode(JSON.stringify({ alg })); // Missing enc
      const invalidJwe = `${badHeader}.${parts[1]}.${parts[2]}.${parts[3]}.${parts[4]}`;
      await expect(decrypt(invalidJwe, keys.unwrapKey)).rejects.toThrow(
        /Unsupported or missing content encryption algorithm.*undefined/,
      );
    });

    it("should throw if decryption fails (wrong key)", async () => {
      const { alg, enc } = testCombinations[0]!; // A128KW/A128GCM
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const wrongKey = await generateKey("A128KW"); // Generate a different key
      await expect(decrypt(jwe, wrongKey)).rejects.toThrow(
        "The operation failed for an operation-specific reason",
      );

      const { alg: rsaAlg, enc: rsaEnc } = testCombinations[2]!; // RSA-OAEP/A128GCM
      const rsaJwe = jweMap.get(`${rsaAlg}/${rsaEnc}`)!;
      const wrongRsaKey = (await generateKey("RSA-OAEP")).privateKey;
      await expect(decrypt(rsaJwe, wrongRsaKey)).rejects.toThrow(
        "The operation failed for an operation-specific reason",
      );
    });

    it("should throw if decryption fails (tampered ciphertext)", async () => {
      const { alg, enc } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const parts = jwe.split(".");
      const tamperedCipher = parts[3]?.slice(0, -2) + "AF"; // Change last char
      const tamperedJwe = `${parts[0]}.${parts[1]}.${parts[2]}.${tamperedCipher}.${parts[4]}`;
      await expect(decrypt(tamperedJwe, keys.unwrapKey)).rejects.toThrow(
        /JWE decryption failed: Authentication tag mismatch/,
      );
    });

    it("should throw if decryption fails (tampered tag)", async () => {
      const { alg, enc } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const parts = jwe.split(".");
      const tamperedTag = parts[4]?.slice(0, -2) + "AF"; // Change last char
      const tamperedJwe = `${parts[0]}.${parts[1]}.${parts[2]}.${parts[3]}.${tamperedTag}`;
      await expect(decrypt(tamperedJwe, keys.unwrapKey)).rejects.toThrow(
        /JWE decryption failed: Authentication tag mismatch/,
      );
    });

    it("should throw if decryption fails (tampered AAD/header)", async () => {
      const { alg, enc } = testCombinations[0]!;
      const keys = getKeysForAlg(alg);
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const parts = jwe.split(".");
      const tamperedHeader = base64UrlEncode(
        JSON.stringify({ alg, enc, tampered: true }),
      );
      const tamperedJwe = `${tamperedHeader}.${parts[1]}.${parts[2]}.${parts[3]}.${parts[4]}`;
      await expect(decrypt(tamperedJwe, keys.unwrapKey)).rejects.toThrow(
        /JWE decryption failed: Authentication tag mismatch/,
      );
    });

    it("should throw for invalid key type provided directly", async () => {
      const { alg, enc } = testCombinations[0]!;
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      // @ts-expect-error - Testing invalid type
      await expect(decrypt(jwe, "not-a-key")).rejects.toThrow(
        /Invalid key type for unwrapping/,
      );
      // @ts-expect-error - Testing invalid type
      await expect(decrypt(jwe, {})).rejects.toThrow(
        /Invalid key type for unwrapping/,
      );
    });

    it("should throw if JWK alg mismatches header alg", async () => {
      const { alg, enc } = testCombinations[0]!; // A128KW/A128GCM
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const { unwrapJwk } = getKeysForAlg("A256KW"); // JWK with alg: A256KW
      await expect(decrypt(jwe, unwrapJwk)).rejects.toThrow(
        /JWE header algorithm 'A128KW' does not match JWK algorithm 'A256KW'/,
      );
    });

    it("should throw if key retrieval function returns invalid type", async () => {
      const { alg, enc } = testCombinations[0]!;
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const keyResolver = async () => "not-a-key";
      // @ts-expect-error - Testing invalid return
      await expect(decrypt(jwe, keyResolver)).rejects.toThrow(
        /Invalid key type for unwrapping/,
      );
    });

    it("should throw if key retrieval function throws", async () => {
      const { alg, enc } = testCombinations[0]!;
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const errorMsg = "Failed to retrieve key";
      const keyResolver = async () => {
        throw new Error(errorMsg);
      };
      await expect(decrypt(jwe, keyResolver)).rejects.toThrow(errorMsg);
    });

    it("should throw if CryptoKey lacks 'unwrapKey' usage", async () => {
      const { alg, enc } = testCombinations[0]!; // A128KW, A128GCM
      const jwe = jweMap.get(`${alg}/${enc}`)!;
      const keyNoUnwrap = await importKey(a128kwJwk, {
        keyUsages: ["wrapKey"],
      }); // Import without unwrapKey usage

      await expect(decrypt(jwe, keyNoUnwrap)).rejects.toThrow(
        "Provided CryptoKey for unwrapping does not have 'unwrapKey' usage.",
      );
    });

    // Note: PBES2 tests are limited as full derivation isn't implemented internally yet.
    it("should throw for PBES2 alg if p2s is missing in header during unwrap", async () => {
      const pbesAlg = "PBES2-HS256+A128KW";
      const enc = "A128GCM";
      const dummyKey = await generateKey("A128KW"); // Key suitable for AES-KW

      // Construct a fake JWE header missing p2s
      const badHeader = base64UrlEncode(
        JSON.stringify({ alg: pbesAlg, enc, p2c: 2048 }),
      );
      const fakeJwe = `${badHeader}.fake.fake.fake.fake`;

      await expect(decrypt(fakeJwe, dummyKey)).rejects.toThrow(
        /PBES2 algorithms require 'p2s' \(salt\) and 'p2c' \(count\)/,
      );
    });

    it("should throw for PBES2 alg if p2c is missing in header during unwrap", async () => {
      const pbesAlg = "PBES2-HS256+A128KW";
      const enc = "A128GCM";
      const dummyKey = await generateKey("A128KW");

      const badHeader = base64UrlEncode(
        JSON.stringify({ alg: pbesAlg, enc, p2s: "salt" }),
      );
      const fakeJwe = `${badHeader}.fake.fake.fake.fake`;

      await expect(decrypt(fakeJwe, dummyKey)).rejects.toThrow(
        /PBES2 algorithms require 'p2s' \(salt\) and 'p2c' \(count\)/,
      );
    });

    it("should warn for PBES2 unwrapping assuming pre-derived key", async () => {
      const pbesAlg = "PBES2-HS256+A128KW";
      const enc = "A128GCM";
      const dummyKey = await generateKey("A128KW"); // Key suitable for AES-KW

      // Construct a fake JWE with valid PBES2 header but fake encrypted parts
      const header = base64UrlEncode(
        JSON.stringify({ alg: pbesAlg, enc, p2s: "salt", p2c: 2048 }),
      );
      // Need plausible base64 parts even if they won't decrypt correctly
      const fakeEncKey = base64UrlEncode(randomBytes(32));
      const fakeIv = base64UrlEncode(randomBytes(12));
      const fakeCipher = base64UrlEncode(randomBytes(16));
      const fakeTag = base64UrlEncode(randomBytes(16));
      const fakeJwe = `${header}.${fakeEncKey}.${fakeIv}.${fakeCipher}.${fakeTag}`;

      const warnSpy = vi.spyOn(console, "warn");

      // Decryption will likely fail later, but the warning should appear during unwrap attempt
      await expect(decrypt(fakeJwe, dummyKey)).rejects.toThrow();

      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "PBES2 unwrapping assumes the provided key is already derived",
        ),
      );
      warnSpy.mockRestore();
    });
  });
});
