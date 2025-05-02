import type { JWK } from "./types";
import { JOSE_ALGORITHMS } from "./utils/defaults";
import { base64UrlEncode, textEncoder, randomBytes } from "./utils";

import {
  JWS_ALGORITHMS_SYMMETRIC,
  JWS_ALGORITHMS_ASYMMETRIC_RSA,
  JWE_KEY_WRAPPING_PBES2,
  JWE_KEY_WRAPPING_RSA,
  JWE_CONTENT_ENCRYPTION_ALGORITHMS,
} from "./utils/defaults";

// --- Define specific algorithm types ---
type SupportedHmacAlg = keyof typeof JWS_ALGORITHMS_SYMMETRIC;
// AES-KW keys derived from PBES2 alg identifiers
type SupportedAesKwAlg = keyof typeof JWE_KEY_WRAPPING_PBES2;
// Filter GCM algorithms from JWE_CONTENT_ENCRYPTION_ALGORITHMS
type SupportedAesGcmAlg = {
  [K in keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS]: (typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS)[K]["type"] extends "gcm"
    ? K
    : never;
}[keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS];
// Filter CBC algorithms from JWE_CONTENT_ENCRYPTION_ALGORITHMS
type SupportedCbcAlg = {
  [K in keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS]: (typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS)[K]["type"] extends "cbc"
    ? K
    : never;
}[keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS];

type SupportedRsaSignAlg = keyof typeof JWS_ALGORITHMS_ASYMMETRIC_RSA;
type SupportedRsaWrapAlg = keyof typeof JWE_KEY_WRAPPING_RSA;

// --- Define composite types for overloads ---
// Algorithms returning a single symmetric CryptoKey
type SupportedSymSingleKeyAlg =
  | SupportedHmacAlg
  | SupportedAesKwAlg
  | SupportedAesGcmAlg;
// Algorithms returning an asymmetric CryptoKeyPair
type SupportedAsymKeyPairAlg = SupportedRsaSignAlg | SupportedRsaWrapAlg;
// All supported algorithms
type SupportedJwkAlg =
  | SupportedSymSingleKeyAlg
  | SupportedAsymKeyPairAlg
  | SupportedCbcAlg;

// --- Define return type for composite CBC keys ---
export type CompositeKey = {
  /** The AES-CBC encryption/decryption key. */
  encryptionKey: CryptoKey;
  /** The HMAC key for integrity/authentication. */
  macKey: CryptoKey;
};

interface GenerateKeyOptions {
  /** Key usages for the generated key. */
  keyUsages?: KeyUsage[];
  /** Mark the key as extractable. Defaults to true. */
  extractable?: boolean;
  /** RSA modulus length. Defaults to 2048. */
  modulusLength?: number;
  /** RSA public exponent. Defaults to 65537 (0x010001). */
  publicExponent?: Uint8Array;
}

/**
 * Generates composite keys (AES-CBC + HMAC) suitable for the specified JWE CBC algorithm.
 *
 * @param alg The JWE CBC algorithm identifier (e.g., "A128CBC-HS256").
 * @param options Optional parameters for key generation.
 * @returns A Promise resolving to an object containing the encryptionKey and macKey.
 * @throws Error if the algorithm is not supported.
 */
export async function generateKey(
  alg: SupportedCbcAlg,
  options?: GenerateKeyOptions, // Make options optional
): Promise<CompositeKey>;
/**
 * Generates a symmetric cryptographic key suitable for the specified JOSE algorithm.
 *
 * @param alg The JOSE algorithm identifier (HMAC, AES-KW, AES-GCM).
 * @param options Optional parameters for key generation.
 * @returns A Promise resolving to the generated CryptoKey.
 * @throws Error if the algorithm is not supported.
 */
export async function generateKey(
  alg: SupportedSymSingleKeyAlg,
  options?: GenerateKeyOptions, // Make options optional
): Promise<CryptoKey>;
/**
 * Generates an asymmetric cryptographic key pair suitable for the specified JOSE algorithm.
 *
 * @param alg The JOSE algorithm identifier (RSA-Sign, RSA-Wrap).
 * @param options Optional parameters for key generation.
 * @returns A Promise resolving to the generated CryptoKeyPair.
 * @throws Error if the algorithm is not supported.
 */
export async function generateKey(
  alg: SupportedAsymKeyPairAlg,
  options?: GenerateKeyOptions, // Make options optional
): Promise<CryptoKeyPair>;
export async function generateKey(
  alg: SupportedJwkAlg,
  options: GenerateKeyOptions = {},
): Promise<CryptoKey | CryptoKeyPair | CompositeKey> {
  const {
    extractable = true,
    modulusLength = 2048,
    publicExponent = new Uint8Array([0x01, 0x00, 0x01]),
  } = options;

  // JWS Symmetric (HMAC)
  if (alg in JWS_ALGORITHMS_SYMMETRIC) {
    const algDetails =
      JWS_ALGORITHMS_SYMMETRIC[alg as keyof typeof JWS_ALGORITHMS_SYMMETRIC];
    const keyGenParams: HmacKeyGenParams = {
      name: algDetails.name, // "HMAC"
      hash: algDetails.hash,
    };
    const keyUsages: KeyUsage[] = options.keyUsages || ["sign", "verify"];
    return crypto.subtle.generateKey(keyGenParams, extractable, keyUsages);
  }

  // JWS Asymmetric (RSA)
  if (alg in JWS_ALGORITHMS_ASYMMETRIC_RSA) {
    const algDetails =
      JWS_ALGORITHMS_ASYMMETRIC_RSA[
        alg as keyof typeof JWS_ALGORITHMS_ASYMMETRIC_RSA
      ];
    const keyGenParams: RsaHashedKeyGenParams = {
      name: algDetails.name, // "RSASSA-PKCS1-v1_5" or "RSASSA-PSS"
      hash: algDetails.hash,
      modulusLength: modulusLength,
      publicExponent: publicExponent,
    };
    const keyUsages: KeyUsage[] = options.keyUsages || ["sign", "verify"];
    return crypto.subtle.generateKey(keyGenParams, extractable, keyUsages);
  }

  // JWE Key Wrapping (PBES2 -> AES-KW)
  // Note: This generates the AES-KW key, not the PBES2 derived key itself.
  if (alg in JWE_KEY_WRAPPING_PBES2) {
    const algDetails =
      JWE_KEY_WRAPPING_PBES2[alg as keyof typeof JWE_KEY_WRAPPING_PBES2];
    const keyGenParams: AesKeyGenParams = {
      name: "AES-KW",
      length: algDetails.keyLength,
    };
    const keyUsages: KeyUsage[] = options.keyUsages || ["wrapKey", "unwrapKey"];
    return crypto.subtle.generateKey(keyGenParams, extractable, keyUsages);
  }

  // JWE Key Wrapping (RSA-OAEP)
  if (alg in JWE_KEY_WRAPPING_RSA) {
    const algDetails =
      JWE_KEY_WRAPPING_RSA[alg as keyof typeof JWE_KEY_WRAPPING_RSA];
    const keyGenParams: RsaHashedKeyGenParams = {
      name: algDetails.name, // "RSA-OAEP"
      hash: algDetails.hash,
      modulusLength: modulusLength,
      publicExponent: publicExponent,
    };
    const keyUsages: KeyUsage[] = options.keyUsages || [
      "wrapKey",
      "unwrapKey",
      "encrypt",
      "decrypt",
    ];
    return crypto.subtle.generateKey(keyGenParams, extractable, keyUsages);
  }

  // JWE Content Encryption (AES-GCM / AES-CBC)
  if (alg in JWE_CONTENT_ENCRYPTION_ALGORITHMS) {
    const algDetails =
      JWE_CONTENT_ENCRYPTION_ALGORITHMS[
        alg as keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS
      ];
    let keyGenParams: AesKeyGenParams;
    if (algDetails.type === "gcm") {
      // --- Generate AES-GCM Key ---
      keyGenParams = {
        name: "AES-GCM",
        length: algDetails.keyLength,
      };
      const keyUsages: KeyUsage[] = options.keyUsages || ["encrypt", "decrypt"];
      return crypto.subtle.generateKey(keyGenParams, extractable, keyUsages);
    } else if (algDetails.type === "cbc") {
      // --- Generate Composite Keys for CBC ---
      const aesCbcParams: AesKeyGenParams = {
        name: "AES-CBC",
        length: algDetails.encKeyLength,
      };
      const hmacParams: HmacKeyGenParams = {
        name: "HMAC",
        hash: algDetails.macAlgorithm,
        length: algDetails.macKeyLength,
      };

      // Ignoring `options.keyUsages` since composite CBC requires different usages
      const aesUsages: KeyUsage[] = ["encrypt", "decrypt"];
      const hmacUsages: KeyUsage[] = ["sign", "verify"];

      const [encryptionKey, macKey] = await Promise.all([
        crypto.subtle.generateKey(aesCbcParams, extractable, aesUsages),
        crypto.subtle.generateKey(hmacParams, extractable, hmacUsages),
      ]);

      // Ensure both keys are CryptoKey objects
      if (
        !(encryptionKey instanceof CryptoKey) ||
        !(macKey instanceof CryptoKey)
      ) {
        throw new TypeError(
          "Internal error: Failed to generate composite keys correctly.",
        );
      }

      return { encryptionKey, macKey };
    }
  }

  throw new Error(
    `Unsupported or unknown algorithm for key generation: ${alg}`,
  );
}

/**
 * Exports a CryptoKey to its JWK representation.
 * Supports symmetric ('oct') keys. Future versions will support asymmetric keys.
 *
 * @param key The CryptoKey to export. Must be extractable.
 *
 * @returns Promise resolving to the JWK representation.
 * @throws Error if the key is not extractable or its type is unsupported for export.
 */
export async function exportKey(key: Readonly<CryptoKey>): Promise<JWK> {
  if (!key.extractable) {
    throw new Error("Key must be extractable to export to JWK format.");
  }

  if (key.type === "secret") {
    try {
      // Prefer standard 'jwk' export if available
      const jwk = await crypto.subtle.exportKey("jwk", key);

      if (jwk.kty === "oct" && typeof jwk.k === "string") {
        const finalJwk: JWK = {
          ...jwk,
          kty: "oct",
          key_ops: jwk.key_ops || key.usages,
          ext: jwk.ext ?? key.extractable,
        };

        // Infer 'alg' if missing
        if (!finalJwk.alg && (key.algorithm as any).name === "HMAC") {
          finalJwk.alg = `HS${(key.algorithm as HmacKeyAlgorithm).hash.name.split("-")[1]}`;
        } else if (!finalJwk.alg) {
          finalJwk.alg = (key.algorithm as any).name; // Fallback to algorithm name
        }
        return finalJwk;
      }
    } catch {
      // Ignore error and fall through to manual 'raw' export if 'jwk' format failed
    }

    // Manual construction using 'raw' export (fallback)
    const rawKey = await crypto.subtle.exportKey("raw", key);
    const jwk: JWK = {
      kty: "oct",
      k: base64UrlEncode(new Uint8Array(rawKey)),
      // Infer JWA algorithm name
      alg:
        (key.algorithm as any).name === "HMAC"
          ? `HS${(key.algorithm as HmacKeyAlgorithm).hash.name.split("-")[1]}`
          : (key.algorithm as any).name, // Use algorithm name directly (e.g., AES-KW)
      key_ops: key.usages,
      ext: key.extractable,
    };
    return jwk;
  } else if (key.type === "public" || key.type === "private") {
    // TODO: Implement asymmetric key export (RSA, EC)
    // This will likely involve exporting as 'jwk' directly,
    // as 'raw'/'pkcs8'/'spki' don't map directly to all JWK fields.
    try {
      const jwk = await crypto.subtle.exportKey("jwk", key);
      // TODO: Validate the structure based on expected kty (RSA/EC)
      // and return the JWK object (potentially casting/adjusting fields).
      // For private keys, this will contain private parameters (d, p, q, etc.).
      // For public keys, it will contain only public parameters (n, e for RSA; x, y for EC).
      return jwk as JWK; // Placeholder cast
    } catch (error) {
      throw new Error(`Failed to export asymmetric key to JWK: ${error}`);
    }
  } else {
    throw new Error(`Unsupported CryptoKey type for export: ${key.type}`);
  }
}

/**
 * Imports a symmetric key from various formats (JWK, raw bytes, string) into a CryptoKey.
 *
 * @param key The key material (JWK object, Uint8Array, or string).
 * @param algorithm The Web Crypto AlgorithmIdentifier to import the key for (e.g., HmacImportParams, AesKeyAlgorithm).
 * @param extractable Whether the imported key should be extractable.
 * @param keyUsages The allowed key usages for the imported CryptoKey.
 *
 * @returns Promise resolving to the imported CryptoKey.
 * @throws Error if the key format is invalid or unsupported for symmetric import.
 */
export async function importKey(
  key: JWK | string | Uint8Array,
  algorithm: AlgorithmIdentifier | HmacImportParams | AesKeyAlgorithm,
  extractable: boolean,
  keyUsages: KeyUsage[],
): Promise<CryptoKey> {
  if (typeof key === "string") {
    // Raw string secret
    const keyData = textEncoder.encode(key);
    return crypto.subtle.importKey(
      "raw",
      keyData,
      algorithm,
      extractable,
      keyUsages,
    );
  } else if (key instanceof Uint8Array) {
    // Raw byte secret
    const keyData = key;
    return crypto.subtle.importKey(
      "raw",
      keyData,
      algorithm,
      extractable,
      keyUsages,
    );
  } else if (typeof key === "object" && key !== null && key.kty === "oct") {
    // Symmetric JWK
    if (typeof key.k !== "string") {
      throw new TypeError(
        "Symmetric JWK must contain the 'k' parameter as a string",
      );
    }

    // The subtle.importKey API handles the base64url decoding internally for "jwk" format.
    const keyData = key as JsonWebKey; // Cast to Web Crypto's expected JsonWebKey type

    // Ensure required JWK properties for import are present if needed by the algorithm
    // (though subtle.importKey often infers or ignores some like alg, key_ops, ext)
    // TODO: I might add more checks here depending on strictness we want to achieve.

    return crypto.subtle.importKey(
      "jwk",
      keyData,
      algorithm,
      extractable,
      keyUsages,
    );
  } else {
    throw new Error(
      "Invalid key format. Expected symmetric JWK (oct), Uint8Array, or string.",
    );
  }
}
