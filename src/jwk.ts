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
  keyUsage?: KeyUsage[];
  /** Mark the key as extractable. Defaults to true. */
  extractable?: boolean;
  /** RSA modulus length. Defaults to 2048. */
  modulusLength?: number;
  /** RSA public exponent. Defaults to 65537 (0x010001). */
  publicExponent?: Uint8Array;
}

interface ImportKeyOptions {
  /** Fallback algorithm identifier if not present in the JWK. */
  alg?: SupportedJwkAlg; // Use the existing comprehensive type
  /** Fallback for key extractability if not present in the JWK. Defaults to false. */
  extractable?: boolean;
  /** Fallback for key usages if not present in the JWK. If still unspecified, defaults will be inferred. */
  keyUsages?: KeyUsage[];
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
    const keyUsage: KeyUsage[] = options.keyUsage || ["sign", "verify"];
    return crypto.subtle.generateKey(keyGenParams, extractable, keyUsage);
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
    const keyUsage: KeyUsage[] = options.keyUsage || ["sign", "verify"];
    return crypto.subtle.generateKey(keyGenParams, extractable, keyUsage);
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
    const keyUsage: KeyUsage[] = options.keyUsage || ["wrapKey", "unwrapKey"];
    return crypto.subtle.generateKey(keyGenParams, extractable, keyUsage);
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
    const keyUsage: KeyUsage[] = options.keyUsage || [
      "wrapKey",
      "unwrapKey",
      "encrypt",
      "decrypt",
    ];
    return crypto.subtle.generateKey(keyGenParams, extractable, keyUsage);
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
      const keyUsage: KeyUsage[] = options.keyUsage || ["encrypt", "decrypt"];
      return crypto.subtle.generateKey(keyGenParams, extractable, keyUsage);
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

      // Ignoring `options.keyUsage` since composite CBC requires different usages
      const aesUsage: KeyUsage[] = ["encrypt", "decrypt"];
      const hmacUsage: KeyUsage[] = ["sign", "verify"];

      const [encryptionKey, macKey] = await Promise.all([
        crypto.subtle.generateKey(aesCbcParams, extractable, aesUsage),
        crypto.subtle.generateKey(hmacParams, extractable, hmacUsage),
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
 * Exports a CryptoKey to its JSON Web Key (JWK) representation.
 *
 * Note: The CryptoKey must have been created with the `extractable`
 * property set to `true`.
 *
 * @param key The CryptoKey to export.
 * @returns A Promise resolving to the JsonWebKey object.
 * @throws Error if the key is not extractable or another export error occurs.
 */
export async function exportKey(key: CryptoKey): Promise<JsonWebKey> {
  if (!key.extractable) {
    throw new Error("Cannot export a non-extractable key.");
  }

  const jwk = await crypto.subtle.exportKey("jwk", key);
  return jwk;
}

/**
 * Imports a JSON Web Key (JWK) into a CryptoKey object.
 *
 * It prioritizes metadata within the JWK (`alg`, `ext`, `key_ops`).
 * Fallbacks can be provided via the options object.
 * Default key usages are inferred based on the algorithm and key type if not specified.
 *
 * @param jwk The JsonWebKey object to import.
 * @param options Optional fallbacks for algorithm, extractability, and key usages.
 * @returns A Promise resolving to the imported CryptoKey.
 * @throws Error if the algorithm cannot be determined or is unsupported,
 *         or if key usages cannot be determined, or if import fails.
 */
export async function importKey(
  jwk: JsonWebKey,
  options: ImportKeyOptions = {},
): Promise<CryptoKey> {
  // 1. Determine Informations
  const alg = jwk.alg ?? options.alg;
  if (!alg) {
    // Attempt basic inference for common types if alg is missing
    if (jwk.kty === "oct" && jwk.k) {
      // Cannot reliably infer specific AES/HMAC without alg or key size context
      throw new Error(
        "Algorithm ('alg') missing in JWK and options, cannot infer for 'oct' key type.",
      );
    } else if (jwk.kty === "RSA" && jwk.n && jwk.e) {
      // Cannot reliably infer RS*/PS*/RSA-OAEP without alg
      throw new Error(
        "Algorithm ('alg') missing in JWK and options, cannot infer specific RSA algorithm.",
      );
    }
    throw new Error("Algorithm ('alg') must be present in JWK or options.");
  }
  const extractable = jwk.ext ?? options.extractable ?? false; // TODO: do we want to keep the default as `false`?

  let algorithm:
    | AlgorithmIdentifier
    | RsaHashedImportParams
    | HmacImportParams
    | AesKeyAlgorithm;
  let defaultUsages: KeyUsage[] = [];

  if (alg in JWS_ALGORITHMS_SYMMETRIC) {
    const algDetails =
      JWS_ALGORITHMS_SYMMETRIC[alg as keyof typeof JWS_ALGORITHMS_SYMMETRIC];
    algorithm = {
      name: algDetails.name,
      hash: algDetails.hash,
    } as HmacImportParams;
    defaultUsages = ["sign", "verify"];
  } else if (alg in JWS_ALGORITHMS_ASYMMETRIC_RSA) {
    const algDetails =
      JWS_ALGORITHMS_ASYMMETRIC_RSA[
        alg as keyof typeof JWS_ALGORITHMS_ASYMMETRIC_RSA
      ];
    algorithm = {
      name: algDetails.name,
      hash: algDetails.hash,
    } as RsaHashedImportParams;
    // Default usages depend on whether it's a public or private key
    defaultUsages = jwk.d ? ["sign"] : ["verify"]; // Check for private exponent 'd'
  } else if (alg in JWE_KEY_WRAPPING_PBES2) {
    // JWK for AES-KW should have kty: "oct"
    // The 'alg' here informs the *intended use* and expected key length,
    // but the Web Crypto import name is "AES-KW".
    if (jwk.kty !== "oct")
      throw new Error(`JWK with alg '${alg}' must have kty 'oct'.`);
    algorithm = { name: "AES-KW" };
    defaultUsages = ["wrapKey", "unwrapKey"];
  } else if (alg in JWE_KEY_WRAPPING_RSA) {
    const algDetails =
      JWE_KEY_WRAPPING_RSA[alg as keyof typeof JWE_KEY_WRAPPING_RSA];
    algorithm = {
      name: algDetails.name,
      hash: algDetails.hash,
    } as RsaHashedImportParams;
    // Default usages depend on public/private key
    defaultUsages = jwk.d ? ["unwrapKey", "decrypt"] : ["wrapKey", "encrypt"];
  } else if (alg in JWE_CONTENT_ENCRYPTION_ALGORITHMS) {
    const algDetails =
      JWE_CONTENT_ENCRYPTION_ALGORITHMS[
        alg as keyof typeof JWE_CONTENT_ENCRYPTION_ALGORITHMS
      ];
    if (jwk.kty !== "oct")
      throw new Error(`JWK with alg '${alg}' must have kty 'oct'.`);

    if (algDetails.type === "gcm") {
      algorithm = { name: "AES-GCM" };
      defaultUsages = ["encrypt", "decrypt"];
    } else if (algDetails.type === "cbc") {
      // This imports *either* the AES-CBC part *or* the HMAC part,
      // depending on what the specific JWK represents.
      // We need to differentiate based on the 'alg' or potentially key size if alg is ambiguous.
      // Assuming the JWK 'alg' correctly identifies the key's direct purpose:
      if (alg.startsWith("A") && alg.includes("CBC")) {
        // e.g., A128CBC-HS256 used for the AES key
        algorithm = { name: "AES-CBC" };
        defaultUsages = ["encrypt", "decrypt"];
      } else if (alg.startsWith("HS")) {
        // e.g., HS256 used for the HMAC key
        // Need to find the corresponding HMAC details
        const hmacAlg = alg as keyof typeof JWS_ALGORITHMS_SYMMETRIC;
        if (!(hmacAlg in JWS_ALGORITHMS_SYMMETRIC)) {
          throw new Error(
            `Cannot determine HMAC parameters for MAC key with alg '${alg}'.`,
          );
        }
        const hmacDetails = JWS_ALGORITHMS_SYMMETRIC[hmacAlg];
        algorithm = {
          name: hmacDetails.name,
          hash: hmacDetails.hash,
        } as HmacImportParams;
        defaultUsages = ["sign", "verify"];
      } else {
        // If alg is like "A128CBC-HS256", we need more info to know which key this JWK is.
        // TODO: study a solution to inspect key length if 'alg' is composite.
        throw new Error(
          `Ambiguous or unsupported 'alg' ('${alg}') for importing a component of a composite CBC key.`,
        );
      }
    } else {
      throw new Error(
        `Unsupported JWE content encryption algorithm type: ${(algDetails as any).type}`,
      );
    }
  } else {
    throw new Error(`Unsupported or unknown algorithm for key import: ${alg}`);
  }

  // 2. Determine Key Usages
  const keyUsages: KeyUsage[] =
    (jwk.key_ops as KeyUsage[] | undefined) ??
    options.keyUsages ??
    defaultUsages;
  if (!keyUsages || keyUsages.length === 0) {
    // Try inferring from jwk.use as a last resort
    if (jwk.use === "sig") {
      if (algorithm.name.startsWith("RSA") || algorithm.name === "HMAC") {
        // Infer sign/verify based on private/public
        Object.assign(keyUsages, jwk.d ? ["sign"] : ["verify"]);
      }
    } else if (
      jwk.use === "enc" &&
      (algorithm.name.startsWith("RSA") || algorithm.name.startsWith("AES"))
    ) {
      // Infer encrypt/decrypt or wrap/unwrap based on private/public/algorithm
      switch (algorithm.name) {
        case "AES-KW": {
          Object.assign(keyUsages, ["wrapKey", "unwrapKey"]);
          break;
        }
        case "AES-GCM":
        case "AES-CBC": {
          Object.assign(keyUsages, ["encrypt", "decrypt"]);
          break;
        }
        case "RSA-OAEP": {
          Object.assign(
            keyUsages,
            jwk.d ? ["unwrapKey", "decrypt"] : ["wrapKey", "encrypt"],
          );
          break;
        }
        // No default
      }
    }

    // If still no usages, throw error as importKey requires it.
    if (!keyUsages || keyUsages.length === 0) {
      throw new Error(
        `Key usages ('key_ops') could not be determined from JWK, options, or defaults for algorithm '${alg}'.`,
      );
    }
  }

  // 3. Perform Import
  try {
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      algorithm,
      extractable,
      keyUsages,
    );
    return cryptoKey;
  } catch (error) {
    console.error("Key import failed. Details:", {
      jwk,
      algorithm,
      extractable,
      keyUsages,
    });
    throw new Error(
      `Failed to import key: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
