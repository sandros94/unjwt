import {
  JWS_ALGORITHMS_SYMMETRIC,
  JWS_ALGORITHMS_ASYMMETRIC_RSA,
  JWE_KEY_WRAPPING_HMAC,
  JWE_KEY_WRAPPING_RSA,
  JWE_CONTENT_ENCRYPTION_ALGORITHMS,
} from "./utils/defaults";
import { randomBytes, textEncoder } from "./utils";

import type {
  HmacAlgorithm,
  HmacWrapAlgorithm,
  AesCbcAlgorithm,
  ContentEncryptionAlgorithm,
  RsaSignAlgorithm,
  RsaWrapAlgorithm,
  JoseKeyPairAlgorithm,
} from "./types/defaults";
import type {
  CompositeKey,
  GenerateKeyOptions,
  ImportKeyOptions,
  DeriveKeyBitsOptions,
  DerivedKeyBitsResult,
  GenerateJoseAlgorithm,
  GenerateHmacWrapAlgorithm,
  JWK,
} from "./types/jwk";

export * from './types/defaults'
export * from './types/jwk'

/**
 * Generates composite keys (AES-CBC + HMAC) suitable for the specified JWE CBC algorithm.
 *
 * @param alg The JWE CBC algorithm identifier (e.g., "A128CBC-HS256").
 * @param options Optional parameters for key generation.
 * @returns A Promise resolving to an object containing the encryptionKey and macKey.
 * @throws Error if the algorithm is not supported.
 */
export async function generateKey<
  ToJWK extends boolean | undefined = undefined,
>(
  alg: AesCbcAlgorithm,
  options?: GenerateKeyOptions<ToJWK>,
): Promise<ToJWK extends true ? JWK : CompositeKey>;
export async function generateKey(
  alg: AesCbcAlgorithm,
  options: GenerateKeyOptions & {
    toJWK: true;
  },
): Promise<{ encryptionKey: JWK; macKey: JWK }>;
/**
 * Generates a symmetric cryptographic key suitable for the specified JOSE algorithm.
 *
 * @param alg The JOSE algorithm identifier (HMAC, AES-KW, AES-GCM).
 * @param options Optional parameters for key generation.
 * @returns A Promise resolving to the generated CryptoKey.
 * @throws Error if the algorithm is not supported.
 */
export async function generateKey<
  ToJWK extends boolean | undefined = undefined,
>(
  alg: GenerateHmacWrapAlgorithm,
  options?: GenerateKeyOptions<ToJWK>,
): Promise<ToJWK extends true ? JWK : CryptoKey>;
/**
 * Generates an asymmetric cryptographic key pair suitable for the specified JOSE algorithm.
 *
 * @param alg The JOSE algorithm identifier (RSA-Sign, RSA-Wrap).
 * @param options Optional parameters for key generation.
 * @returns A Promise resolving to the generated CryptoKeyPair.
 * @throws Error if the algorithm is not supported.
 */
export async function generateKey<
  ToJWK extends boolean | undefined = undefined,
>(
  alg: JoseKeyPairAlgorithm,
  options?: GenerateKeyOptions<ToJWK>,
): Promise<ToJWK extends true ? JWK : CryptoKeyPair>;
export async function generateKey(
  alg: JoseKeyPairAlgorithm,
  options?: GenerateKeyOptions & {
    toJWK: true;
  },
): Promise<{ publicKey: JWK; privateKey: JWK }>;
export async function generateKey(
  alg: GenerateJoseAlgorithm,
  options: GenerateKeyOptions = {},
): Promise<
  | JWK
  | (CryptoKey | CryptoKeyPair | CompositeKey)
  | { encryptionKey: JWK; macKey: JWK }
  | { publicKey: JWK; privateKey: JWK }
> {
  const {
    extractable = true,
    modulusLength = 2048,
    publicExponent = new Uint8Array([0x01, 0x00, 0x01]),
  } = options;

  // JWS Symmetric (HMAC)
  if (alg in JWS_ALGORITHMS_SYMMETRIC) {
    const algDetails = JWS_ALGORITHMS_SYMMETRIC[alg as HmacAlgorithm];
    const keyGenParams: HmacKeyGenParams = {
      name: algDetails.name, // "HMAC"
      hash: algDetails.hash,
    };
    const keyUsage: KeyUsage[] = options.keyUsage || ["sign", "verify"];
    const cryptoKey = await crypto.subtle.generateKey(
      keyGenParams,
      extractable,
      keyUsage,
    );

    return options.toJWK ? await exportKey(cryptoKey) : cryptoKey;
  }

  // JWS Asymmetric (RSA)
  if (alg in JWS_ALGORITHMS_ASYMMETRIC_RSA) {
    const algDetails = JWS_ALGORITHMS_ASYMMETRIC_RSA[alg as RsaSignAlgorithm];
    const keyGenParams: RsaHashedKeyGenParams = {
      name: algDetails.name, // "RSASSA-PKCS1-v1_5" or "RSASSA-PSS"
      hash: algDetails.hash,
      modulusLength: modulusLength,
      publicExponent: publicExponent,
    };
    const keyUsage: KeyUsage[] = options.keyUsage || ["sign", "verify"];
    const cryptoKey = await crypto.subtle.generateKey(
      keyGenParams,
      extractable,
      keyUsage,
    );

    return options.toJWK
      ? {
          publicKey: await exportKey(cryptoKey.publicKey),
          privateKey: await exportKey(cryptoKey.privateKey),
        }
      : cryptoKey;
  }

  // JWE Key Wrapping (PBES2 -> AES-KW)
  // Note: This generates the AES-KW key, not the PBES2 derived key itself.
  if (alg in JWE_KEY_WRAPPING_HMAC) {
    const algDetails = JWE_KEY_WRAPPING_HMAC[alg as HmacWrapAlgorithm];
    const keyGenParams: AesKeyGenParams = {
      name: "AES-KW",
      length: algDetails.keyLength,
    };
    const keyUsage: KeyUsage[] = options.keyUsage || ["wrapKey", "unwrapKey"];
    const cryptoKey = await crypto.subtle.generateKey(
      keyGenParams,
      extractable,
      keyUsage,
    );

    return options.toJWK ? await exportKey(cryptoKey) : cryptoKey;
  }

  // JWE Key Wrapping (RSA-OAEP)
  if (alg in JWE_KEY_WRAPPING_RSA) {
    const algDetails = JWE_KEY_WRAPPING_RSA[alg as RsaWrapAlgorithm];
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
    const cryptoKey = await crypto.subtle.generateKey(
      keyGenParams,
      extractable,
      keyUsage,
    );

    return options.toJWK
      ? {
          publicKey: await exportKey(cryptoKey.publicKey),
          privateKey: await exportKey(cryptoKey.privateKey),
        }
      : cryptoKey;
  }

  // JWE Content Encryption (AES-GCM / AES-CBC)
  if (alg in JWE_CONTENT_ENCRYPTION_ALGORITHMS) {
    const algDetails =
      JWE_CONTENT_ENCRYPTION_ALGORITHMS[alg as ContentEncryptionAlgorithm];
    let keyGenParams: AesKeyGenParams;
    if (algDetails.type === "gcm") {
      // --- Generate AES-GCM Key ---
      keyGenParams = {
        name: "AES-GCM",
        length: algDetails.keyLength,
      };
      const keyUsage: KeyUsage[] = options.keyUsage || ["encrypt", "decrypt"];
      const cryptoKey = await crypto.subtle.generateKey(
        keyGenParams,
        extractable,
        keyUsage,
      );

      return options.toJWK ? await exportKey(cryptoKey) : cryptoKey;
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

      return options.toJWK
        ? {
            encryptionKey: await exportKey(encryptionKey),
            macKey: await exportKey(macKey),
          }
        : {
            encryptionKey,
            macKey,
          };
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
 * @param jwk Optional JWK object to merge with the exported key.
 * @returns A Promise resolving to the JsonWebKey object.
 * @throws Error if the key is not extractable or another export error occurs.
 */
export async function exportKey(
  key: CryptoKey,
  jwk?: Partial<JWK>,
): Promise<JWK> {
  if (!key.extractable) {
    throw new Error("Cannot export a non-extractable key.");
  }

  const exportedJwk = await crypto.subtle.exportKey("jwk", key);
  return {
    ...exportedJwk,
    ...jwk,
    key_ops: jwk?.key_ops ?? exportedJwk.key_ops,
    ext: jwk?.ext ?? exportedJwk.ext,
  } as JWK;
}

/**
 * Imports a cryptographic key from either its JSON Web Key (JWK) representation
 * or from raw key bits (ArrayBuffer/Uint8Array).
 *
 * When importing raw key bits (e.g., derived from a password using
 * `deriveKeyBitsFromPassword`), the `alg` and `keyUsages` must be specified
 * in the `options` parameter to define the key's intended algorithm and
 * allowed operations.
 *
 * When importing a JWK, the function attempts to infer the algorithm and
 * key usages from the JWK properties (`alg`, `use`, `key_ops`) if not
 * explicitly provided in the `options`.
 *
 * @param keyData The key data, either as a JsonWebKey object or an ArrayBuffer/Uint8Array containing raw key bits.
 * @param options Optional parameters for key import. Required when importing raw key bits.
 * @param options.alg The algorithm identifier (e.g., "HS256", "RSA-OAEP", "A256GCM"). Mandatory if not present in the JWK or when importing raw bits.
 * @param options.keyUsages An array of key usage strings (e.g., ["sign", "verify"], ["encrypt", "decrypt"]). Mandatory if not present in the JWK or when importing raw bits.
 * @param options.extractable A boolean indicating whether the imported key should be extractable. Defaults to `true`.
 * @returns A Promise resolving to the imported CryptoKey.
 * @throws Error if required information (like `alg` or `keyUsages` for raw import) is missing or if the algorithm/key type combination is unsupported.
 */
export async function importKey(
  keyData: ArrayBuffer | Uint8Array,
  options?: ImportKeyOptions,
): Promise<CryptoKey>;
export async function importKey(
  keyData: JsonWebKey,
  options?: ImportKeyOptions,
): Promise<CryptoKey>;
export async function importKey(
  keyData: JsonWebKey | ArrayBuffer | Uint8Array,
  options: ImportKeyOptions = {},
): Promise<CryptoKey> {
  // --- Handle Password or Raw Key Bits Import ---
  if (keyData instanceof ArrayBuffer || keyData instanceof Uint8Array) {
    const { alg, keyUsages, extractable = true } = options;
    if (!alg) {
      throw new Error(
        "Algorithm ('alg') must be specified in options when importing raw key bits.",
      );
    }
    if (!keyUsages || keyUsages.length === 0) {
      throw new Error(
        "Key usages ('keyUsages') must be specified in options when importing raw key bits.",
      );
    }

    let algorithm:
      | AlgorithmIdentifier
      | RsaHashedImportParams
      | HmacImportParams
      | AesKeyAlgorithm;

    // Determine algorithm parameters based on the provided 'alg'
    if (alg in JWS_ALGORITHMS_SYMMETRIC) {
      const algDetails = JWS_ALGORITHMS_SYMMETRIC[alg as HmacAlgorithm];
      algorithm = {
        name: algDetails.name,
        hash: algDetails.hash,
      } as HmacImportParams;
    } else if (alg in JWE_KEY_WRAPPING_HMAC) {
      // PBES2 itself isn't imported directly, treating as AES-KW key
      const algDetails = JWE_KEY_WRAPPING_HMAC[alg as HmacWrapAlgorithm];
      algorithm =
        "hash" in algDetails
          ? { name: "AES-KW", hash: algDetails.hash }
          : { name: "AES-KW" };
    } else if (alg in JWE_CONTENT_ENCRYPTION_ALGORITHMS) {
      const algDetails =
        JWE_CONTENT_ENCRYPTION_ALGORITHMS[alg as ContentEncryptionAlgorithm];
      if (algDetails.type === "gcm") {
        algorithm = { name: "AES-GCM" };
      } else if (algDetails.type === "cbc") {
        algorithm = { name: "AES-CBC" };
      } else {
        /* v8 ignore next 2 */
        throw new Error(
          `Unsupported JWE content encryption algorithm type for raw import: ${(algDetails as any).type}`,
        );
      }
    } else {
      // Note: Asymmetric keys (RSA) cannot typically be imported
      // from raw bits directly. JWK format is preferred for them.
      throw new Error(
        `Unsupported or unsuitable algorithm for raw key import: ${alg}`,
      );
    }

    return crypto.subtle.importKey(
      "raw",
      keyData,
      algorithm,
      extractable,
      keyUsages,
    );
  }

  // --- Existing JWK Import Logic ---
  const jwk = keyData;

  // 1. Determine Informations
  const alg = options.alg ?? jwk.alg;
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
  const extractable = options.extractable ?? jwk.ext ?? true;

  let algorithm:
    | AlgorithmIdentifier
    | RsaHashedImportParams
    | HmacImportParams
    | AesKeyAlgorithm;
  let defaultUsages: KeyUsage[] = [];

  if (alg in JWS_ALGORITHMS_SYMMETRIC) {
    const algDetails = JWS_ALGORITHMS_SYMMETRIC[alg as HmacAlgorithm];
    algorithm = {
      name: algDetails.name,
      hash: algDetails.hash,
    } as HmacImportParams;
    defaultUsages = ["sign", "verify"];
  } else if (alg in JWS_ALGORITHMS_ASYMMETRIC_RSA) {
    const algDetails = JWS_ALGORITHMS_ASYMMETRIC_RSA[alg as RsaSignAlgorithm];
    algorithm = {
      name: algDetails.name,
      hash: algDetails.hash,
    } as RsaHashedImportParams;
    defaultUsages = jwk.d ? ["sign"] : ["verify"];
  } else if (alg in JWE_KEY_WRAPPING_HMAC) {
    if (jwk.kty !== "oct")
      throw new Error(`JWK with alg '${alg}' must have kty 'oct'.`);
    const algDetails = JWE_KEY_WRAPPING_HMAC[alg as HmacWrapAlgorithm];
    algorithm =
      "hash" in algDetails
        ? { name: "AES-KW", hash: algDetails.hash }
        : { name: "AES-KW" };
    defaultUsages = ["wrapKey", "unwrapKey"];
  } else if (alg in JWE_KEY_WRAPPING_RSA) {
    const algDetails = JWE_KEY_WRAPPING_RSA[alg as RsaWrapAlgorithm];
    algorithm = {
      name: algDetails.name,
      hash: algDetails.hash,
    } as RsaHashedImportParams;
    // Default usages depend on public/private key
    defaultUsages = jwk.d ? ["unwrapKey", "decrypt"] : ["wrapKey", "encrypt"];
  } else if (alg in JWE_CONTENT_ENCRYPTION_ALGORITHMS) {
    const algDetails =
      JWE_CONTENT_ENCRYPTION_ALGORITHMS[alg as ContentEncryptionAlgorithm];
    if (jwk.kty !== "oct")
      throw new Error(`JWK with alg '${alg}' must have kty 'oct'.`);

    if (algDetails.type === "gcm") {
      algorithm = { name: "AES-GCM" };
    } else if (algDetails.type === "cbc") {
      algorithm = { name: "AES-CBC" };

      /* v8 ignore next 5, should be unreachable leaving mostly for type safety */
    } else {
      throw new Error(
        `Unsupported JWE content encryption algorithm type: ${(algDetails as any).type}`,
      );
    }

    defaultUsages = ["encrypt", "decrypt"];
  } else {
    throw new Error(`Unsupported or unknown algorithm for key import: ${alg}`);
  }

  // 2. Determine Key Usages
  let keyUsages: KeyUsage[] | undefined =
    options.keyUsages ?? (jwk.key_ops as KeyUsage[] | undefined);

  if (!keyUsages) {
    // If still undefined, try inferring from jwk.use or apply defaults
    if (jwk.use === "sig") {
      if (algorithm.name.startsWith("RSA")) {
        keyUsages = jwk.d ? ["sign"] : ["verify"];
      } else if (algorithm.name === "HMAC") {
        keyUsages = ["sign", "verify"];
      }
    } else if (
      jwk.use === "enc" &&
      (algorithm.name.startsWith("RSA") || algorithm.name.startsWith("AES"))
    ) {
      switch (algorithm.name) {
        case "AES-KW": {
          keyUsages = ["wrapKey", "unwrapKey"];
          break;
        }
        case "AES-GCM":
        case "AES-CBC": {
          keyUsages = ["encrypt", "decrypt"];
          break;
        }
        case "RSA-OAEP": {
          keyUsages = jwk.d ? ["unwrapKey", "decrypt"] : ["wrapKey", "encrypt"];
          break;
        }
      }
    }

    // If still no usages inferred, apply the defaults determined earlier
    if (!keyUsages) {
      keyUsages = defaultUsages;
    }
  }

  // 3. Prepare JWK for native import (remove potentially conflicting fields)
  const jwkForImport = { ...jwk };
  delete jwkForImport.alg;
  delete jwkForImport.use;
  delete jwkForImport.key_ops;

  // 4. Perform Import
  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwkForImport,
    algorithm,
    extractable,
    keyUsages,
  );
  return cryptoKey;
}

/**
 * Derives raw key bits from a password using PBKDF2.
 *
 * This function generates the raw cryptographic material. You will typically
 * need to import these bits using `importKey` for the specific cryptographic
 * algorithm you intend to use (e.g., "HS256" for signing, "AES-GCM" for encryption).
 *
 * @param password The password to derive the key from.
 * @param options Options controlling the derivation process, including the desired key length.
 * @returns A Promise resolving to an object containing the derived bits, salt, and iterations.
 */
export async function deriveKeyBitsFromPassword(
  password: string | Uint8Array,
  options: DeriveKeyBitsOptions & { keyLength: number },
): Promise<DerivedKeyBitsResult> {
  const {
    keyLength,
    salt = randomBytes(16),
    iterations = 2048,
    hash = "SHA-256",
  } = options;

  if (!keyLength || keyLength <= 0) {
    throw new Error("keyLength must be a positive number.");
  }
  if (salt.length === 0) {
    throw new Error("Salt cannot be empty.");
  }
  if (iterations <= 0) {
    throw new Error("Iterations must be positive.");
  }

  const passwordBuffer =
    typeof password === "string" ? textEncoder.encode(password) : password;

  // 1. Import the password as a base key for PBKDF2
  const baseKey = await crypto.subtle.importKey(
    "raw",
    passwordBuffer,
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  // 2. Define PBKDF2 parameters
  const pbkdf2Params: Pbkdf2Params = {
    name: "PBKDF2",
    hash: hash,
    salt: salt,
    iterations: iterations,
  };

  // 3. Derive the key bits
  const derivedBits = await crypto.subtle.deriveBits(
    pbkdf2Params,
    baseKey,
    keyLength,
  );

  return { derivedBits, salt, iterations, keyLength, hash };
}
