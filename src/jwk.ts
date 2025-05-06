import type {
  JWK,
  JWK_oct,
  JWK_PBES2,
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
  GenerateKeyReturn,
  DeriveKeyOptions,
  DeriveKeyReturn,
  KeyManagementAlgorithm,
  WrapKeyOptions,
  WrapKeyResult,
  UnwrapKeyOptions,
} from "./types";
import { base64UrlDecode, isJWK, textEncoder, randomBytes } from "./utils";
import {
  jwkTokey,
  keyToJWK,
  isCryptoKey,
  bitLengthCEK,
  deriveKey as deriveKeyPBES2,
  wrap as _wrap,
  unwrap as _unwrap,
  encryptIV as aesGcmKwEncrypt,
  decryptIV as aesGcmKwDecrypt,
} from "./jose";

/**
 * Generates a cryptographic key for the specified algorithm.
 *
 * @param alg The JWA algorithm identifier (e.g., "HS256", "RS256", "A128GCM").
 * @param options Configuration options for key generation.
 * @returns A Promise resolving to the generated key (CryptoKey, CryptoKeyPair, or Uint8Array) or its JWK representation.
 */
export async function generateKey<
  TAlg extends GenerateKeyAlgorithm,
  TOptions extends GenerateKeyOptions,
>(alg: TAlg, options?: TOptions): Promise<GenerateKeyReturn<TAlg, TOptions>>;
export async function generateKey(
  alg: string,
  options: GenerateKeyOptions = {},
): Promise<
  | CryptoKey
  | CryptoKeyPair
  | Uint8Array
  | JWK
  | { privateKey: JWK; publicKey: JWK }
> {
  const exportToJWK = options.toJWK === true;
  const defaultExtractable = options.extractable !== false; // Default true

  // Handle AES-CBC separately as it requires raw key generation
  if (
    alg === "A128CBC-HS256" ||
    alg === "A192CBC-HS384" ||
    alg === "A256CBC-HS512"
  ) {
    const keyLength = bitLengthCEK(alg);
    const keyBytes = randomBytes(keyLength >> 3);

    if (exportToJWK) {
      // Use keyToJWK which handles Uint8Array to JWK_oct
      return keyToJWK(keyBytes); // Returns JWK_oct
    }
    return keyBytes; // Returns Uint8Array
  }

  // For other algorithms, use crypto.subtle.generateKey
  const { algorithm, keyUsages } = getGenerateKeyParams(alg, options);

  const key = await crypto.subtle.generateKey(
    algorithm,
    defaultExtractable,
    keyUsages,
  );

  if (exportToJWK) {
    if (key instanceof CryptoKey) {
      // Symmetric keys (HMAC, AES-KW, AES-GCM)
      return exportKey(key, { alg }); // Returns JWK
    } else {
      // Asymmetric keys (RSA, EC)
      const [publicKey, privateKey] = await Promise.all([
        exportKey(key.publicKey, { alg }),
        exportKey(key.privateKey, { alg }),
      ]);
      return { privateKey, publicKey };
    }
  }

  return key;
}

/**
 * Derives a key from a password using PBKDF2 as specified by PBES2 algorithms.
 *
 * @param password The password to derive the key from (string or Uint8Array).
 * @param alg The PBES2 algorithm identifier (e.g., "PBES2-HS256+A128KW").
 * @param options Configuration options including salt and iterations.
 * @returns A Promise resolving to the derived key (CryptoKey) or its JWK_oct representation.
 */
export async function deriveKeyFromPassword<
  TAlg extends JWK_PBES2,
  TOptions extends DeriveKeyOptions,
>(
  password: string | Uint8Array,
  alg: TAlg,
  options: TOptions,
): Promise<DeriveKeyReturn<TOptions>>;
export async function deriveKeyFromPassword(
  password: string | Uint8Array,
  alg: JWK_PBES2,
  options: DeriveKeyOptions,
): Promise<CryptoKey | JWK_oct> {
  const { salt, iterations, toJWK, extractable, keyUsage } = options;

  if (!(salt instanceof Uint8Array) || salt.length < 8) {
    throw new Error("PBES2 Salt Input (salt) must be 8 or more octets");
  }
  if (typeof iterations !== "number" || iterations < 1) {
    throw new Error(
      "PBES2 Iteration Count (iterations) must be a positive integer",
    );
  }

  const passwordBytes =
    typeof password === "string" ? textEncoder.encode(password) : password;

  const derivedBytes = await deriveKeyPBES2(
    salt,
    alg,
    iterations,
    passwordBytes,
  );

  const wrappingAlg = alg.slice(-6); // "A128KW", "A192KW", "A256KW"
  const defaultUsages: KeyUsage[] = ["wrapKey", "unwrapKey"];
  const finalUsages = keyUsage ?? defaultUsages;
  const finalExtractable = extractable === true; // Default false

  // Import the derived bytes as a CryptoKey for the wrapping algorithm
  const derivedKey = await crypto.subtle.importKey(
    "raw",
    derivedBytes,
    { name: "AES-KW" },
    finalExtractable,
    finalUsages,
  );

  if (toJWK === true) {
    const jwk = (await keyToJWK(derivedKey)) as JWK_oct;

    return { ...jwk, alg: wrappingAlg, kty: "oct" };
  }

  return derivedKey;
}

/**
 * Imports a key from various formats (CryptoKey, JWK, Uint8Array).
 *
 * @param key The key to import, which can be a CryptoKey, JWK, or Uint8Array.
 * @param alg The algorithm to use for the imported key.
 * @returns A Promise resolving to the imported key in CryptoKey or Uint8Array format.
 */
export async function importKey(key: CryptoKey): Promise<CryptoKey>;
export async function importKey(key: Uint8Array): Promise<Uint8Array>;
export async function importKey(key: JWK, alg: string): Promise<CryptoKey>;
export async function importKey(
  key: CryptoKey | JWK | Uint8Array,
  alg?: string,
): Promise<CryptoKey | Uint8Array> {
  if (key instanceof Uint8Array) {
    return key;
  }

  if (isCryptoKey(key)) {
    return key;
  }

  if (isJWK(key)) {
    if ("k" in key && (key as JWK_oct).k) {
      return base64UrlDecode((key as JWK_oct).k, false);
    }
    return jwkTokey({ ...key, alg });
  }

  throw new Error("unreachable");
}

/**
 * Exports a CryptoKey to a JWK (JSON Web Key) format.
 *
 * @param key The CryptoKey to export.
 * @param jwk Optional partial JWK to merge with the exported key, allowing overrides.
 * @returns A Promise resolving to the exported JWK.
 */
export async function exportKey(
  key: CryptoKey,
  jwk?: Partial<JWK>,
): Promise<JWK> {
  const exportedJwk = await keyToJWK(key);

  // Merge the optional jwk properties
  if (jwk) {
    return { ...exportedJwk, ...jwk };
  }

  return exportedJwk;
}

/**
 * Wraps a Content Encryption Key (CEK) using the specified algorithm and wrapping key.
 *
 * @param alg The JWA key management algorithm (e.g., "A128KW", "RSA-OAEP", "PBES2-HS256+A128KW").
 * @param keyToWrap The key to be wrapped (CEK), typically a symmetric key as Uint8Array or CryptoKey.
 * @param wrappingKey The key used to wrap the CEK (CryptoKey, JWK, or password string/Uint8Array for PBES2).
 * @param options Additional options required by certain algorithms (e.g., p2s, p2c for PBES2).
 * @returns A Promise resolving to an object containing the wrapped key and any necessary parameters (iv, tag, epk, etc.).
 */
export async function wrapKey(
  alg: KeyManagementAlgorithm,
  keyToWrap: CryptoKey | Uint8Array,
  wrappingKey: CryptoKey | JWK | string | Uint8Array,
  options: WrapKeyOptions = {},
): Promise<WrapKeyResult> {
  const cekBytes =
    keyToWrap instanceof Uint8Array
      ? keyToWrap
      : new Uint8Array(await crypto.subtle.exportKey("raw", keyToWrap));

  let importedWrappingKey: CryptoKey | Uint8Array;
  const isPbes = alg.startsWith("PBES2");
  const isAesKw = ["A128KW", "A192KW", "A256KW"].includes(alg);

  if (
    isPbes &&
    (typeof wrappingKey === "string" || wrappingKey instanceof Uint8Array)
  ) {
    // PBES2 uses password bytes directly
    importedWrappingKey =
      typeof wrappingKey === "string"
        ? textEncoder.encode(wrappingKey)
        : wrappingKey;
  } else if (isPbes || isAesKw) {
    // Import AES-KW key or the key derived *from* password for PBES2
    if (typeof wrappingKey === "string") {
      throw new TypeError(
        "Wrapping key must be a CryptoKey, JWK, or Uint8Array for AES-KW or non-password PBES2",
      );
    }
    importedWrappingKey = await importKey(wrappingKey as any, alg);
  } else {
    // Handle other algorithms (RSA, AESGCMKW, ECDH-ES)
    if (typeof wrappingKey === "string") {
      throw new TypeError(
        "Wrapping key must be a CryptoKey, JWK, or Uint8Array for non-PBES2 algorithms",
      );
    }
    importedWrappingKey = await importKey(wrappingKey as any, alg);
  }

  switch (alg) {
    // AES Key Wrap and PBES2 are handled by the same helper
    case "A128KW":
    case "A192KW":
    case "A256KW":
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      const { p2s, p2c } = options;
      if (isPbes && (!p2s || typeof p2c !== "number")) {
        throw new Error(
          "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
        );
      }
      return _wrap(alg, importedWrappingKey, cekBytes, p2c, p2s);
    }

    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      const { encryptedKey, iv, tag } = await aesGcmKwEncrypt(
        alg,
        importedWrappingKey,
        cekBytes,
        options.iv,
      );
      return { encryptedKey, iv, tag };
    }

    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      // Use crypto.subtle.wrapKey directly for RSA-OAEP
      const keyToWrapImported = await crypto.subtle.importKey(
        "raw",
        cekBytes,
        { name: "AES-GCM", length: cekBytes.length * 8 },
        true,
        ["encrypt", "decrypt"],
      );
      const encryptedKey = new Uint8Array(
        await crypto.subtle.wrapKey(
          "raw",
          keyToWrapImported,
          importedWrappingKey as CryptoKey,
          { name: "RSA-OAEP" },
        ),
      );
      return { encryptedKey };
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      // ECDH-ES requires more complex logic
      throw new Error(`Algorithm ${alg} not yet implemented in wrapKey`);
    }

    default: {
      throw new Error(`Unsupported key wrapping algorithm: ${alg}`);
    }
  }
}

/**
 * Unwraps a Content Encryption Key (CEK) using the specified algorithm and unwrapping key.
 *
 * @param alg The JWA key management algorithm (e.g., "A128KW", "RSA-OAEP", "PBES2-HS256+A128KW").
 * @param wrappedKey The wrapped key (ciphertext) as Uint8Array.
 * @param unwrappingKey The key used to unwrap the CEK (CryptoKey, JWK, or password string/Uint8Array for PBES2).
 * @param options Additional options required by certain algorithms (e.g., iv, tag, p2s, p2c, epk).
 * @returns A Promise resolving to the unwrapped key (CEK) as a CryptoKey or Uint8Array.
 */
export async function unwrapKey<T extends boolean | undefined = undefined>(
  alg: KeyManagementAlgorithm,
  wrappedKey: Uint8Array,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array,
  options: UnwrapKeyOptions & { returnAs?: T } = {},
): Promise<T extends false ? Uint8Array : CryptoKey> {
  const { returnAs = true } = options; // Default to returning CryptoKey
  const defaultExtractable = options.extractable !== false; // Default true

  let importedUnwrappingKey: CryptoKey | Uint8Array;
  const isPbes = alg.startsWith("PBES2");
  const isAesKw = ["A128KW", "A192KW", "A256KW"].includes(alg);

  if (
    isPbes &&
    (typeof unwrappingKey === "string" || unwrappingKey instanceof Uint8Array)
  ) {
    // PBES2 uses password bytes directly
    importedUnwrappingKey =
      typeof unwrappingKey === "string"
        ? textEncoder.encode(unwrappingKey)
        : unwrappingKey;
  } else if (isPbes || isAesKw) {
    // Import AES-KW key or the key derived *from* password for PBES2
    if (typeof unwrappingKey === "string") {
      throw new TypeError(
        "Unwrapping key must be a CryptoKey, JWK, or Uint8Array for AES-KW or non-password PBES2",
      );
    }
    importedUnwrappingKey = await importKey(unwrappingKey as any, alg);
  } else {
    // Handle other algorithms (RSA, AESGCMKW, ECDH-ES)
    if (typeof unwrappingKey === "string") {
      throw new TypeError(
        "Unwrapping key must be a CryptoKey, JWK, or Uint8Array for non-PBES2 algorithms",
      );
    }
    importedUnwrappingKey = await importKey(unwrappingKey as any, alg);
  }

  let unwrappedCekBytes: Uint8Array;

  switch (alg) {
    // AES Key Wrap and PBES2 are handled by the same helper
    case "A128KW":
    case "A192KW":
    case "A256KW":
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      const { p2s, p2c } = options;
      let p2sBytes: Uint8Array | undefined;
      if (isPbes) {
        if (!p2s || typeof p2c !== "number") {
          throw new Error(
            "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
          );
        }
        p2sBytes = typeof p2s === "string" ? base64UrlDecode(p2s, false) : p2s;
      }
      unwrappedCekBytes = await _unwrap(
        alg,
        importedUnwrappingKey,
        wrappedKey,
        p2c,
        p2sBytes,
      );
      break;
    }

    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      if (!options.iv || !options.tag) {
        throw new Error(
          "AES-GCMKW requires 'iv' and 'tag' options for unwrapping",
        );
      }
      const ivBytes =
        typeof options.iv === "string"
          ? base64UrlDecode(options.iv, false)
          : options.iv;
      const tagBytes =
        typeof options.tag === "string"
          ? base64UrlDecode(options.tag, false)
          : options.tag;
      unwrappedCekBytes = await aesGcmKwDecrypt(
        alg,
        importedUnwrappingKey,
        wrappedKey,
        ivBytes,
        tagBytes,
      );
      break;
    }

    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      // Use crypto.subtle.unwrapKey directly for RSA-OAEP
      const unwrappedKey = await crypto.subtle.unwrapKey(
        "raw",
        wrappedKey,
        importedUnwrappingKey as CryptoKey,
        { name: "RSA-OAEP" },
        options.unwrappedKeyAlgorithm || { name: "AES-GCM" }, // Fallback
        defaultExtractable,
        options.keyUsage || ["encrypt", "decrypt"], // Default usages
      );
      if (returnAs) return unwrappedKey as any;
      // Otherwise, export the bytes
      unwrappedCekBytes = new Uint8Array(
        await crypto.subtle.exportKey("raw", unwrappedKey),
      );
      break;
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!options.epk) {
        throw new Error("ECDH-ES requires 'epk' (Ephemeral Public Key) option");
      }
      // ECDH-ES requires key agreement then AES-KW unwrap
      throw new Error(`Algorithm ${alg} not yet implemented in unwrapKey`);
    }

    default: {
      throw new Error(`Unsupported key unwrapping algorithm: ${alg}`);
    }
  }

  // If returning bytes, return them now (applies to AES-KW/PBES2/AES-GCMKW paths)
  if (!returnAs) {
    return unwrappedCekBytes as any;
  }

  // Otherwise, import the unwrapped bytes as a CryptoKey
  const finalKey = await crypto.subtle.importKey(
    "raw",
    unwrappedCekBytes,
    options.unwrappedKeyAlgorithm || { name: "AES-GCM" },
    defaultExtractable,
    options.keyUsage || ["encrypt", "decrypt"],
  );

  return finalKey as any;
}

function getGenerateKeyParams(
  alg: string,
  options?: Omit<GenerateKeyOptions, "toJWK">,
): {
  algorithm: AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams;
  keyUsages: KeyUsage[];
} {
  let algorithm: AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams;
  let keyUsages: KeyUsage[];

  const defaultKeyUsage = options?.keyUsage;

  switch (alg) {
    // HMAC Signatures
    case "HS256":
    case "HS384":
    case "HS512": {
      algorithm = {
        name: "HMAC",
        hash: `SHA-${alg.slice(2)}`,
      };
      keyUsages = defaultKeyUsage ?? ["sign", "verify"];
      break;
    }
    // RSA Signatures
    case "RS256":
    case "RS384":
    case "RS512": {
      algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: options?.modulusLength ?? 2048,
        publicExponent:
          options?.publicExponent ?? new Uint8Array([0x01, 0x00, 0x01]),
        hash: `SHA-${alg.slice(2)}`,
      };
      keyUsages = defaultKeyUsage ?? ["sign", "verify"];
      break;
    }
    // RSA PSS Signatures
    case "PS256":
    case "PS384":
    case "PS512": {
      algorithm = {
        name: "RSA-PSS",
        modulusLength: options?.modulusLength ?? 2048,
        publicExponent:
          options?.publicExponent ?? new Uint8Array([0x01, 0x00, 0x01]),
        hash: `SHA-${alg.slice(2)}`,
      };
      keyUsages = defaultKeyUsage ?? ["sign", "verify"];
      break;
    }
    // ECDSA Signatures
    case "ES256": {
      algorithm = { name: "ECDSA", namedCurve: "P-256" };
      keyUsages = defaultKeyUsage ?? ["sign", "verify"];
      break;
    }
    case "ES384": {
      algorithm = { name: "ECDSA", namedCurve: "P-384" };
      keyUsages = defaultKeyUsage ?? ["sign", "verify"];
      break;
    }
    case "ES512": {
      algorithm = { name: "ECDSA", namedCurve: "P-521" };
      keyUsages = defaultKeyUsage ?? ["sign", "verify"];
      break;
    }
    // EdDSA Signatures should be imported

    // RSA Encryption
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      algorithm = {
        name: "RSA-OAEP",
        modulusLength: options?.modulusLength ?? 2048,
        publicExponent:
          options?.publicExponent ?? new Uint8Array([0x01, 0x00, 0x01]),
        hash: `SHA-${Number.parseInt(alg.slice(9), 10) || 1}`,
      };
      keyUsages = defaultKeyUsage ?? [
        "encrypt",
        "decrypt",
        "wrapKey",
        "unwrapKey",
      ];
      break;
    }
    // AES Key Wrap
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      algorithm = { name: "AES-KW" };
      keyUsages = defaultKeyUsage ?? ["wrapKey", "unwrapKey"];
      break;
    }
    // AES GCM Encryption
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      algorithm = { name: "AES-GCM" };
      keyUsages = defaultKeyUsage ?? ["encrypt", "decrypt"];
      break;
    }

    // ECDH Key Agreement (requires specific curve in JWK for import, generation is simpler)
    // For generation, typically generate the EC key pair first (e.g., P-256, P-384, P-521, X25519)
    // then use deriveBits/deriveKey. Direct generation for "ECDH-ES*" alg isn't standard.
    // Handle EC key pair generation under ES256/ES384/ES512.

    default: {
      throw new Error(
        `Unsupported or invalid algorithm for key generation: ${alg}`,
      );
    }
  }

  return { algorithm, keyUsages };
}
