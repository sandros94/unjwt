import type {
  JWK,
  JWKSet,
  JWK_oct,
  JWK_PBES2,
  JWKPEMAlgorithm,
  JWKParameters,
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
  GenerateKeyReturn,
  GenerateJWKOptions,
  GenerateJWKReturn,
  DeriveKeyOptions,
  DeriveKeyReturn,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
  WrapKeyOptions,
  WrapKeyResult,
  UnwrapKeyOptions,
  JoseHeaderParameters,
} from "./types";
import {
  base64UrlDecode,
  isCryptoKey,
  isJWK,
  isJWKSet,
  textEncoder,
  randomBytes,
} from "./utils";
import { sanitizeObject } from "./utils";
import {
  jwkTokey,
  keyToJWK,
  bitLengthCEK,
  deriveKey as deriveKeyPBES2,
  deriveECDHESKey,
  allowed as isEcdhKeyAllowed,
  normalizeKey,
  wrap as _wrap,
  unwrap as _unwrap,
  encryptIV as aesGcmKwEncrypt,
  decryptIV as aesGcmKwDecrypt,
  fromPKCS8,
  fromSPKI,
  fromX509,
  decryptRSAES,
  toPKCS8,
  toSPKI,
  type KeyImportOptions,
} from "./jose";

export type * from "./types/jwk";
export type * from "./types/jwt";

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
  | Uint8Array<ArrayBuffer>
  | JWK
  | { privateKey: JWK; publicKey: JWK }
> {
  const exportToJWK = options.toJWK !== undefined && options.toJWK !== false;
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
      // Use keyToJWK which handles Uint8Array<ArrayBuffer> to JWK_oct
      return keyToJWK(keyBytes); // Returns JWK_oct
    }
    return keyBytes; // Returns Uint8Array<ArrayBuffer>
  }

  // For other algorithms, use crypto.subtle.generateKey
  const { algorithm, keyUsages } = getGenerateKeyParams(alg, options);

  const key = await crypto.subtle.generateKey(
    algorithm,
    defaultExtractable,
    keyUsages,
  );

  if (exportToJWK) {
    const {
      alg: _a,
      kty: _k,
      key_ops: _ko,
      ext: _e,
      ...additionalKeyParams
    } = typeof options.toJWK === "object"
      ? (options.toJWK as JWKParameters)
      : {};
    if (key instanceof CryptoKey) {
      // Symmetric keys (HMAC, AES-KW, AES-GCM)
      return exportKey(key, {
        ...additionalKeyParams,
        alg,
      });
    } else {
      // Asymmetric keys (RSA, EC, OKP)
      const [publicKey, privateKey] = await Promise.all([
        exportKey(key.publicKey, { ...additionalKeyParams, alg }),
        exportKey(key.privateKey, {
          ...additionalKeyParams,
          alg,
        }),
      ]);
      return { privateKey, publicKey };
    }
  }

  return key;
}

/**
 * Generates a Json Web Key (JWK) for the specified algorithm.
 *
 * @param alg The JWA algorithm identifier (e.g., "HS256", "RS256", "A128GCM").
 * @param jwkParams Optional partial JWK to merge with the generated key, allowing overrides.
 * @param options Configuration options for key generation.
 * @returns A Promise resolving to the generated JWK or JWK pair representation.
 */
export async function generateJWK<TAlg extends GenerateKeyAlgorithm>(
  alg: TAlg,
  jwkParams?: Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">,
  options: GenerateJWKOptions = {},
): Promise<GenerateJWKReturn<TAlg>> {
  const {
    // @ts-expect-error destructuring just to avoid passing it down
    toJWK: _,
    ...opts
  } = options;

  return generateKey(alg, {
    ...opts,
    toJWK: {
      kid:
        typeof jwkParams?.kid === "string"
          ? jwkParams.kid
          : crypto.randomUUID(),
      ...jwkParams,
    },
  });
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
  password: string | Uint8Array<ArrayBuffer>,
  alg: TAlg,
  options: TOptions,
): Promise<DeriveKeyReturn<TOptions>>;
export async function deriveKeyFromPassword(
  password: string | Uint8Array<ArrayBuffer>,
  alg: JWK_PBES2,
  options: DeriveKeyOptions,
): Promise<CryptoKey | JWK_oct> {
  const { salt, iterations, extractable, keyUsage } = options;
  const exportToJWK = options.toJWK !== undefined && options.toJWK !== false;

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
  const finalExtractable = exportToJWK ? true : extractable === true;

  // Import the derived bytes as a CryptoKey for the wrapping algorithm
  const derivedKey = await crypto.subtle.importKey(
    "raw",
    derivedBytes,
    { name: "AES-KW" },
    finalExtractable,
    finalUsages,
  );

  if (exportToJWK) {
    const jwk = await keyToJWK<JWK_oct>(derivedKey);
    const {
      alg: _a,
      kty: _k,
      key_ops: _ko,
      ext: _e,
      ...additionalKeyParams
    } = typeof options.toJWK === "object"
      ? (options.toJWK as JWKParameters)
      : {};

    return { ...additionalKeyParams, ...jwk, alg: wrappingAlg, kty: "oct" };
  }

  return derivedKey;
}

/**
 * Derives a Json Web Key (JWK) from a password using PBKDF2 as specified by PBES2 algorithms.
 *
 * @param password The password to derive the key from (string or Uint8Array).
 * @param alg The PBES2 algorithm identifier (e.g., "PBES2-HS256+A128KW").
 * @param jwkParams Optional partial JWK to merge with the generated key, allowing overrides.
 * @param options Configuration options including salt and iterations.
 * @returns A Promise resolving to the derived JWK (JWK_oct).
 */
export async function deriveJWKFromPassword(
  password: string | Uint8Array<ArrayBuffer>,
  alg: JWK_PBES2,
  options: Omit<DeriveKeyOptions, "toJWK">,
  jwkParams?: Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">,
): Promise<JWK_oct> {
  const {
    // @ts-expect-error destructuring just to avoid passing it down
    toJWK: _,
    ...opts
  } = options;

  return deriveKeyFromPassword(password, alg, {
    ...opts,
    toJWK: (jwkParams as object) || true,
  });
}

/**
 * Imports a key from various formats (CryptoKey, JWK, Uint8Array).
 *
 * - If `key` is a CryptoKey, it's returned directly.
 * - If `key` is a Uint8Array, it's returned directly.
 * - If `key` is a JWK_oct (symmetric key with 'k'), the raw key bytes are returned as Uint8Array.
 * - If `key` is any other JWK type (asymmetric), the `alg` parameter is required, and a CryptoKey is returned.
 *
 * @param key The key to import.
 * @param alg The algorithm hint, required when importing asymmetric JWKs.
 * @returns A Promise resolving to the imported key as CryptoKey or Uint8Array.
 */
export async function importKey(key: string): Promise<Uint8Array<ArrayBuffer>>;
export async function importKey(
  key: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>>;
export async function importKey(key: CryptoKey): Promise<CryptoKey>;
export async function importKey(key: JWK_oct): Promise<Uint8Array<ArrayBuffer>>;
export async function importKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer> | string,
  alg?: string,
): Promise<CryptoKey | Uint8Array<ArrayBuffer>>;
export async function importKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer> | string,
  alg?: string,
): Promise<CryptoKey | Uint8Array<ArrayBuffer>> {
  if (typeof key === "string") {
    key = textEncoder.encode(key);
  }

  if (key instanceof Uint8Array) {
    return key;
  }

  if (isCryptoKey(key)) {
    return key;
  }

  if (isJWK(key)) {
    if ("k" in key && typeof key.k === "string") {
      return base64UrlDecode(key.k as string, false);
    } else {
      if (!key.alg && !alg) {
        throw new TypeError(
          "Algorithm must be provided when importing non-oct JWK",
        );
      }
      return jwkTokey({
        ...key,
        alg: key.alg || alg,
      });
    }
  }

  // This should be unreachable
  throw new Error("Invalid key type provided to importKey");
}

/**
 * Exports a CryptoKey to a JWK (JSON Web Key) format.
 *
 * @param key The CryptoKey to export.
 * @param jwk Optional partial JWK to merge with the exported key, allowing overrides.
 * @returns A Promise resolving to the exported JWK.
 */
export async function exportKey<T extends JWK>(
  key: CryptoKey,
  jwk?: Partial<JWK>,
): Promise<T> {
  const exportedJwk = await keyToJWK<T>(key);

  // Merge the additional jwk properties and make sure the exported ones have priority
  if (jwk) {
    return { ...sanitizeObject(jwk), ...exportedJwk };
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
  keyToWrap: CryptoKey | Uint8Array<ArrayBuffer>,
  wrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: WrapKeyOptions = {},
): Promise<WrapKeyResult> {
  const cekBytes =
    keyToWrap instanceof Uint8Array
      ? keyToWrap
      : new Uint8Array(await crypto.subtle.exportKey("raw", keyToWrap));

  let importedWrappingKey: CryptoKey | Uint8Array<ArrayBuffer>;
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
  wrappedKey: Uint8Array<ArrayBuffer>,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: UnwrapKeyOptions & { returnAs?: T } = {},
): Promise<T extends false ? Uint8Array<ArrayBuffer> : CryptoKey> {
  const { returnAs = true } = options; // Default to returning CryptoKey
  const defaultExtractable = options.extractable !== false; // Default true

  let importedUnwrappingKey: CryptoKey | Uint8Array<ArrayBuffer>;
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

  let unwrappedCekBytes: Uint8Array<ArrayBuffer>;

  switch (alg) {
    // AES Key Wrap and PBES2 are handled by the same helper
    case "A128KW":
    case "A192KW":
    case "A256KW":
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      const { p2s, p2c } = options;
      let p2sBytes: Uint8Array<ArrayBuffer> | undefined;
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
      if (!(importedUnwrappingKey instanceof CryptoKey)) {
        throw new TypeError(
          "RSA-OAEP requires the unwrapping key to be provided as a CryptoKey",
        );
      }

      unwrappedCekBytes = await decryptRSAES(
        alg,
        importedUnwrappingKey,
        wrappedKey,
      );

      if (!returnAs) {
        break;
      }

      const inferredAlgorithm =
        options.unwrappedKeyAlgorithm ||
        inferAesImportAlgorithm(options.enc, unwrappedCekBytes.length);

      if (!inferredAlgorithm) {
        throw new Error(
          'Unable to infer algorithm for RSA-OAEP unwrapped key. Provide "unwrappedKeyAlgorithm" in options.',
        );
      }

      const keyUsages = options.keyUsage || ["encrypt", "decrypt"];
      return (await crypto.subtle.importKey(
        "raw",
        unwrappedCekBytes,
        inferredAlgorithm,
        defaultExtractable,
        keyUsages,
      )) as any;
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!options.epk) {
        throw new Error("ECDH-ES requires 'epk' (Ephemeral Public Key) option");
      }
      if (!(importedUnwrappingKey instanceof CryptoKey)) {
        throw new TypeError(
          "ECDH-ES requires the unwrapping key to be a CryptoKey",
        );
      }

      if (!isEcdhKeyAllowed(importedUnwrappingKey)) {
        throw new Error(
          "ECDH with the provided key is not allowed or not supported",
        );
      }

      const epkCandidate =
        options.epk instanceof CryptoKey
          ? options.epk
          : ((await normalizeKey(options.epk, alg)) as CryptoKey);

      if (!(epkCandidate instanceof CryptoKey)) {
        throw new TypeError("Failed to normalize ECDH ephemeral public key");
      }

      const apuBytes =
        typeof options.apu === "string"
          ? base64UrlDecode(options.apu, false)
          : (options.apu ?? new Uint8Array(0));
      const apvBytes =
        typeof options.apv === "string"
          ? base64UrlDecode(options.apv, false)
          : (options.apv ?? new Uint8Array(0));

      const infoAlg = alg === "ECDH-ES" ? options.enc : alg;

      if (!infoAlg) {
        throw new Error(
          "ECDH-ES requires content encryption algorithm ('enc') to derive the shared secret",
        );
      }

      const keyLength =
        alg === "ECDH-ES"
          ? bitLengthCEK(infoAlg)
          : Number.parseInt(alg.slice(-5, -2), 10);

      const sharedSecret = await deriveECDHESKey(
        epkCandidate,
        importedUnwrappingKey,
        infoAlg,
        keyLength,
        apuBytes,
        apvBytes,
      );

      if (alg === "ECDH-ES") {
        unwrappedCekBytes = sharedSecret;
      } else {
        const kwAlg = alg.slice(-6);
        if (!(wrappedKey instanceof Uint8Array) || wrappedKey.length === 0) {
          throw new Error(
            "ECDH-ES key agreement with key wrapping requires an encrypted key",
          );
        }
        unwrappedCekBytes = await _unwrap(kwAlg, sharedSecret, wrappedKey);
      }

      break;
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

/**
 * Imports a key from a PEM-encoded string and converts it to a JWK.
 *
 * @param pem The PEM-encoded string.
 * @param pemType The type of PEM encoding ('pkcs8' for private keys, 'spki' for public keys, 'x509' for certificates).
 * @param alg The JWA algorithm identifier. This is crucial for `crypto.subtle.importKey`
 *            to understand the key's intended algorithm and for setting the 'alg' field in the resulting JWK.
 * @param importOptions Options for the PEM import process (e.g., extractable for the CryptoKey).
 * @param jwkExtras Additional properties to merge into the resulting JWK.
 * @returns A Promise resolving to the imported key as a JWK.
 */
export async function importJWKFromPEM<T extends JWK>(
  pem: string,
  pemType: "pkcs8" | "spki" | "x509",
  alg: JWKPEMAlgorithm,
  importOptions?: KeyImportOptions,
  jwkExtras?: Partial<JWK>,
): Promise<T> {
  let cryptoKey: CryptoKey;
  const defaultExtractable = importOptions?.extractable !== false; // Default true

  switch (pemType) {
    case "pkcs8": {
      cryptoKey = await fromPKCS8(pem, alg, {
        ...importOptions,
        extractable: defaultExtractable,
      });
      break;
    }
    case "spki": {
      cryptoKey = await fromSPKI(pem, alg, {
        ...importOptions,
        extractable: defaultExtractable,
      });
      break;
    }
    case "x509": {
      // fromX509 internally calls fromSPKI, passing alg and options.
      cryptoKey = await fromX509(pem, alg, {
        ...importOptions,
        extractable: defaultExtractable,
      });
      break;
    }
    default: {
      throw new TypeError(`Unsupported PEM type: ${pemType}`);
    }
  }

  // Ensure the 'alg' from input is included in the new JWK.
  const finalJWKExtras = { alg, ...jwkExtras };
  return exportKey(cryptoKey, finalJWKExtras);
}

/**
 * Exports a JWK to a PEM-encoded string.
 *
 * @param jwk The JWK to export.
 * @param pemFormat The desired PEM format ('pkcs8' for private keys, 'spki' for public keys).
 * @param algForCryptoKeyImport If the JWK does not have an 'alg' property, this algorithm hint is
 *                              required to correctly convert it to a CryptoKey first.
 * @returns A Promise resolving to the PEM-encoded key string.
 */
export async function exportJWKToPEM(
  jwk: JWK,
  pemFormat: "pkcs8" | "spki",
  algForCryptoKeyImport?: JWKPEMAlgorithm,
): Promise<string> {
  if (jwk.kty === "oct") {
    throw new TypeError(
      "Octet (symmetric) JWKs (kty: 'oct') cannot be exported to PKCS8 or SPKI PEM formats.",
    );
  }

  const effectiveAlg = jwk.alg || algForCryptoKeyImport;
  if (
    !effectiveAlg &&
    (jwk.kty === "RSA" || jwk.kty === "EC" || jwk.kty === "OKP")
  ) {
    throw new TypeError(
      "Algorithm (alg) must be provided in the JWK or as a parameter for converting this JWK type to a CryptoKey.",
    );
  }

  // Ensure the JWK is treated as extractable for the intermediate CryptoKey,
  // as PEM export should require a CryptoKey to be extractable.
  const jwkForImport: JWK = { ...jwk, ext: true };

  // This function returns CryptoKey for non-'oct' JWKs.
  const cryptoKeyCandidate = await importKey(jwkForImport, effectiveAlg);

  if (!isCryptoKey(cryptoKeyCandidate)) {
    throw new Error(
      "Failed to convert JWK to a CryptoKey instance suitable for PEM export.",
    );
  }
  const cryptoKey = cryptoKeyCandidate;

  switch (pemFormat) {
    case "pkcs8": {
      if (cryptoKey.type !== "private") {
        throw new TypeError(
          `Only 'private' type CryptoKeys can be exported to PKCS8 PEM format. Key type is '${cryptoKey.type}'.`,
        );
      }
      return toPKCS8(cryptoKey);
    }
    case "spki": {
      if (cryptoKey.type !== "public") {
        throw new TypeError(
          `Only 'public' type CryptoKeys can be exported to SPKI PEM format. Key type is '${cryptoKey.type}'.`,
        );
      }
      return toSPKI(cryptoKey);
    }
    default: {
      throw new TypeError(`Unsupported PEM format: ${pemFormat}`);
    }
  }
}

/**
 * Retrieves a JWK (JSON Web Key) from a JWKSet based on a key ID (kid) or
 * properties from a JOSE Header.
 *
 * @param jwkSet The JWKSet to search within.
 * @param kidOrProtectedHeader Either a string representing the 'kid' (Key ID)
 *        or an object representing the JOSE Protected Header. If an object is
 *        provided, it must contain a 'kid' property. It can optionally contain
 *        'alg' (Algorithm) and 'kty' (Key Type) to further refine the search.
 * @returns The matching JWK from the set.
 * @throws TypeError if `jwkSet` is invalid or `kidOrProtectedHeader` is not a
 *         string or a valid header object.
 * @throws Error if no key is found matching the provided criteria, or if the
 *         header object is missing the 'kid' property.
 */
export function getJWKFromSet(
  jwkSet: JWKSet,
  kidOrProtectedHeader:
    | string
    | (JoseHeaderParameters & { alg?: string; kty?: string }),
): JWK {
  if (!jwkSet || !isJWKSet(jwkSet)) {
    throw new TypeError("Invalid JWK Set provided");
  }

  if (typeof kidOrProtectedHeader === "string") {
    // If kidOrProtectedHeader is a string, treat it as a kid
    const kid = kidOrProtectedHeader;
    const selectedKey = jwkSet.keys.find((k: JWK) => k.kid === kid);
    if (!selectedKey) {
      throw new Error(`No key found in JWK Set with kid "${kid}".`);
    }
    return selectedKey;
  } else if (typeof kidOrProtectedHeader === "object") {
    // If kidOrProtectedHeader is an object, treat it as a protected header

    const { kid, alg, kty } = kidOrProtectedHeader;

    if (!kid) {
      throw new Error(
        "JWS Protected Header is missing 'kid' (Key ID) and a JWK Set was provided. Cannot select key from JWK Set automatically.",
      );
    }

    const selectedKey = jwkSet.keys.find((k: JWK) => {
      return (
        k.kid === kid && (!alg || k.alg === alg) && (!kty || k.kty === kty)
      );
    });

    if (!selectedKey) {
      let errorMessage = `No key found in JWK Set with kid "${kid}"`;
      if (alg) {
        errorMessage += ` and alg "${alg}"`;
      }
      if (kty) {
        errorMessage += ` and kty "${kty}"`;
      }
      errorMessage += ".";
      throw new Error(errorMessage);
    }

    return selectedKey;
  }

  throw new TypeError(
    "`kidOrProtectedHeader` must be a string (kid) or an object (JOSE Protected Header).",
  );
}

function getGenerateKeyParams(
  alg: string,
  options?: Omit<GenerateKeyOptions, "toJWK">,
): {
  algorithm: AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams;
  keyUsages: KeyUsage[];
} {
  let algorithm:
    | AlgorithmIdentifier
    | AesKeyAlgorithm
    | RsaHashedKeyGenParams
    | EcKeyGenParams;
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
      const length = Number.parseInt(alg.slice(1, 4), 10);
      algorithm = { name: "AES-KW", length };
      keyUsages = defaultKeyUsage ?? ["wrapKey", "unwrapKey"];
      break;
    }

    // AES GCM Encryption
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      const length = Number.parseInt(alg.slice(1, 4), 10);
      algorithm = { name: "AES-GCM", length };
      keyUsages = defaultKeyUsage ?? ["encrypt", "decrypt"];
      break;
    }

    // ECDSA Signatures
    case "ES256":
    case "ES384":
    case "ES512": {
      algorithm = { name: "ECDSA", namedCurve: `P-${alg.slice(2)}` };
      keyUsages = defaultKeyUsage ?? ["sign", "verify"];
      break;
    }
    case "Ed25519": {
      keyUsages = defaultKeyUsage ?? ["sign", "verify"];
      algorithm = { name: "Ed25519" };
      break;
    }
    case "EdDSA": {
      keyUsages = defaultKeyUsage ?? ["sign", "verify"];
      const namedCurve = options?.namedCurve ?? "Ed25519";
      switch (namedCurve) {
        case "Ed25519":
        case "Ed448": {
          algorithm = { name: namedCurve };
          break;
        }
        default: {
          throw new Error(
            "Unsupported namedCurve provided. Supported values are: Ed25519 and Ed448",
          );
        }
      }
      break;
    }

    // ECDSA Signatures
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      keyUsages = ["deriveBits"];
      const namedCurve = options?.namedCurve ?? "P-256";
      switch (namedCurve) {
        case "P-256":
        case "P-384":
        case "P-521": {
          algorithm = { name: "ECDH", namedCurve };
          break;
        }
        case "X25519": {
          algorithm = { name: "X25519" };
          break;
        }
        default: {
          throw new Error(
            "Unsupported namedCurve provided. Supported values are: P-256, P-384, P-521 and X25519",
          );
        }
      }
      break;
    }

    default: {
      throw new Error(
        `Unsupported or invalid algorithm for key generation: ${alg}`,
      );
    }
  }

  return { algorithm, keyUsages };
}

function inferAesImportAlgorithm(
  enc: ContentEncryptionAlgorithm | undefined,
  cekLengthBytes: number,
): AesKeyAlgorithm | undefined {
  const bitLength = cekLengthBytes << 3;

  if (enc) {
    if (enc.includes("GCM")) {
      return {
        name: "AES-GCM",
        length: Number.parseInt(enc.slice(1, 4), 10),
      } satisfies AesKeyAlgorithm;
    }

    if (enc.includes("CBC-HS")) {
      return undefined;
    }
  }

  if (bitLength === 128 || bitLength === 192 || bitLength === 256) {
    return { name: "AES-GCM", length: bitLength } satisfies AesKeyAlgorithm;
  }

  return undefined;
}
