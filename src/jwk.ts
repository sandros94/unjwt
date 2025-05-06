import type {
  JWK,
  JWK_oct,
  JWK_PBES2,
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
  GenerateKeyReturn,
  DeriveKeyOptions,
  DeriveKeyReturn,
} from "./types";
import { base64UrlDecode, isJWK, textEncoder, randomBytes } from "./utils";
import {
  jwkTokey,
  keyToJWK,
  isCryptoKey,
  bitLengthCEK,
  deriveKey as deriveKeyPBES2,
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
