import type {
  JWK,
  JWKSet,
  JWK_Pair,
  JWK_oct,
  JWK_PBES2,
  JWK_EC,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_ECDH_ES,
  JWKPEMAlgorithm,
  JWKParameters,
  JWKCacheAdapter,
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
  base64UrlEncode,
  isCryptoKey,
  isCryptoKeyPair,
  isJWK,
  isJWKSet,
  sanitizeObject,
  textEncoder,
  randomBytes,
} from "./utils";
import { JWTError } from "./error";
import {
  jwkTokey,
  keyToJWK,
  bitLengthCEK,
  deriveKeyPBES2,
  pbes2Wrap,
  pbes2Unwrap,
  deriveECDHESKey,
  isECDHKeyAllowed,
  normalizeKey,
  aesKwWrap,
  aesKwUnwrap,
  gcmkwEncrypt,
  gcmkwDecrypt,
  fromPKCS8,
  fromSPKI,
  fromX509,
  encryptRSAES,
  decryptRSAES,
  toPKCS8,
  toSPKI,
} from "./_crypto";

export type * from "./types/jwk";
export { JWTError, isJWTError } from "./error";
export type { JWTErrorCode, JWTErrorCauseMap } from "./error";

/**
 * Generates a cryptographic key for the specified JWA algorithm.
 *
 * The return type is narrowed by `alg` and `options.toJWK`. When `toJWK` is not set
 * (or is `false`):
 *
 * - **Symmetric algorithms** (`HS*`, `A*KW`, `A*GCM`, `A*GCMKW`) → `CryptoKey`. The key
 *   is imported with Web Crypto usages derived from the algorithm (e.g. `["sign", "verify"]`
 *   for HMAC, `["wrapKey", "unwrapKey"]` for AES-KW, `["encrypt", "decrypt"]` for AES-GCM).
 * - **AES-CBC + HMAC composites** (`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`) →
 *   `Uint8Array`. These keys are returned as raw bytes because the composite layout
 *   (AES key ∥ HMAC key) is not directly importable via `crypto.subtle.importKey`. They
 *   are split internally during encrypt/decrypt.
 * - **Asymmetric algorithms** (`RS*`, `PS*`, `ES*`, `RSA-OAEP*`, `Ed25519`, `EdDSA`,
 *   `ECDH-ES*`) → `CryptoKeyPair`.
 *
 * When `options.toJWK` is `true`, the same call returns a JWK / JWK pair instead, with
 * a freshly generated `kid` attached (use {@link generateJWK} to customise `kid`,
 * `use`, etc.). Composite AES-CBC+HMAC keys are serialised to a single `JWK_oct` and
 * re-split internally on use.
 *
 * PBES2 is not a key-generation algorithm — use {@link deriveKeyFromPassword} or
 * {@link deriveJWKFromPassword} instead.
 *
 * @param alg The JWA algorithm identifier (e.g. `"HS256"`, `"RS256"`, `"A128GCM"`,
 *            `"A256CBC-HS512"`). PBES2, `"dir"`, and `"none"` are not accepted.
 * @param options
 *   - `toJWK?` — when `true`, return JWK / JWK pair instead of `CryptoKey` / `CryptoKeyPair`.
 *   - `extractable?` — forwarded to `crypto.subtle.generateKey`. Defaults to `true`.
 *   - `keyUsage?` — override the default usages derived from `alg`.
 *   - `modulusLength?` — RSA only; defaults to `2048`.
 *   - `publicExponent?` — RSA only; defaults to `0x010001`.
 *   - `namedCurve?` — EC and OKP only; defaults to `"P-256"` for EC and `"Ed25519"` for OKP.
 *
 * @example
 * ```ts
 * // HS256 → CryptoKey
 * const hmac = await generateKey("HS256");
 *
 * // A256CBC-HS512 → Uint8Array (composite key)
 * const cek = await generateKey("A256CBC-HS512");
 *
 * // RS256 → CryptoKeyPair
 * const rsa = await generateKey("RS256", { modulusLength: 2048 });
 *
 * // As JWK pair
 * const { privateKey, publicKey } = await generateKey("ES256", { toJWK: true });
 * ```
 */
export async function generateKey<
  TAlg extends GenerateKeyAlgorithm,
  TOptions extends GenerateKeyOptions,
>(alg: TAlg, options?: TOptions): Promise<GenerateKeyReturn<TAlg, TOptions>>;
export async function generateKey(
  alg: string,
  options: GenerateKeyOptions = {},
): Promise<CryptoKey | CryptoKeyPair | Uint8Array<ArrayBuffer> | JWK | JWK_Pair> {
  const exportToJWK = options.toJWK !== undefined && options.toJWK !== false;
  const defaultExtractable = options.extractable !== false; // Default true

  // Handle AES-CBC separately as it requires raw key generation
  if (alg === "A128CBC-HS256" || alg === "A192CBC-HS384" || alg === "A256CBC-HS512") {
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

  const key = await crypto.subtle.generateKey(algorithm, defaultExtractable, keyUsages);

  if (exportToJWK) {
    if (key instanceof CryptoKey) {
      // Symmetric keys (HMAC, AES-KW, AES-GCM). Force `alg` since Web Crypto's JWK
      // export drops the `KW` suffix on AES-GCM key wrap algorithms.
      return { ...(await exportKey(key)), alg };
    } else {
      // Asymmetric keys (RSA, EC, OKP)
      const [pub, priv] = await Promise.all([exportKey(key.publicKey), exportKey(key.privateKey)]);
      return { privateKey: { ...priv, alg }, publicKey: { ...pub, alg } } as JWK_Pair;
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
  options?: GenerateJWKOptions & Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">,
): Promise<GenerateJWKReturn<TAlg>> {
  const { keyUsage, extractable, modulusLength, publicExponent, namedCurve, ...jwkParams } =
    options ?? {};
  const kid = typeof jwkParams.kid === "string" ? jwkParams.kid : crypto.randomUUID();
  const extraParams = { ...jwkParams, kid };

  const result = await generateKey(alg, {
    keyUsage,
    extractable,
    modulusLength,
    publicExponent,
    namedCurve,
    toJWK: true,
  });

  if (result && typeof result === "object" && "privateKey" in result && "publicKey" in result) {
    const pair = result as { privateKey: JWK; publicKey: JWK };
    return {
      privateKey: { ...extraParams, ...pair.privateKey },
      publicKey: { ...extraParams, ...pair.publicKey },
    } as GenerateJWKReturn<TAlg>;
  }
  return { ...extraParams, ...(result as JWK) } as GenerateJWKReturn<TAlg>;
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
    throw new JWTError("PBES2 Salt Input (salt) must be 8 or more octets", "ERR_JWE_INVALID");
  }
  if (typeof iterations !== "number" || iterations < 1) {
    throw new JWTError(
      "PBES2 Iteration Count (iterations) must be a positive integer",
      "ERR_JWE_INVALID",
    );
  }

  const passwordBytes = typeof password === "string" ? textEncoder.encode(password) : password;

  const derivedBytes = await deriveKeyPBES2(salt, alg, iterations, passwordBytes);

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
    return { ...jwk, alg: wrappingAlg, kty: "oct" };
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
  options: Omit<DeriveKeyOptions, "toJWK"> & Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">,
): Promise<JWK_oct> {
  const { salt, iterations, keyUsage, extractable, ...jwkParams } = options;
  const result = await deriveKeyFromPassword(password, alg, {
    salt,
    iterations,
    keyUsage,
    extractable,
    toJWK: true,
  });
  return Object.keys(jwkParams).length > 0 ? { ...jwkParams, ...result } : result;
}

/**
 * Default JWK import cache backed by a WeakMap.
 *
 * The outer WeakMap is keyed by the JWK object reference — a cache hit only
 * occurs when the exact same object variable is passed to {@link importKey}.
 * Reconstructing a structurally identical JWK (e.g. `{ ...jwk }`) will miss
 * the cache.
 *
 * The inner `Record<string, CryptoKey>` uses a plain object rather than `Map`
 * because typical entries have 1–2 algorithm strings per key. V8 applies
 * hidden-class optimisation to small plain objects, making property access
 * faster than `Map.get()` at this cardinality.
 */
export class WeakMapJWKCache implements JWKCacheAdapter {
  private readonly _map = new WeakMap<object, Record<string, CryptoKey>>();

  get(jwk: JWK, alg: string): CryptoKey | undefined {
    return this._map.get(jwk)?.[alg];
  }

  set(jwk: JWK, alg: string, key: CryptoKey): void {
    let entry = this._map.get(jwk);
    if (!entry) {
      this._map.set(jwk, { [alg]: key });
    } else {
      entry[alg] = key;
    }
  }
}

let _activeCache: JWKCacheAdapter | false = new WeakMapJWKCache();

/**
 * Replace or disable the JWK import cache used by {@link importKey}.
 *
 * Pass a custom {@link JWKCacheAdapter} to use your own cache strategy
 * (LRU, Redis-backed wrapper, test spy, etc.). Pass `false` to disable
 * caching entirely.
 *
 * @example Disable caching:
 * ```ts
 * configureJWKCache(false);
 * ```
 * @example Use a custom kid-keyed cache:
 * ```ts
 * const map = new Map<string, CryptoKey>();
 * configureJWKCache({
 *   get: (jwk, alg) => map.get(`${jwk.kid}:${alg}`),
 *   set: (jwk, alg, key) => map.set(`${jwk.kid}:${alg}`, key),
 * });
 * ```
 */
export function configureJWKCache(cache: JWKCacheAdapter | false): void {
  _activeCache = cache;
}

/**
 * Reset the JWK import cache to a fresh {@link WeakMapJWKCache}.
 * Useful in test environments to clear all cached CryptoKey references
 * between test runs without disabling the cache entirely.
 */
export function clearJWKCache(): void {
  _activeCache = new WeakMapJWKCache();
}
/**
 * Imports a key from various formats (CryptoKey, JWK, Uint8Array).
 *
 * - If `key` is a `CryptoKey`, it's returned directly.
 * - If `key` is a `Uint8Array`, it's returned directly.
 * - If `key` is a `JWK_oct` (symmetric key with `k`), the raw key bytes are returned as `Uint8Array`.
 * - If `key` is any other JWK type (asymmetric), an algorithm hint is required (positional or via options)
 *   and a `CryptoKey` is returned.
 *
 * ### `expect` option (asymmetric only)
 *
 * Pass `expect: "public"` or `expect: "private"` to validate the caller's intent against the key's
 * shape before the import. A private JWK passed with `expect: "public"` throws `ERR_JWK_INVALID`
 * instead of silently importing the private material. Callers who deliberately want to drop private
 * fields can do so themselves — no silent stripping.
 *
 * `expect` is a no-op for symmetric (`oct`) JWKs and for `CryptoKey` instances whose
 * `algorithm.type` is `"secret"`.
 */
export async function importKey(key: string): Promise<Uint8Array<ArrayBuffer>>;
export async function importKey(key: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>>;
export async function importKey(key: CryptoKey): Promise<CryptoKey>;
export async function importKey(key: JWK_oct): Promise<Uint8Array<ArrayBuffer>>;
export async function importKey(
  key: JWK_oct,
  options: {
    asCryptoKey: true;
    /** Algorithm to import the key as (e.g. `{ name: "AES-GCM", length: 256 }`). */
    algorithm: Parameters<typeof crypto.subtle.importKey>[2];
    /** Key usages for the resulting CryptoKey. */
    usage: KeyUsage[];
    /** Mark the key as extractable. Defaults to `false`. */
    extractable?: boolean;
  },
): Promise<CryptoKey>;
export async function importKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer> | string,
  options: {
    /** Algorithm hint. Required when `key.alg` is absent on an asymmetric JWK. */
    alg?: string;
    /** Reject on shape mismatch instead of silently importing. */
    expect?: "public" | "private";
  },
): Promise<CryptoKey | Uint8Array<ArrayBuffer>>;
export async function importKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer> | string,
  alg?: string,
): Promise<CryptoKey | Uint8Array<ArrayBuffer>>;
export async function importKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer> | string,
  algOrOptions?:
    | string
    | {
        asCryptoKey?: true;
        algorithm?: Parameters<typeof crypto.subtle.importKey>[2];
        usage?: KeyUsage[];
        extractable?: boolean;
        alg?: string;
        expect?: "public" | "private";
      },
): Promise<CryptoKey | Uint8Array<ArrayBuffer>> {
  const alg = typeof algOrOptions === "string" ? algOrOptions : (algOrOptions?.alg ?? undefined);
  const expect = typeof algOrOptions === "object" ? (algOrOptions.expect ?? undefined) : undefined;

  if (typeof key === "string") {
    key = textEncoder.encode(key);
  }

  if (key instanceof Uint8Array) {
    return key;
  }

  if (isCryptoKey(key)) {
    assertIntentOnCryptoKey(key, expect);
    return key;
  }

  if (isJWK(key)) {
    if ("k" in key && typeof key.k === "string") {
      const rawBytes = base64UrlDecode(key.k as string, false);
      if (typeof algOrOptions === "object" && algOrOptions.asCryptoKey) {
        const { algorithm, usage, extractable = false } = algOrOptions;
        if (!algorithm || !usage) {
          throw new JWTError(
            "asCryptoKey option requires `algorithm` and `usage` to be provided.",
            "ERR_JWK_INVALID",
          );
        }
        return crypto.subtle.importKey("raw", rawBytes, algorithm, extractable, usage);
      }
      return rawBytes;
    } else {
      if (!key.alg && !alg) {
        throw new JWTError(
          "Algorithm must be provided when importing non-oct JWK",
          "ERR_JWK_INVALID",
        );
      }
      assertIntentOnJWK(key, expect);
      const effectiveAlg = (key.alg || alg)!;
      const cacheKey = expect ? `${effectiveAlg}:${expect}` : effectiveAlg;
      if (_activeCache) {
        const cached = _activeCache.get(key, cacheKey);
        if (cached) return cached;
      }
      const cryptoKey = await jwkTokey(key.alg ? key : { ...key, alg });
      if (_activeCache) _activeCache.set(key, cacheKey, cryptoKey);
      return cryptoKey;
    }
  }

  // This should be unreachable
  throw new JWTError("Invalid key type provided to importKey", "ERR_JWK_INVALID");
}

function assertIntentOnJWK(jwk: JWK, expect: "public" | "private" | undefined): void {
  if (expect === undefined || jwk.kty === "oct") return;
  const hasPrivateScalar = "d" in jwk && typeof (jwk as { d?: unknown }).d === "string";
  if (expect === "public" && hasPrivateScalar) {
    throw new JWTError(
      "Private JWK passed where a public key is expected. Strip `d` (and CRT fields on RSA) before import.",
      "ERR_JWK_INVALID",
    );
  }
  if (expect === "private" && !hasPrivateScalar) {
    throw new JWTError("Public JWK passed where a private key is expected.", "ERR_JWK_INVALID");
  }
}

function assertIntentOnCryptoKey(key: CryptoKey, expect: "public" | "private" | undefined): void {
  if (expect === undefined || key.type === "secret") return;
  if (expect === "public" && key.type === "private") {
    throw new JWTError(
      "Private CryptoKey passed where a public key is expected.",
      "ERR_JWK_INVALID",
    );
  }
  if (expect === "private" && key.type === "public") {
    throw new JWTError(
      "Public CryptoKey passed where a private key is expected.",
      "ERR_JWK_INVALID",
    );
  }
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
  jwkParams?: Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">,
): Promise<T> {
  const exportedJwk = await keyToJWK<T>(key);
  if (jwkParams) {
    return { ...exportedJwk, ...sanitizeObject(jwkParams) };
  }
  return exportedJwk;
}

async function resolveWrappingKey(
  alg: KeyManagementAlgorithm,
  key: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  expect?: "public" | "private",
): Promise<CryptoKey | Uint8Array<ArrayBuffer>> {
  if (alg.startsWith("PBES2") && (typeof key === "string" || key instanceof Uint8Array)) {
    return typeof key === "string" ? textEncoder.encode(key) : key;
  }
  if (typeof key === "string") {
    throw new TypeError(`Key must be CryptoKey, JWK, or Uint8Array for ${alg}`);
  }
  if (expect !== undefined) {
    return importKey(key as any, { alg, expect });
  }
  return importKey(key as any, alg);
}

/**
 * Wraps a Content Encryption Key (CEK) using the specified algorithm and wrapping key.
 *
 * The return shape is narrowed by `alg` — see {@link WrapKeyResult}.
 *
 * @param alg The JWA key management algorithm (e.g., "A128KW", "RSA-OAEP", "PBES2-HS256+A128KW").
 * @param keyToWrap The key to be wrapped (CEK), typically a symmetric key as Uint8Array or CryptoKey.
 * @param wrappingKey The key used to wrap the CEK (CryptoKey, JWK, or password string/Uint8Array for PBES2).
 * @param options Additional options required by certain algorithms (e.g., p2s, p2c for PBES2).
 * @returns A Promise resolving to an alg-specific {@link WrapKeyResult}.
 */
export async function wrapKey<TAlg extends KeyManagementAlgorithm>(
  alg: TAlg,
  keyToWrap: CryptoKey | Uint8Array<ArrayBuffer>,
  wrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options?: WrapKeyOptions,
): Promise<WrapKeyResult<TAlg>>;
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

  const importedWrappingKey = await resolveWrappingKey(alg, wrappingKey, "public");

  switch (alg) {
    case "dir": {
      // Direct encryption: the provided key IS the CEK — nothing to wrap.
      // The JWE Encrypted Key field is empty per RFC 7516 §4.5.
      return { encryptedKey: new Uint8Array(0) };
    }

    case "A128KW":
    case "A192KW":
    case "A256KW": {
      const encryptedKey = await aesKwWrap(alg, importedWrappingKey, cekBytes);
      return { encryptedKey };
    }

    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      const { p2s, p2c } = options;
      if (!p2s || typeof p2c !== "number") {
        throw new JWTError(
          "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
          "ERR_JWE_INVALID",
        );
      }
      return pbes2Wrap(alg, importedWrappingKey, cekBytes, p2c, p2s);
    }

    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      const { encryptedKey, iv, tag } = await gcmkwEncrypt(
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
      const encryptedKey = await encryptRSAES(alg, importedWrappingKey as CryptoKey, cekBytes);
      return { encryptedKey };
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!(importedWrappingKey instanceof CryptoKey)) {
        throw new TypeError(
          "ECDH-ES requires the wrapping key to be a CryptoKey (recipient's public key)",
        );
      }
      if (!isECDHKeyAllowed(importedWrappingKey)) {
        throw new JWTError(
          "ECDH with the provided key is not allowed or not supported",
          "ERR_JWK_INVALID",
        );
      }

      const apu = options.ecdh?.partyUInfo ?? new Uint8Array(0);
      const apv = options.ecdh?.partyVInfo ?? new Uint8Array(0);

      const { ephemeralPrivateKey, epkJwk } = await resolveECDHEphemeralPair(
        importedWrappingKey,
        options.ecdh?.ephemeralKey,
      );

      const infoAlg =
        alg === "ECDH-ES"
          ? (() => {
              if (!options.ecdh?.enc) {
                throw new JWTError(
                  "ECDH-ES direct key agreement requires options.ecdh.enc (the target content encryption algorithm)",
                  "ERR_JWK_INVALID",
                );
              }
              return options.ecdh.enc;
            })()
          : alg;

      const keyLength =
        alg === "ECDH-ES" ? bitLengthCEK(infoAlg) : Number.parseInt(alg.slice(-5, -2), 10);

      const sharedSecret = await deriveECDHESKey(
        importedWrappingKey,
        ephemeralPrivateKey,
        infoAlg,
        keyLength,
        apu,
        apv,
      );

      const wrapResult: WrapKeyResult<JWK_ECDH_ES> = {
        encryptedKey: new Uint8Array(0),
        epk: epkJwk,
      };
      if (apu.length > 0) wrapResult.apu = base64UrlEncode(apu);
      if (apv.length > 0) wrapResult.apv = base64UrlEncode(apv);

      if (alg === "ECDH-ES") {
        // Direct key agreement: derived secret is the CEK; no encrypted key.
        return wrapResult;
      }

      // Key agreement with wrapping: AES-KW the caller-supplied CEK.
      const kwAlg = alg.slice(-6);
      wrapResult.encryptedKey = await aesKwWrap(kwAlg, sharedSecret, cekBytes);
      return wrapResult;
    }

    default: {
      throw new JWTError(`Unsupported key wrapping algorithm: ${alg}`, "ERR_JWK_UNSUPPORTED");
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
export async function unwrapKey(
  alg: KeyManagementAlgorithm,
  wrappedKey: Uint8Array<ArrayBuffer>,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: UnwrapKeyOptions & { format: "raw" },
): Promise<Uint8Array<ArrayBuffer>>;
export async function unwrapKey(
  alg: KeyManagementAlgorithm,
  wrappedKey: Uint8Array<ArrayBuffer>,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options?: UnwrapKeyOptions & { format?: "cryptokey" },
): Promise<CryptoKey>;
export async function unwrapKey(
  alg: KeyManagementAlgorithm,
  wrappedKey: Uint8Array<ArrayBuffer>,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: UnwrapKeyOptions,
): Promise<CryptoKey | Uint8Array<ArrayBuffer>>;
export async function unwrapKey(
  alg: KeyManagementAlgorithm,
  wrappedKey: Uint8Array<ArrayBuffer>,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: UnwrapKeyOptions = {},
): Promise<CryptoKey | Uint8Array<ArrayBuffer>> {
  const returnRaw = options.format === "raw";
  const defaultExtractable = options.extractable !== false; // Default true

  const importedUnwrappingKey = await resolveWrappingKey(alg, unwrappingKey, "private");

  let unwrappedCekBytes: Uint8Array<ArrayBuffer>;

  switch (alg) {
    case "dir": {
      // Direct encryption: the provided key IS the CEK — nothing to unwrap.
      if (importedUnwrappingKey instanceof Uint8Array) {
        unwrappedCekBytes = importedUnwrappingKey;
      } else {
        if (!returnRaw) {
          return importedUnwrappingKey as CryptoKey;
        }
        unwrappedCekBytes = new Uint8Array(
          await crypto.subtle.exportKey("raw", importedUnwrappingKey as CryptoKey),
        );
      }
      break;
    }

    case "A128KW":
    case "A192KW":
    case "A256KW": {
      unwrappedCekBytes = await aesKwUnwrap(alg, importedUnwrappingKey, wrappedKey);
      break;
    }

    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      const { p2s, p2c, minIterations, maxIterations } = options;
      if (!p2s || typeof p2c !== "number") {
        throw new JWTError(
          "PBES2 requires 'p2s' (salt) and 'p2c' (count) options",
          "ERR_JWE_INVALID",
        );
      }
      const p2sBytes = typeof p2s === "string" ? base64UrlDecode(p2s, false) : p2s;
      unwrappedCekBytes = await pbes2Unwrap(
        alg,
        importedUnwrappingKey,
        wrappedKey,
        p2c,
        p2sBytes,
        minIterations,
        maxIterations,
      );
      break;
    }

    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      if (!options.iv || !options.tag) {
        throw new JWTError(
          "AES-GCMKW requires 'iv' and 'tag' options for unwrapping",
          "ERR_JWE_INVALID",
        );
      }
      const ivBytes =
        typeof options.iv === "string" ? base64UrlDecode(options.iv, false) : options.iv;
      const tagBytes =
        typeof options.tag === "string" ? base64UrlDecode(options.tag, false) : options.tag;
      unwrappedCekBytes = await gcmkwDecrypt(
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
        throw new TypeError("RSA-OAEP requires the unwrapping key to be provided as a CryptoKey");
      }

      unwrappedCekBytes = await decryptRSAES(alg, importedUnwrappingKey, wrappedKey);

      if (returnRaw) {
        break;
      }

      const inferredAlgorithm =
        options.unwrappedKeyAlgorithm ||
        inferAesImportAlgorithm(options.enc, unwrappedCekBytes.length);

      if (!inferredAlgorithm) {
        throw new JWTError(
          'Unable to infer algorithm for RSA-OAEP unwrapped key. Provide "unwrappedKeyAlgorithm" in options.',
          "ERR_JWE_INVALID",
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
        throw new JWTError(
          "ECDH-ES requires 'epk' (Ephemeral Public Key) option",
          "ERR_JWE_INVALID",
        );
      }
      if (!(importedUnwrappingKey instanceof CryptoKey)) {
        throw new TypeError("ECDH-ES requires the unwrapping key to be a CryptoKey");
      }

      if (!isECDHKeyAllowed(importedUnwrappingKey)) {
        throw new JWTError(
          "ECDH with the provided key is not allowed or not supported",
          "ERR_JWK_INVALID",
        );
      }

      const epkCandidate =
        options.epk instanceof CryptoKey
          ? options.epk
          : ((await normalizeKey(options.epk, alg)) as CryptoKey);

      if (!(epkCandidate instanceof CryptoKey)) {
        throw new JWTError("Failed to normalize ECDH ephemeral public key", "ERR_JWK_INVALID");
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
        throw new JWTError(
          "ECDH-ES requires content encryption algorithm ('enc') to derive the shared secret",
          "ERR_JWE_INVALID",
        );
      }

      const keyLength =
        alg === "ECDH-ES" ? bitLengthCEK(infoAlg) : Number.parseInt(alg.slice(-5, -2), 10);

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
          throw new JWTError(
            "ECDH-ES key agreement with key wrapping requires an encrypted key",
            "ERR_JWE_INVALID",
          );
        }
        unwrappedCekBytes = await aesKwUnwrap(kwAlg, sharedSecret, wrappedKey);
      }

      break;
    }

    default: {
      throw new JWTError(`Unsupported key unwrapping algorithm: ${alg}`, "ERR_JWK_UNSUPPORTED");
    }
  }

  // If returning bytes, return them now (applies to AES-KW/PBES2/AES-GCMKW paths)
  if (returnRaw) {
    return unwrappedCekBytes;
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
 * Imports a PEM-encoded key and returns it as a JWK.
 *
 * The PEM type is inferred from the `-----BEGIN <X>-----` label:
 * - `PRIVATE KEY` → PKCS#8 private key (RFC 5208)
 * - `PUBLIC KEY`  → SubjectPublicKeyInfo public key (RFC 5280 §4.1.2.7)
 * - `CERTIFICATE` → X.509 certificate; its SPKI is extracted into the JWK and all cert metadata
 *                   (issuer, validity, extensions) is discarded — a JWK cannot represent it
 *
 * A caller can override the inference via `options.pemType`; the underlying label assertion
 * still runs, so a mismatched override (e.g. `pemType: "pkcs8"` on a SPKI body) throws
 * `ERR_JWK_INVALID` before any crypto work.
 *
 * @param pem The PEM-encoded string.
 * @param alg The JWA algorithm identifier. Required for `crypto.subtle.importKey` to understand
 *            the key's intended algorithm and for setting the `alg` field on the resulting JWK.
 * @param options
 *   - `pemType?` — explicit PEM type; inferred from the label when omitted.
 *   - `extractable?` — forwarded to `crypto.subtle.importKey`. Defaults to `false` for private
 *     keys and `true` for public keys.
 *   - `jwkParams?` — additional JWK properties merged into the result (e.g. `kid`, `use`).
 *     `alg`, `kty`, `key_ops`, and `ext` are reserved and cannot be overridden here.
 * @throws `JWTError("ERR_JWK_INVALID")` if the PEM type cannot be inferred (no recognised label
 *         and no `options.pemType`), or if the label does not match the requested/inferred type.
 * @throws `JWTError("ERR_JWK_UNSUPPORTED")` if `options.pemType` is a value outside the supported set.
 *
 * @example
 * ```ts
 * // Inferred — label on the PEM drives selection.
 * const jwk = await importPEM(pemString, "RS256", { jwkParams: { kid: "rsa-1" } });
 *
 * // Explicit override.
 * const jwk2 = await importPEM(pemString, "RS256", { pemType: "x509" });
 * ```
 */
export async function importPEM<T extends JWK>(
  pem: string,
  alg: JWKPEMAlgorithm,
  options?: {
    /** PEM type. Inferred from the PEM label when omitted. */
    pemType?: "pkcs8" | "spki" | "x509";
    /** Passed to `crypto.subtle.importKey`. Defaults to `false` for private keys, `true` otherwise. */
    extractable?: boolean;
    /** Additional JWK properties merged into the exported key (e.g. `kid`). */
    jwkParams?: Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">;
  },
): Promise<T> {
  const extractable = options?.extractable !== false;
  const pemType = options?.pemType ?? inferPEMType(pem);

  if (!pemType) {
    throw new JWTError(
      'Cannot infer PEM type from the input; pass "options.pemType" explicitly.',
      "ERR_JWK_INVALID",
    );
  }

  let cryptoKey: CryptoKey;
  switch (pemType) {
    case "pkcs8": {
      cryptoKey = await fromPKCS8(pem, alg, { extractable });
      break;
    }
    case "spki": {
      cryptoKey = await fromSPKI(pem, alg, { extractable });
      break;
    }
    case "x509": {
      cryptoKey = await fromX509(pem, alg, { extractable });
      break;
    }
    default: {
      throw new JWTError(`Unsupported PEM type: ${pemType}`, "ERR_JWK_UNSUPPORTED");
    }
  }

  const jwk = await exportKey(cryptoKey, options?.jwkParams);
  return { ...jwk, alg } as T;
}

/**
 * @deprecated Use {@link importPEM} instead. `pemType` has moved into the options object and
 * is now inferred from the PEM label by default.
 */
export async function importFromPEM<T extends JWK>(
  pem: string,
  pemType: "pkcs8" | "spki" | "x509",
  alg: JWKPEMAlgorithm,
  options?: {
    extractable?: boolean;
    jwkParams?: Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">;
  },
): Promise<T> {
  return importPEM<T>(pem, alg, { pemType, ...options });
}

/**
 * Exports a JWK to a PEM-encoded string.
 *
 * The PEM format is inferred from the JWK shape:
 * - JWK with `d` (private component) → PKCS#8 (`-----BEGIN PRIVATE KEY-----`)
 * - JWK without `d` → SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`)
 *
 * X.509 certificate export is intentionally not supported: a certificate carries metadata
 * (subject/issuer DNs, validity window, extensions) and a CA signature that a JWK cannot provide.
 * Producing a cert is a CA operation, not a key-format conversion.
 *
 * Symmetric `oct` JWKs cannot be exported to PEM — PKCS#8/SPKI are asymmetric-key formats.
 *
 * @param jwk The JWK to export. Must not be `kty: "oct"`.
 * @param options
 *   - `pemFormat?` — force the output format. Inferred from the JWK shape when omitted.
 *   - `alg?` — algorithm hint used only when `jwk.alg` is absent (both `kty: "RSA"` / `"EC"` /
 *     `"OKP"` JWKs need an algorithm to be round-tripped through `crypto.subtle.importKey`).
 * @throws `JWTError("ERR_JWK_UNSUPPORTED")` for `oct` JWKs, or an unrecognised `pemFormat`.
 * @throws `JWTError("ERR_JWK_INVALID")` if the JWK requires an `alg` hint that was not supplied,
 *         or if `pemFormat` is forced to a value incompatible with the JWK's public/private shape.
 *
 * @example
 * ```ts
 * // Inferred — private JWKs become PKCS#8, public JWKs become SPKI.
 * const pem = await exportPEM(jwk);
 *
 * // Override (will throw if incompatible with the JWK shape).
 * const spki = await exportPEM(jwk, { pemFormat: "spki" });
 *
 * // JWK without `alg` — provide a hint.
 * const pem2 = await exportPEM(rawJwk, { alg: "RS256" });
 * ```
 */
export async function exportPEM(
  jwk: JWK,
  options?: {
    /** PEM format. Inferred from the JWK shape when omitted. */
    pemFormat?: "pkcs8" | "spki";
    /** Algorithm hint used when `jwk.alg` is absent. */
    alg?: JWKPEMAlgorithm;
  },
): Promise<string> {
  if (jwk.kty === "oct") {
    throw new JWTError(
      "Octet (symmetric) JWKs (kty: 'oct') cannot be exported to PKCS8 or SPKI PEM formats.",
      "ERR_JWK_UNSUPPORTED",
    );
  }

  const effectiveAlg = jwk.alg || options?.alg;
  if (!effectiveAlg && (jwk.kty === "RSA" || jwk.kty === "EC" || jwk.kty === "OKP")) {
    throw new JWTError(
      "Algorithm (alg) must be provided in the JWK or via options for converting this JWK type to a CryptoKey.",
      "ERR_JWK_INVALID",
    );
  }

  const pemFormat = options?.pemFormat ?? ("d" in jwk ? "pkcs8" : "spki");

  // Intermediate CryptoKey must be extractable to be exported back to PEM.
  const cryptoKeyCandidate = await importKey(
    { ...jwk, ext: true },
    { alg: effectiveAlg, expect: pemFormat === "pkcs8" ? "private" : "public" },
  );

  if (!isCryptoKey(cryptoKeyCandidate)) {
    throw new JWTError(
      "Failed to convert JWK to a CryptoKey instance suitable for PEM export.",
      "ERR_JWK_INVALID",
    );
  }
  const cryptoKey = cryptoKeyCandidate;

  switch (pemFormat) {
    case "pkcs8": {
      if (cryptoKey.type !== "private") {
        throw new JWTError(
          `Only 'private' type CryptoKeys can be exported to PKCS8 PEM format. Key type is '${cryptoKey.type}'.`,
          "ERR_JWK_INVALID",
        );
      }
      return toPKCS8(cryptoKey);
    }
    case "spki": {
      if (cryptoKey.type !== "public") {
        throw new JWTError(
          `Only 'public' type CryptoKeys can be exported to SPKI PEM format. Key type is '${cryptoKey.type}'.`,
          "ERR_JWK_INVALID",
        );
      }
      return toSPKI(cryptoKey);
    }
    default: {
      throw new JWTError(`Unsupported PEM format: ${pemFormat}`, "ERR_JWK_UNSUPPORTED");
    }
  }
}

/**
 * @deprecated Use {@link exportPEM} instead. `pemFormat` has moved into the options object and
 * is now inferred from the JWK shape by default. The `algForCryptoKeyImport` parameter has
 * been renamed to `options.alg`.
 */
export async function exportToPEM(
  jwk: JWK,
  pemFormat: "pkcs8" | "spki",
  algForCryptoKeyImport?: JWKPEMAlgorithm,
): Promise<string> {
  return exportPEM(jwk, { pemFormat, alg: algForCryptoKeyImport });
}

function inferPEMType(pem: string): "pkcs8" | "spki" | "x509" | undefined {
  if (pem.includes("-----BEGIN PRIVATE KEY-----")) return "pkcs8";
  if (pem.includes("-----BEGIN PUBLIC KEY-----")) return "spki";
  if (pem.includes("-----BEGIN CERTIFICATE-----")) return "x509";
  return undefined;
}

/**
 * Derives a shared secret using ECDH-ES key agreement (RFC 7518 §4.6).
 *
 * Performs an Elliptic Curve Diffie-Hellman Ephemeral-Static key derivation
 * followed by a Concat KDF (NIST SP 800-56A) to produce key material of the
 * requested length. The result can be used directly as a CEK (for `ECDH-ES`
 * direct key agreement) or as a KEK to wrap a separately generated CEK (for
 * `ECDH-ES+A*KW`).
 *
 * For multi-recipient JWE, call this once per recipient with their public key
 * and a fresh ephemeral private key, then wrap the shared CEK with the derived
 * material using {@link wrapKey}.
 *
 * @param publicKey The recipient's static public key (or the sender's
 *   ephemeral public key on the decryption side).
 * @param privateKey The sender's ephemeral private key (or the recipient's
 *   static private key on the decryption side).
 * @param alg The algorithm identifier used as the `AlgorithmID` in the
 *   concat KDF info structure. Pass a {@link JWK_ECDH_ES} variant
 *   (e.g. `"ECDH-ES+A128KW"`) or a {@link ContentEncryptionAlgorithm}
 *   (e.g. `"A256GCM"`) for direct key agreement.
 * @param options Optional overrides for key length and party info.
 */
export async function deriveSharedSecret(
  publicKey: CryptoKey | JWK_EC_Public,
  privateKey: CryptoKey | JWK_EC_Private,
  alg: JWK_ECDH_ES | ContentEncryptionAlgorithm,
  options?: {
    /** Override the derived key length in bits. Defaults to the standard length for `alg`. */
    keyLength?: number;
    /** Agreement PartyUInfo (apu). */
    partyUInfo?: Uint8Array<ArrayBuffer>;
    /** Agreement PartyVInfo (apv). */
    partyVInfo?: Uint8Array<ArrayBuffer>;
  },
): Promise<Uint8Array<ArrayBuffer>> {
  const pubCryptoKey = isCryptoKey(publicKey)
    ? publicKey
    : ((await importKey(publicKey as JWK, { alg: "ECDH-ES", expect: "public" })) as CryptoKey);
  const privCryptoKey = isCryptoKey(privateKey)
    ? privateKey
    : ((await importKey(privateKey as JWK, { alg: "ECDH-ES", expect: "private" })) as CryptoKey);

  let keyLength: number;
  if (options?.keyLength !== undefined) {
    keyLength = options.keyLength;
  } else if (alg === "ECDH-ES") {
    throw new JWTError(
      'deriveSharedSecret with alg "ECDH-ES" requires an explicit keyLength in options',
      "ERR_JWK_INVALID",
    );
  } else if ((alg as string).startsWith("ECDH-ES+")) {
    keyLength = Number.parseInt((alg as string).slice(-5, -2), 10);
  } else {
    keyLength = bitLengthCEK(alg);
  }

  return deriveECDHESKey(
    pubCryptoKey,
    privCryptoKey,
    alg,
    keyLength,
    options?.partyUInfo ?? new Uint8Array(0),
    options?.partyVInfo ?? new Uint8Array(0),
  );
}

/**
 * @deprecated For set queries, use {@link getJWKsFromSet} which returns all
 * matching keys as an array. This function remains available for internal
 * single-key resolution by `kid` or JOSE header (used by `verify` and `decrypt`).
 *
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
  kidOrProtectedHeader: string | (JoseHeaderParameters & { alg?: string; kty?: string }),
): JWK {
  if (!jwkSet || !isJWKSet(jwkSet)) {
    throw new JWTError("Invalid JWK Set provided", "ERR_JWK_INVALID");
  }

  if (typeof kidOrProtectedHeader === "string") {
    // If kidOrProtectedHeader is a string, treat it as a kid
    const kid = kidOrProtectedHeader;
    const selectedKey = jwkSet.keys.find((k: JWK) => k.kid === kid);
    if (!selectedKey) {
      throw new JWTError(`No key found in JWK Set with kid "${kid}".`, "ERR_JWK_KEY_NOT_FOUND");
    }
    return selectedKey;
  } else if (typeof kidOrProtectedHeader === "object") {
    // If kidOrProtectedHeader is an object, treat it as a protected header

    const { kid, alg, kty } = kidOrProtectedHeader;

    if (!kid) {
      if (jwkSet.keys.length === 1) {
        return jwkSet.keys[0]!;
      }
      throw new JWTError(
        "JWS Protected Header is missing 'kid' (Key ID) and the JWK Set contains multiple keys. " +
          "Add a 'kid' parameter to the token header and to the matching JWK to enable automatic selection.",
        "ERR_JWK_KEY_NOT_FOUND",
      );
    }

    const selectedKey = jwkSet.keys.find((k: JWK) => {
      return k.kid === kid && (!alg || k.alg === alg) && (!kty || k.kty === kty);
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
      throw new JWTError(errorMessage, "ERR_JWK_KEY_NOT_FOUND");
    }

    return selectedKey;
  }

  throw new TypeError(
    "`kidOrProtectedHeader` must be a string (kid) or an object (JOSE Protected Header).",
  );
}

/**
 * Returns all JWKs from a JWK Set, optionally narrowed by a predicate.
 *
 * Useful for multi-key verification retry, key rotation tooling, and
 * constructing multi-recipient JWE JSON Serialization structures.
 *
 * @param jwkSet The JWK Set to search.
 * @param filter Optional predicate `(jwk: JWK) => boolean`. Returns all keys when omitted.
 * @returns An array of matching JWKs.
 */
export function getJWKsFromSet(jwkSet: JWKSet, filter?: (jwk: JWK) => boolean): JWK[] {
  if (!jwkSet || !isJWKSet(jwkSet)) {
    throw new JWTError("Invalid JWK Set provided", "ERR_JWK_INVALID");
  }

  if (!filter) {
    return [...jwkSet.keys];
  }

  return jwkSet.keys.filter(filter);
}

function getGenerateKeyParams(
  alg: string,
  options?: Omit<GenerateKeyOptions, "toJWK">,
): {
  algorithm: AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams;
  keyUsages: KeyUsage[];
} {
  let algorithm: AlgorithmIdentifier | AesKeyAlgorithm | RsaHashedKeyGenParams | EcKeyGenParams;
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
        publicExponent: options?.publicExponent ?? new Uint8Array([0x01, 0x00, 0x01]),
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
        publicExponent: options?.publicExponent ?? new Uint8Array([0x01, 0x00, 0x01]),
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
        publicExponent: options?.publicExponent ?? new Uint8Array([0x01, 0x00, 0x01]),
        hash: `SHA-${Number.parseInt(alg.slice(9), 10) || 1}`,
      };
      keyUsages = defaultKeyUsage ?? ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
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
    case "A256GCM":
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      // If it ends in KW, strip it to get the length
      const baseAlg = alg.replace("KW", "");
      const length = Number.parseInt(baseAlg.slice(1, 4), 10);
      algorithm = { name: "AES-GCM", length };

      // If it's explicitly KW, default to wrapping usages, otherwise encrypt/decrypt
      keyUsages =
        defaultKeyUsage ?? (alg.endsWith("KW") ? ["wrapKey", "unwrapKey"] : ["encrypt", "decrypt"]);
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
          throw new JWTError(
            "Unsupported namedCurve provided. Supported values are: Ed25519 and Ed448",
            "ERR_JWK_UNSUPPORTED",
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
          throw new JWTError(
            "Unsupported namedCurve provided. Supported values are: P-256, P-384, P-521 and X25519",
            "ERR_JWK_UNSUPPORTED",
          );
        }
      }
      break;
    }

    default: {
      throw new JWTError(
        `Unsupported or invalid algorithm for key generation: ${alg}`,
        "ERR_JWK_UNSUPPORTED",
      );
    }
  }

  return { algorithm, keyUsages };
}

async function resolveECDHEphemeralPair(
  recipientPublicKey: CryptoKey,
  ephemeralKeyInput: NonNullable<WrapKeyOptions["ecdh"]>["ephemeralKey"],
): Promise<{ ephemeralPrivateKey: CryptoKey; epkJwk: JWK_EC_Public }> {
  if (!ephemeralKeyInput) {
    const generated = await crypto.subtle.generateKey(
      recipientPublicKey.algorithm as EcKeyAlgorithm,
      true,
      ["deriveBits"],
    );
    const rawJwk = (await keyToJWK(generated.publicKey)) as JWK_EC;
    return { ephemeralPrivateKey: generated.privateKey, epkJwk: stripPrivateJwkFields(rawJwk) };
  }

  if (isCryptoKeyPair(ephemeralKeyInput)) {
    const rawJwk = (await keyToJWK(ephemeralKeyInput.publicKey)) as JWK_EC;
    return {
      ephemeralPrivateKey: ephemeralKeyInput.privateKey,
      epkJwk: stripPrivateJwkFields(rawJwk),
    };
  }

  if (
    typeof ephemeralKeyInput === "object" &&
    "publicKey" in ephemeralKeyInput &&
    "privateKey" in ephemeralKeyInput
  ) {
    const { publicKey, privateKey } = ephemeralKeyInput as {
      publicKey: CryptoKey | JWK_EC_Public;
      privateKey: CryptoKey | JWK_EC_Private;
    };
    const privCryptoKey = isCryptoKey(privateKey)
      ? privateKey
      : ((await importKey(privateKey as JWK, {
          alg: "ECDH-ES",
          expect: "private",
        })) as CryptoKey);
    const epkJwk = isCryptoKey(publicKey)
      ? stripPrivateJwkFields((await keyToJWK(publicKey)) as JWK_EC)
      : stripPrivateJwkFields(publicKey as JWK_EC);
    return { ephemeralPrivateKey: privCryptoKey, epkJwk };
  }

  if (isCryptoKey(ephemeralKeyInput)) {
    if (ephemeralKeyInput.type !== "private") {
      throw new JWTError("ECDH-ES ephemeral CryptoKey must be a private key", "ERR_JWK_INVALID");
    }
    return {
      ephemeralPrivateKey: ephemeralKeyInput,
      epkJwk: stripPrivateJwkFields((await keyToJWK(ephemeralKeyInput)) as JWK_EC),
    };
  }

  // JWK_EC_Private
  if (isJWK(ephemeralKeyInput) && "d" in ephemeralKeyInput) {
    const privCryptoKey = (await importKey(ephemeralKeyInput as JWK, {
      alg: "ECDH-ES",
      expect: "private",
    })) as CryptoKey;
    return {
      ephemeralPrivateKey: privCryptoKey,
      epkJwk: stripPrivateJwkFields(ephemeralKeyInput as JWK_EC),
    };
  }

  throw new JWTError("Unsupported ECDH-ES ephemeral key material", "ERR_JWK_INVALID");
}

function stripPrivateJwkFields(jwk: JWK_EC): JWK_EC_Public {
  const { d: _d, ...pub } = jwk as JWK_EC_Private;
  return pub as JWK_EC_Public;
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
