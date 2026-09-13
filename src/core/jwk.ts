import { secureRandomBytes } from "unsecure/random";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import { base64UrlStringify } from "./utils/base64";
import { assertDirectKeyRole, decodeSegment, stringKeyError } from "./_internal";

import type {
  JWK,
  JWKSet,
  JWK_Pair,
  JWK_oct,
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
  WrappingKeyFor,
  UnwrapKeyOptions,
  UnwrapKeyResult,
  UnwrappingKeyFor,
} from "./types";
import { isCryptoKey, isCryptoKeyPair, isJWK, isJWKSet } from "./utils";
import { isContentEncryptionAlgorithm } from "./utils/algorithms";
import { JWTError } from "./error";
import {
  jwkTokey,
  keyToJWK,
  assertPBES2Params,
  bitLengthCEK,
  assertOctKeyLength,
  deriveKeyPBES2,
  pbes2Wrap,
  pbes2Unwrap,
  deriveECDHESKey,
  isECDHKeyAllowed,
  normalizeEpk,
  bitLengthIV,
  bitLengthTag,
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
  thumbprint,
} from "./_crypto";

export type * from "./types/jwk";
export { thumbprint };
export type { ThumbprintHash } from "./_crypto";
export {
  type UnsecureErrorCode,
  JWTError,
  isJWTError,
  UnsecureError,
  isUnsecureError,
} from "./error";
export type { JWTErrorCode, KnownJWTErrorCode, JWTErrorCauseMap } from "./error";

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
 *     Ignored when `toJWK` is set — the JWK output requires exporting the intermediate key.
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
  // The JWK output requires exporting the intermediate key, so `toJWK` forces extractable.
  const defaultExtractable = exportToJWK || options.extractable !== false;

  // AES-CBC+HMAC composite material isn't directly importable via Web Crypto,
  // so we generate and export raw bytes.
  if (alg === "A128CBC-HS256" || alg === "A192CBC-HS384" || alg === "A256CBC-HS512") {
    const keyLength = bitLengthCEK(alg);
    const keyBytes = secureRandomBytes(keyLength >> 3);

    if (exportToJWK) {
      // The composite bytes never pass through WebCrypto, so the members its
      // JWK export would have written are stamped here instead — without them
      // the key describes no algorithm and infers no role.
      const jwk = await keyToJWK<JWK_oct>(keyBytes);
      return withThumbprintKid({
        ...jwk,
        alg,
        ext: true,
        key_ops: resolveKeyUsage(options.keyUsage, {
          allowed: CONTENT_ENCRYPTION_USAGES,
          fallback: ["encrypt", "decrypt"],
          alg,
        }),
      });
    }
    return keyBytes;
  }

  const { algorithm, keyUsages } = getGenerateKeyParams(alg, options);

  const key = await crypto.subtle.generateKey(algorithm, defaultExtractable, keyUsages);

  if (exportToJWK) {
    if (key instanceof CryptoKey) {
      // Force `alg`: Web Crypto's JWK export drops the `KW` suffix on AES-GCM key wrap algs.
      return withThumbprintKid({ ...(await exportKey(key)), alg });
    } else {
      const [pub, priv] = await Promise.all([exportKey(key.publicKey), exportKey(key.privateKey)]);
      // The thumbprint takes only the public members, so the pair shares one name.
      const kid = await thumbprint({ ...pub, alg } as JWK);
      return {
        privateKey: { ...priv, alg, kid },
        publicKey: { ...pub, alg, kid },
      } as JWK_Pair;
    }
  }

  return key;
}

/**
 * Generates a ready-to-use JWK (or JWK pair) for the specified algorithm.
 *
 * Always returns JWK form with a `kid` attached — auto-generated via
 * `crypto.randomUUID()` when not supplied. For a `CryptoKey` / `CryptoKeyPair`
 * result instead, use {@link generateKey}. PBES2 is not a key-generation
 * algorithm — use {@link deriveJWKFromPassword}.
 *
 * Composite AES-CBC+HMAC keys (`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`)
 * are serialised to a single `JWK_oct` and re-split internally on use.
 *
 * @param alg The JWA algorithm identifier (e.g. `"HS256"`, `"RS256"`, `"ES256"`,
 *            `"A128GCM"`, `"A256CBC-HS512"`). PBES2, `"dir"`, and `"none"` are
 *            not accepted.
 * @param options
 *   - `keyUsage?` — override the default usages derived from `alg`.
 *   - `modulusLength?` — RSA only; defaults to `2048`.
 *   - `publicExponent?` — RSA only; defaults to `0x010001`.
 *   - `namedCurve?` — EC and OKP only; defaults to `"P-256"` for EC and `"Ed25519"` for OKP.
 *   - JWK metadata (`kid`, `use`, `x5c`, `x5t`, `x5t#S256`, `x5u`) is merged onto the
 *     result. `alg`, `kty`, `key_ops`, and `ext` are managed by the library and cannot
 *     be overridden here.
 *
 * @example
 * ```ts
 * // HS256 → JWK_oct
 * const hmac = await generateJWK("HS256");
 *
 * // RS256 → { privateKey: JWK_RSA_Private; publicKey: JWK_RSA_Public }
 * const rsa = await generateJWK("RS256", { modulusLength: 2048, kid: "rsa-1" });
 *
 * // ES256 with explicit metadata
 * const { privateKey, publicKey } = await generateJWK("ES256", { kid: "ec-1", use: "sig" });
 * ```
 */
export async function generateJWK<TAlg extends GenerateKeyAlgorithm>(
  alg: TAlg,
  options?: GenerateJWKOptions & Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">,
): Promise<GenerateJWKReturn<TAlg>> {
  // The generation options are separated from the JWK metadata by name, so an
  // option can never leak into the emitted key as a member of its own.
  const {
    keyUsage,
    modulusLength,
    publicExponent,
    namedCurve,
    extractable: _extractable,
    toJWK: _toJWK,
    ...jwkParams
  } = (options ?? {}) as GenerateJWKOptions &
    Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext"> & {
      extractable?: boolean;
      toJWK?: boolean;
    };
  assertNoReservedJWKParams(jwkParams);
  const callerKid = typeof jwkParams.kid === "string" ? jwkParams.kid : undefined;

  const result = await generateKey(alg, {
    keyUsage,
    modulusLength,
    publicExponent,
    namedCurve,
    toJWK: true,
  });

  // `generateKey` already named the key by its thumbprint; a caller-supplied
  // `kid` replaces that name on both halves.
  const named = callerKid === undefined ? undefined : { kid: callerKid };
  if (result && typeof result === "object" && "privateKey" in result && "publicKey" in result) {
    const pair = result as { privateKey: JWK; publicKey: JWK };
    return {
      privateKey: { ...jwkParams, ...pair.privateKey, ...named },
      publicKey: { ...jwkParams, ...pair.publicKey, ...named },
    } as GenerateJWKReturn<TAlg>;
  }
  return { ...jwkParams, ...(result as JWK), ...named } as GenerateJWKReturn<TAlg>;
}

/**
 * Derives a key from a password using PBKDF2 as specified by PBES2 algorithms.
 *
 * @param password The password to derive the key from (string or Uint8Array).
 * @param options
 *   - `alg` — the PBES2 algorithm identifier (e.g. `"PBES2-HS256+A128KW"`).
 *   - `salt` — PBKDF2 salt input (`p2s`). Must be at least 8 octets.
 *   - `iterations` — PBKDF2 iteration count (`p2c`). Must be a positive integer.
 *   - `keyUsage?` — defaults to `["wrapKey", "unwrapKey"]`.
 *   - `extractable?` — defaults to `false`. Ignored when `toJWK` is set.
 *   - `toJWK?` — return the derived key as a `JWK_oct` instead of a `CryptoKey`.
 * @returns A Promise resolving to the derived key (CryptoKey) or its JWK_oct representation.
 */
export async function deriveKeyFromPassword<TOptions extends DeriveKeyOptions>(
  password: string | Uint8Array<ArrayBuffer>,
  options: TOptions,
): Promise<DeriveKeyReturn<TOptions, TOptions["alg"]>>;
export async function deriveKeyFromPassword(
  password: string | Uint8Array<ArrayBuffer>,
  options: DeriveKeyOptions,
): Promise<CryptoKey | JWK_oct> {
  const { alg, salt, iterations, extractable, keyUsage } = options;
  const exportToJWK = options.toJWK !== undefined && options.toJWK !== false;

  const saltBytes = typeof salt === "string" ? textEncoder.encode(salt) : salt;
  if (!(saltBytes instanceof Uint8Array) || saltBytes.length < 8) {
    throw new JWTError("PBES2 Salt Input (salt) must be 8 or more octets", "ERR_JWE_INVALID");
  }
  if (typeof iterations !== "number" || iterations < 1) {
    throw new JWTError(
      "PBES2 Iteration Count (iterations) must be a positive integer",
      "ERR_JWE_INVALID",
    );
  }

  const passwordBytes = typeof password === "string" ? textEncoder.encode(password) : password;

  const derivedBytes = await deriveKeyPBES2(saltBytes, alg, iterations, passwordBytes);

  const wrappingAlg = alg.slice(-6);
  const defaultUsages: KeyUsage[] = ["wrapKey", "unwrapKey"];
  const finalUsages = keyUsage ?? defaultUsages;
  const finalExtractable = exportToJWK ? true : extractable === true;

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
 * Derives a `JWK_oct` from a password using PBKDF2 as specified by PBES2
 * (RFC 7518 §4.8). The resulting JWK's `alg` is the underlying AES-KW variant
 * (`A128KW` / `A192KW` / `A256KW`), ready to use with {@link wrapKey} /
 * {@link unwrapKey}.
 *
 * For a `CryptoKey` result without JWK metadata, use {@link deriveKeyFromPassword}.
 *
 * @param password The password to derive the key from (string or `Uint8Array`).
 * @param options
 *   - `alg` — the PBES2 algorithm identifier (e.g. `"PBES2-HS256+A128KW"`).
 *   - `salt` — PBKDF2 salt input (`p2s`). Must be at least 8 octets (RFC 7518 §4.8.1.1).
 *   - `iterations` — PBKDF2 iteration count (`p2c`). Must be a positive integer.
 *   - `keyUsage?` — defaults to `["wrapKey", "unwrapKey"]`.
 *   - JWK metadata (`kid`, `use`, `x5c`, `x5t`, `x5t#S256`, `x5u`) is merged onto the
 *     result. `alg`, `kty`, `key_ops`, and `ext` are managed by the library and cannot
 *     be overridden here.
 */
export async function deriveJWKFromPassword(
  password: string | Uint8Array<ArrayBuffer>,
  options: Omit<DeriveKeyOptions, "toJWK" | "extractable"> &
    Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">,
): Promise<JWK_oct> {
  const {
    alg,
    salt,
    iterations,
    keyUsage,
    extractable: _extractable,
    toJWK: _toJWK,
    ...jwkParams
  } = options as DeriveKeyOptions & Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">;
  assertNoReservedJWKParams(jwkParams);
  const result = await deriveKeyFromPassword(password, {
    alg,
    salt,
    iterations,
    keyUsage,
    toJWK: true,
  });
  const kid = typeof jwkParams.kid === "string" ? jwkParams.kid : await thumbprint(result);
  return { ...jwkParams, kid, ...result };
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
 * A cache shared across JWK objects keys on the key material itself — its
 * {@link thumbprint} — together with the algorithm it is imported under. A
 * `kid` is not a safe key: it is a label its publisher chooses, and two
 * different keys may carry the same one, so an entry stored under a `kid` can
 * serve the wrong key material. `get` and `set` may both return a promise.
 *
 * @example Use a thumbprint-keyed cache:
 * ```ts
 * const map = new Map<string, CryptoKey>();
 * configureJWKCache({
 *   get: async (jwk, alg) => map.get(`${await thumbprint(jwk)}:${alg}`),
 *   set: async (jwk, alg, key) => {
 *     map.set(`${await thumbprint(jwk)}:${alg}`, key);
 *   },
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
 * A `string` is not key material and throws `ERR_JWK_INVALID`: PEM text belongs in
 * {@link importPEM}, a shared secret in an `oct` JWK or a `Uint8Array`, and a password in
 * {@link deriveJWKFromPassword} or the PBES2 `alg` of a JWE.
 *
 * ### Which option applies to which key
 *
 * The overloads cannot express it, so the split is stated here:
 *
 * - `asCryptoKey` (with its `algorithm` and `usage`) applies only to an `oct` JWK — it is what
 *   turns the raw secret into a `CryptoKey` instead of the default `Uint8Array`.
 * - `expect` applies only to asymmetric key material; it is a no-op on `oct` JWKs and on
 *   `CryptoKey` instances of type `"secret"`.
 * - `alg` is required for an asymmetric JWK without its own `alg`, and optional elsewhere.
 * - `extractable` applies to asymmetric JWK imports; the `asCryptoKey` overload carries its own.
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
 *
 * ### Declared algorithm
 *
 * A JWK's `alg` is authoritative (RFC 7517 §4.4): asking for an operation under a
 * different algorithm throws `ERR_JWK_INVALID` rather than importing the key under
 * whichever of the two happens to win. The one exception is the JWE symmetric role
 * mapping — an `oct` JWK whose `alg` is a content encryption algorithm (`A*GCM`,
 * `A*CBC-HS*`) is the CEK `alg: "dir"` consumes, and decryption additionally
 * requires the token's `enc` to be that same algorithm.
 */
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
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer>,
  options: {
    /** Algorithm hint. Required when `key.alg` is absent on an asymmetric JWK. */
    alg?: string;
    /** Reject on shape mismatch instead of silently importing. */
    expect?: "public" | "private";
    /**
     * Import the key as extractable. Defaults to `false` for private key
     * material and `true` for public. A JWK's `ext: false` still lowers it.
     */
    extractable?: boolean;
  },
): Promise<CryptoKey | Uint8Array<ArrayBuffer>>;
export async function importKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer>,
  alg?: string,
): Promise<CryptoKey | Uint8Array<ArrayBuffer>>;
export async function importKey(
  key: CryptoKey | JWK | Uint8Array<ArrayBuffer>,
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
  const extractable =
    typeof algOrOptions === "object" && !algOrOptions.asCryptoKey
      ? algOrOptions.extractable
      : undefined;

  if (typeof key === "string") {
    throw stringKeyError();
  }

  if (key instanceof Uint8Array) {
    return key;
  }

  if (isCryptoKey(key)) {
    assertIntentOnCryptoKey(key, expect);
    return key;
  }

  if (isJWK(key)) {
    assertJWKAlgAuthority(key, alg);
    if ("k" in key && typeof key.k === "string") {
      const rawBytes = decodeSegment(key.k as string, { family: "JWK", what: '"k"' });
      assertOctKeyLength(rawBytes, alg ?? key.alg);
      if (typeof algOrOptions === "object" && algOrOptions.asCryptoKey) {
        const { algorithm, usage, extractable = false } = algOrOptions;
        if (!algorithm || !usage) {
          throw new JWTError(
            "asCryptoKey option requires `algorithm` and `usage` to be provided.",
            "ERR_JWK_INVALID",
          );
        }
        if (typeof algorithm === "object" && algorithm.name === "HMAC") {
          const hash = (algorithm as HmacImportParams).hash;
          const hashName = typeof hash === "string" ? hash : hash?.name;
          const minBytes = Number.parseInt(hashName?.slice(-3) ?? "", 10) / 8;
          if (minBytes && rawBytes.length < minBytes) {
            throw new JWTError(
              `HMAC with ${hashName} requires a key of at least ${minBytes} bytes (got ${rawBytes.length})`,
              "ERR_JWK_INVALID",
            );
          }
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
      // A caller-chosen extractability is not part of the cache identity, so a
      // key imported for it is neither served from nor written to the cache.
      const cache = extractable === undefined ? _activeCache : false;
      if (cache) {
        const cached = await cache.get(key, effectiveAlg);
        if (cached) return cached;
      }
      const cryptoKey = await jwkTokey(key.alg ? key : { ...key, alg }, { extractable });
      if (cache) await cache.set(key, effectiveAlg, cryptoKey);
      return cryptoKey;
    }
  }

  throw new JWTError("Invalid key type provided to importKey", "ERR_JWK_INVALID");
}

/**
 * RFC 7517 §4.4 — a JWK's `alg` identifies the algorithm it is meant for, so an
 * operation under a different one is a mistake, not a hint to be resolved. The
 * single exception is the JWE symmetric role mapping: an `oct` JWK declaring a
 * content encryption algorithm is the CEK that `dir` consumes.
 */
function assertJWKAlgAuthority(jwk: JWK, alg: string | undefined): void {
  if (!alg || !jwk.alg || jwk.alg === alg) return;
  if (jwk.kty === "oct" && alg === "dir" && isContentEncryptionAlgorithm(jwk.alg)) return;
  throw new JWTError(
    `JWK "alg" is "${jwk.alg}" but the operation requires "${alg}".`,
    "ERR_JWK_INVALID",
  );
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
 * @param jwkParams Optional JWK metadata (`kid`, `use`, `x5c`, …) merged onto the exported key.
 *        `alg`, `kty`, `key_ops`, `ext` and the key material members are reserved.
 * @returns A Promise resolving to the exported JWK.
 * @throws `JWTError("ERR_INVALID_OPTION")` if `key` is not a `CryptoKey`, or if
 *         `jwkParams` carries a reserved member.
 * @throws `JWTError("ERR_JWK_INVALID")` if the key was imported as
 *         non-extractable — its material cannot leave the runtime.
 */
export async function exportKey<T extends JWK>(
  key: CryptoKey,
  jwkParams?: Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">,
): Promise<T> {
  if (!isCryptoKey(key)) {
    throw new JWTError(
      `exportKey expects a CryptoKey, got ${key === null ? "null" : typeof key}.`,
      "ERR_INVALID_OPTION",
    );
  }
  if (!key.extractable) {
    throw new JWTError(
      "A non-extractable CryptoKey cannot be exported as a JWK.",
      "ERR_JWK_INVALID",
    );
  }
  const exportedJwk = await keyToJWK<T>(key);
  if (jwkParams) {
    const extraParams = sanitizeObjectCopy(jwkParams);
    assertNoReservedJWKParams(extraParams);
    return { ...exportedJwk, ...extraParams };
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
    throw stringKeyError();
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
 * @param keyToWrap The key to be wrapped (CEK), typically a symmetric key as Uint8Array or CryptoKey.
 * @param wrappingKey The key used to wrap the CEK (CryptoKey, JWK, or password string/Uint8Array for PBES2).
 * @param options
 *   - `alg` — the JWA key management algorithm (e.g. `"A128KW"`, `"RSA-OAEP"`, `"PBES2-HS256+A128KW"`).
 *   - plus the options certain algorithms require (`p2s`/`p2c` for PBES2, `ecdh` for ECDH-ES, …).
 * @returns A Promise resolving to an alg-specific {@link WrapKeyResult}.
 */
export async function wrapKey<TAlg extends KeyManagementAlgorithm>(
  keyToWrap: CryptoKey | Uint8Array<ArrayBuffer>,
  wrappingKey: WrappingKeyFor<TAlg>,
  options: WrapKeyOptions<TAlg>,
): Promise<WrapKeyResult<TAlg>>;
export async function wrapKey(
  keyToWrap: CryptoKey | Uint8Array<ArrayBuffer>,
  wrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: WrapKeyOptions,
): Promise<WrapKeyResult> {
  const { alg } = options;
  const cekBytes =
    keyToWrap instanceof Uint8Array
      ? keyToWrap
      : new Uint8Array(await crypto.subtle.exportKey("raw", keyToWrap));

  // AES Key Wrap (RFC 3394 §2) — and every algorithm layered on it — carries the
  // CEK in 64-bit blocks, so a key of any other size cannot be wrapped at all.
  if (alg.endsWith("KW")) assertWrappableCEK(cekBytes, alg);
  if (alg.startsWith("PBES2")) assertPBES2Params({ p2s: options.p2s, p2c: options.p2c });

  const importedWrappingKey = await resolveWrappingKey(alg, wrappingKey, "public");

  switch (alg) {
    case "dir": {
      // RFC 7516 §4.5: for direct encryption, the JWE Encrypted Key is empty.
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
      if (!isCryptoKey(importedWrappingKey)) {
        throw new JWTError(
          "RSA-OAEP requires the wrapping key to be provided as a CryptoKey",
          "ERR_JWK_INVALID",
        );
      }
      const encryptedKey = await encryptRSAES(alg, importedWrappingKey, cekBytes);
      return { encryptedKey };
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!isCryptoKey(importedWrappingKey)) {
        throw new JWTError(
          "ECDH-ES requires the wrapping key to be a CryptoKey (recipient's public key)",
          "ERR_JWK_INVALID",
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
      if (apu.length > 0) wrapResult.apu = base64UrlStringify(apu);
      if (apv.length > 0) wrapResult.apv = base64UrlStringify(apv);

      if (alg === "ECDH-ES") {
        return wrapResult;
      }

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
 * @param wrappedKey The wrapped key (ciphertext) as Uint8Array.
 * @param unwrappingKey The key used to unwrap the CEK (CryptoKey, JWK, or password string/Uint8Array for PBES2).
 * @param options
 *   - `alg` — the JWA key management algorithm (e.g. `"A128KW"`, `"RSA-OAEP"`, `"PBES2-HS256+A128KW"`).
 *   - `format?` — `"cryptokey"` (default) or `"raw"`; it narrows the result type.
 *   - plus the options certain algorithms require (`iv`/`tag`, `p2s`/`p2c`, `epk`, …).
 * @returns A Promise resolving to the unwrapped key (CEK) as a CryptoKey or Uint8Array.
 */
export async function unwrapKey<TOptions extends UnwrapKeyOptions>(
  wrappedKey: Uint8Array<ArrayBuffer>,
  unwrappingKey: UnwrappingKeyFor<TOptions["alg"]>,
  options: TOptions,
): Promise<UnwrapKeyResult<TOptions>>;
export async function unwrapKey(
  wrappedKey: Uint8Array<ArrayBuffer>,
  unwrappingKey: CryptoKey | JWK | string | Uint8Array<ArrayBuffer>,
  options: UnwrapKeyOptions,
): Promise<CryptoKey | Uint8Array<ArrayBuffer>> {
  const { alg } = options;
  const returnRaw = options.format === "raw";
  const defaultExtractable = options.extractable !== false; // Default true

  const importedUnwrappingKey = await resolveWrappingKey(alg, unwrappingKey, "private");

  let unwrappedCekBytes: Uint8Array<ArrayBuffer>;

  switch (alg) {
    case "dir": {
      assertDirectKeyRole(unwrappingKey, options.enc);
      if (importedUnwrappingKey instanceof Uint8Array) {
        assertOctKeyLength(importedUnwrappingKey, options.enc);
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
      const p2sBytes =
        typeof p2s === "string" ? decodeSegment(p2s, { family: "JWE", what: '"p2s"' }) : p2s;
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
        typeof options.iv === "string"
          ? decodeSegment(options.iv, { family: "JWE", what: '"iv"' })
          : options.iv;
      const tagBytes =
        typeof options.tag === "string"
          ? decodeSegment(options.tag, { family: "JWE", what: '"tag"' })
          : options.tag;
      assertKeyWrapSegmentLength("iv", ivBytes, bitLengthIV(alg) >> 3, alg);
      assertKeyWrapSegmentLength("tag", tagBytes, bitLengthTag(alg) >> 3, alg);
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
      if (!isCryptoKey(importedUnwrappingKey)) {
        throw new JWTError(
          "RSA-OAEP requires the unwrapping key to be provided as a CryptoKey",
          "ERR_JWK_INVALID",
        );
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
      if (!isCryptoKey(importedUnwrappingKey)) {
        throw new JWTError(
          "ECDH-ES requires the unwrapping key to be a CryptoKey",
          "ERR_JWK_INVALID",
        );
      }

      if (!isECDHKeyAllowed(importedUnwrappingKey)) {
        throw new JWTError(
          "ECDH with the provided key is not allowed or not supported",
          "ERR_JWK_INVALID",
        );
      }

      const epkCandidate = await normalizeEpk(options.epk, {
        alg,
        recipientKey: importedUnwrappingKey,
      });

      const apuBytes =
        typeof options.apu === "string"
          ? decodeSegment(options.apu, { family: "JWE", what: '"apu"' })
          : (options.apu ?? new Uint8Array(0));
      const apvBytes =
        typeof options.apv === "string"
          ? decodeSegment(options.apv, { family: "JWE", what: '"apv"' })
          : (options.apv ?? new Uint8Array(0));
      assertPartyInfoLength("apu", apuBytes);
      assertPartyInfoLength("apv", apvBytes);

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

  if (returnRaw) {
    return unwrappedCekBytes;
  }

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
 *   - `jwkParams?` — additional JWK properties merged into the result (e.g. `kid`, `use`).
 *
 * The returned JWK always contains the key material in plain JavaScript — non-extractable
 * import is impossible for a PEM → JWK conversion (JWK export requires an extractable key).
 * To obtain a non-extractable `CryptoKey`, pass the result to
 * `importKey(jwk, { extractable: false })`.
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
    /** Additional JWK properties merged into the exported key (e.g. `kid`). */
    jwkParams?: Omit<JWKParameters, "alg" | "kty" | "key_ops" | "ext">;
  },
): Promise<T> {
  // The intermediate CryptoKey must be extractable: the JWK output requires exporting it.
  const extractable = true;
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
      throw new JWTError(`Unsupported PEM type: ${String(pemType)}`, "ERR_JWK_UNSUPPORTED");
    }
  }

  const jwk = await exportKey(cryptoKey, options?.jwkParams);
  return { ...jwk, alg } as T;
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
  if (effectiveAlg !== undefined && !PEM_ALGORITHMS.has(effectiveAlg)) {
    throw new JWTError(`Unsupported PEM algorithm: ${effectiveAlg}`, "ERR_JWK_UNSUPPORTED");
  }

  const pemFormat = options?.pemFormat ?? ("d" in jwk ? "pkcs8" : "spki");

  // Intermediate CryptoKey must be extractable to be exported back to PEM.
  const cryptoKeyCandidate = await importKey(
    { ...jwk, ext: true },
    {
      alg: effectiveAlg,
      expect: pemFormat === "pkcs8" ? "private" : "public",
      extractable: true,
    },
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
      throw new JWTError(`Unsupported PEM format: ${String(pemFormat)}`, "ERR_JWK_UNSUPPORTED");
    }
  }
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
 * @param options
 *   - `enc` — the algorithm identifier used as the `AlgorithmID` in the concat KDF
 *     info structure. Pass a {@link JWK_ECDH_ES} variant (e.g. `"ECDH-ES+A128KW"`)
 *     or a {@link ContentEncryptionAlgorithm} (e.g. `"A256GCM"`) for direct key agreement.
 *   - `keyLength?` / `partyUInfo?` / `partyVInfo?` — overrides for key length and party info.
 */
export async function deriveSharedSecret(
  publicKey: CryptoKey | JWK_EC_Public,
  privateKey: CryptoKey | JWK_EC_Private,
  options: {
    /** Algorithm identifier fed to the concat KDF as `AlgorithmID`. */
    enc: JWK_ECDH_ES | ContentEncryptionAlgorithm;
    /** Override the derived key length in bits. Defaults to the standard length for `enc`. */
    keyLength?: number;
    /** Agreement PartyUInfo (apu). */
    partyUInfo?: Uint8Array<ArrayBuffer>;
    /** Agreement PartyVInfo (apv). */
    partyVInfo?: Uint8Array<ArrayBuffer>;
  },
): Promise<Uint8Array<ArrayBuffer>> {
  const { enc: alg, keyLength: requestedKeyLength, partyUInfo, partyVInfo } = options;
  if (requestedKeyLength !== undefined) {
    assertDerivedKeyLength(requestedKeyLength);
  }

  // A JWK minted for `ECDH-ES+A256KW` declares that alg, and a JWK's `alg` is
  // authoritative — so the import names the requested key management algorithm
  // when there is one, and bare `ECDH-ES` when `enc` is a content algorithm.
  const importAlg = (alg as string).startsWith("ECDH-ES") ? (alg as string) : "ECDH-ES";
  const pubCryptoKey = isCryptoKey(publicKey)
    ? publicKey
    : ((await importKey(publicKey as JWK, { alg: importAlg, expect: "public" })) as CryptoKey);
  const privCryptoKey = isCryptoKey(privateKey)
    ? privateKey
    : ((await importKey(privateKey as JWK, { alg: importAlg, expect: "private" })) as CryptoKey);

  let keyLength: number;
  if (requestedKeyLength !== undefined) {
    keyLength = requestedKeyLength;
  } else if (alg === "ECDH-ES") {
    throw new JWTError(
      'deriveSharedSecret with enc "ECDH-ES" requires an explicit keyLength in options',
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
    partyUInfo ?? new Uint8Array(0),
    partyVInfo ?? new Uint8Array(0),
  );
}

/**
 * Returns all JWKs from a JWK Set, optionally narrowed by a predicate.
 *
 * Entries that are not JWKs are dropped: `keys` arrives over the wire and may
 * hold `null`, strings or junk objects, none of which is key material.
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

  const keys = jwkSet.keys.filter((key) => isJWK(key));

  return filter ? keys.filter(filter) : keys;
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

  const requested = options?.keyUsage;
  const usage = (allowed: readonly KeyUsage[], fallback: KeyUsage[]): KeyUsage[] =>
    resolveKeyUsage(requested, { allowed, fallback, alg });

  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      algorithm = {
        name: "HMAC",
        hash: `SHA-${alg.slice(2)}`,
      };
      keyUsages = usage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }

    case "RS256":
    case "RS384":
    case "RS512": {
      algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: assertModulusLength(options?.modulusLength),
        publicExponent: options?.publicExponent ?? new Uint8Array([0x01, 0x00, 0x01]),
        hash: `SHA-${alg.slice(2)}`,
      };
      keyUsages = usage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }

    case "PS256":
    case "PS384":
    case "PS512": {
      algorithm = {
        name: "RSA-PSS",
        modulusLength: assertModulusLength(options?.modulusLength),
        publicExponent: options?.publicExponent ?? new Uint8Array([0x01, 0x00, 0x01]),
        hash: `SHA-${alg.slice(2)}`,
      };
      keyUsages = usage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }

    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      algorithm = {
        name: "RSA-OAEP",
        modulusLength: assertModulusLength(options?.modulusLength),
        publicExponent: options?.publicExponent ?? new Uint8Array([0x01, 0x00, 0x01]),
        hash: `SHA-${Number.parseInt(alg.slice(9), 10) || 1}`,
      };
      keyUsages = usage(KEY_ENCRYPTION_USAGES, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
      break;
    }

    case "A128KW":
    case "A192KW":
    case "A256KW": {
      const length = Number.parseInt(alg.slice(1, 4), 10);
      algorithm = { name: "AES-KW", length };
      keyUsages = usage(KEY_WRAPPING_USAGES, ["wrapKey", "unwrapKey"]);
      break;
    }

    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      const baseAlg = alg.replace("KW", "");
      const length = Number.parseInt(baseAlg.slice(1, 4), 10);
      algorithm = { name: "AES-GCM", length };
      keyUsages = usage(
        KEY_ENCRYPTION_USAGES,
        alg.endsWith("KW") ? ["wrapKey", "unwrapKey"] : ["encrypt", "decrypt"],
      );
      break;
    }

    case "ES256":
    case "ES384":
    case "ES512": {
      algorithm = { name: "ECDSA", namedCurve: `P-${alg.slice(2)}` };
      keyUsages = usage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }
    case "Ed25519": {
      keyUsages = usage(SIGNATURE_USAGES, ["sign", "verify"]);
      algorithm = { name: "Ed25519" };
      break;
    }
    case "EdDSA": {
      keyUsages = usage(SIGNATURE_USAGES, ["sign", "verify"]);
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

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      keyUsages = usage(DERIVATION_USAGES, ["deriveBits"]);
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

/**
 * JWK members the library derives from the key itself. A caller-supplied
 * `jwkParams` may decorate a key, never rewrite it: letting `kty`, `alg`,
 * `key_ops`, `ext` or any key-material member through would produce a JWK that
 * misdescribes the bytes it carries.
 */
const RESERVED_JWK_PARAMS = new Set([
  "kty",
  "alg",
  "key_ops",
  "ext",
  "k",
  "d",
  "n",
  "e",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "oth",
  "x",
  "y",
  "crv",
]);

function assertNoReservedJWKParams(jwkParams: object): void {
  const reserved = Object.keys(jwkParams).filter((name) => RESERVED_JWK_PARAMS.has(name));
  if (reserved.length > 0) {
    throw new JWTError(
      `jwkParams must not set reserved JWK members: ${reserved.join(", ")}`,
      "ERR_INVALID_OPTION",
    );
  }
}

/** `key_ops` each algorithm family admits — a caller's `keyUsage` may narrow it. */
const SIGNATURE_USAGES: readonly KeyUsage[] = ["sign", "verify"];
const KEY_WRAPPING_USAGES: readonly KeyUsage[] = ["wrapKey", "unwrapKey"];
const KEY_ENCRYPTION_USAGES: readonly KeyUsage[] = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
const DERIVATION_USAGES: readonly KeyUsage[] = ["deriveBits", "deriveKey"];
const CONTENT_ENCRYPTION_USAGES: readonly KeyUsage[] = ["encrypt", "decrypt"];

/**
 * The usages a generated key carries: the caller's when they name any, the
 * algorithm's own otherwise. A requested usage the algorithm cannot serve is a
 * malformed option rather than something to silently drop — WebCrypto would
 * reject it as a `DOMException`, or the key would be minted unable to do the
 * job it was asked for.
 */
function resolveKeyUsage(
  requested: KeyUsage[] | undefined,
  options: { allowed: readonly KeyUsage[]; fallback: KeyUsage[]; alg: string },
): KeyUsage[] {
  const { allowed, fallback, alg } = options;
  if (requested === undefined) return fallback;
  if (!Array.isArray(requested) || requested.length === 0) {
    throw new JWTError('"keyUsage" must be a non-empty array.', "ERR_INVALID_OPTION");
  }
  const rejected = requested.filter((entry) => !allowed.includes(entry));
  if (rejected.length > 0) {
    throw new JWTError(
      `"keyUsage" ${rejected.join(", ")} cannot be served by ${alg}; it admits ${allowed.join(", ")}.`,
      "ERR_INVALID_OPTION",
    );
  }
  return requested;
}

/** Name a freshly generated JWK by its RFC 7638 thumbprint. */
async function withThumbprintKid<T extends JWK>(jwk: T): Promise<T> {
  return { ...jwk, kid: await thumbprint(jwk) };
}

/**
 * The algorithms {@link importPEM} and {@link exportPEM} round-trip.
 * `satisfies Record<JWKPEMAlgorithm, true>` is the compile-time guard that keeps
 * it in lockstep with the union: a missing key and a stray key both fail.
 */
const PEM_ALGORITHMS: ReadonlySet<string> = /* @__PURE__ */ new Set(
  Object.keys({
    "PS256": true,
    "PS384": true,
    "PS512": true,
    "RS256": true,
    "RS384": true,
    "RS512": true,
    "RSA-OAEP": true,
    "RSA-OAEP-256": true,
    "RSA-OAEP-384": true,
    "RSA-OAEP-512": true,
    "ES256": true,
    "ES384": true,
    "ES512": true,
    "ECDH-ES": true,
    "ECDH-ES+A128KW": true,
    "ECDH-ES+A192KW": true,
    "ECDH-ES+A256KW": true,
    "Ed25519": true,
    "EdDSA": true,
  } satisfies Record<JWKPEMAlgorithm, true>),
);

/**
 * RFC 3394 §2 — AES Key Wrap operates on whole 64-bit blocks and needs at least
 * two of them, so a CEK of any other length cannot be wrapped.
 */
function assertWrappableCEK(cek: Uint8Array<ArrayBuffer>, alg: string): void {
  if (cek.length >= 16 && cek.length % 8 === 0) return;
  throw new JWTError(
    `${alg} wraps a key of 16 or more bytes in whole 8-byte blocks (got ${cek.length}).`,
    "ERR_INVALID_OPTION",
  );
}

function assertModulusLength(modulusLength: number | undefined): number {
  const length = modulusLength ?? 2048;
  if (!Number.isInteger(length) || length < 2048) {
    throw new JWTError(
      "modulusLength must be at least 2048 bits (RFC 7518 §3.3)",
      "ERR_INVALID_OPTION",
    );
  }
  return length;
}

const MAX_PARTY_INFO_BYTES = 1024;

/**
 * RFC 7518 §4.6.1.2 / §4.6.1.3 — `apu` / `apv` are attacker-supplied and feed
 * the Concat KDF input verbatim, so their size is bounded.
 */
function assertPartyInfoLength(name: "apu" | "apv", bytes: Uint8Array<ArrayBuffer>): void {
  if (bytes.length > MAX_PARTY_INFO_BYTES) {
    throw new JWTError(
      `Invalid JWE: "${name}" must not exceed ${MAX_PARTY_INFO_BYTES} bytes (got ${bytes.length}).`,
      "ERR_JWE_INVALID",
    );
  }
}

function assertKeyWrapSegmentLength(
  name: "iv" | "tag",
  bytes: Uint8Array<ArrayBuffer>,
  expected: number,
  alg: string,
): void {
  if (bytes.length !== expected) {
    throw new JWTError(
      `Invalid JWE: "${name}" must be ${expected} bytes for ${alg} (got ${bytes.length}).`,
      "ERR_JWE_INVALID",
    );
  }
}

function assertDerivedKeyLength(keyLength: number): void {
  if (!Number.isInteger(keyLength) || keyLength <= 0 || keyLength % 8 !== 0 || keyLength > 8192) {
    throw new JWTError(
      `keyLength must be a positive multiple of 8 no greater than 8192 bits, got ${keyLength}`,
      "ERR_INVALID_OPTION",
    );
  }
}
