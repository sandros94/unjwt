import { secureRandomBytes } from "unsecure/random";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import { textEncoder } from "unsecure/utils";
import {
  MAX_PARTY_INFO_BYTES,
  asDecryptionError,
  assertDirectKeyRole,
  buildECDHAgreementParams,
  decodeSegment,
  resolvePasswordKey,
  stringKeyError,
} from "./_internal";

import type {
  JWK,
  JWKSet,
  JWK_oct,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_ECDH_ES,
  JWKPEMAlgorithm,
  JWKMetadata,
  JWKCacheAdapter,
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
  GenerateKeyReturn,
  GenerateJWKOptions,
  GenerateJWKReturn,
  ImportedKey,
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
import { assertPlainObject, isCryptoKey, isJWK, isJWKSet } from "./utils/guards";
import { PBES2_ALGORITHMS, isContentEncryptionAlgorithm } from "./utils/algorithms";
import { JWTError } from "./error";
import {
  jwkTokey,
  keyToJWK,
  assertPBES2Params,
  assertPBES2Salt,
  assertPBES2Count,
  bitLengthCEK,
  assertOctKeyLength,
  deriveKeyPBES2,
  pbes2Wrap,
  pbes2Unwrap,
  deriveECDHESKey,
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
import { assertECDHKeyAllowed, ecdhDerivedBits } from "./_crypto/_ecdh";
import { ecdhesWrap } from "./_crypto/_key-encryption";
import {
  ECDSA_CURVES,
  aesBitsOf,
  innerKeyWrapAlg,
  jwsHashOf,
  rsaOaepHashOf,
} from "./_crypto/_key-algorithm";

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
 * Generates a key for a JWA algorithm: a `CryptoKey` for symmetric algorithms, raw bytes for
 * the `A*CBC-HS*` composites, a `CryptoKeyPair` for asymmetric ones; with `toJWK: true`, a JWK
 * (or JWK pair) whose `kid` is its RFC 7638 thumbprint. PBES2, `"dir"` and `"none"` are refused.
 *
 * @param options
 *   - `extractable?` — defaults to `true`; ignored when `toJWK` is set.
 *   - `keyUsage?` — narrows the usages derived from `alg`; leaving either half of a pair with
 *     no usage throws `ERR_INVALID_OPTION`.
 *   - `modulusLength?` — RSA only; defaults to `2048`.
 *   - `publicExponent?` — RSA only; big-endian bytes, defaults to `0x010001`.
 *   - `namedCurve?` — EC/OKP only; defaults to `"P-256"` / `"Ed25519"`. One that contradicts
 *     the curve `ES*` or `Ed25519` names throws `ERR_INVALID_OPTION`.
 */
export async function generateKey<TAlg extends GenerateKeyAlgorithm, ToJWK extends boolean = false>(
  alg: TAlg,
  options?: GenerateKeyOptions<ToJWK>,
): Promise<GenerateKeyReturn<TAlg, GenerateKeyOptions<ToJWK>>>;
export async function generateKey(
  alg: string,
  options: GenerateKeyOptions = {},
): Promise<
  CryptoKey | CryptoKeyPair | Uint8Array<ArrayBuffer> | JWK | { privateKey: JWK; publicKey: JWK }
> {
  const exportToJWK = options.toJWK !== undefined && options.toJWK;
  const defaultExtractable = exportToJWK || options.extractable !== false;

  // Composite AES-CBC+HMAC keys are not importable via WebCrypto, so they stay raw bytes.
  if (alg === "A128CBC-HS256" || alg === "A192CBC-HS384" || alg === "A256CBC-HS512") {
    const keyLength = bitLengthCEK(alg);
    const keyBytes = secureRandomBytes(keyLength >> 3);

    if (exportToJWK) {
      // WebCrypto never exports these bytes, so the members its JWK export would write are set.
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
      const kid = await thumbprint({ ...pub, alg });
      return {
        privateKey: { ...priv, alg, kid },
        publicKey: { ...pub, alg, kid },
      };
    }
  }

  return key;
}

/**
 * Generates a JWK (or JWK pair) for a JWA algorithm, its `kid` the caller's or its RFC 7638
 * thumbprint. PBES2, `"dir"` and `"none"` are refused.
 *
 * @param options
 *   - `keyUsage?`, `modulusLength?` (default `2048`), `publicExponent?` (default `0x010001`),
 *     `namedCurve?` (default `"P-256"` / `"Ed25519"`); a narrowing that empties a pair half or
 *     a curve that contradicts `alg` throws `ERR_INVALID_OPTION`.
 *   - JWK metadata (`kid`, `use`, `x5c`, `x5t`, `x5t#S256`, `x5u`) is merged onto the result;
 *     `alg`, `kty`, `key_ops`, `ext` and key-material members are reserved (`ERR_INVALID_OPTION`).
 */
export async function generateJWK<TAlg extends GenerateKeyAlgorithm>(
  alg: TAlg,
  options?: GenerateJWKOptions & JWKMetadata,
): Promise<GenerateJWKReturn<TAlg>>;
export async function generateJWK(
  alg: GenerateKeyAlgorithm,
  options?: GenerateJWKOptions & JWKMetadata,
): Promise<JWK | { privateKey: JWK; publicKey: JWK }> {
  const {
    keyUsage,
    modulusLength,
    publicExponent,
    namedCurve,
    extractable: _extractable,
    toJWK: _toJWK,
    ...jwkParams
  } = (options ?? {}) as GenerateJWKOptions &
    JWKMetadata & {
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

  const named = callerKid === undefined ? undefined : { kid: callerKid };
  if (result && typeof result === "object" && "privateKey" in result && "publicKey" in result) {
    return {
      privateKey: { ...jwkParams, ...result.privateKey, ...named },
      publicKey: { ...jwkParams, ...result.publicKey, ...named },
    };
  }
  return { ...jwkParams, ...result, ...named };
}

/**
 * Derives an AES-KW key from a password with PBKDF2 per PBES2 (RFC 7518 §4.8).
 *
 * @param options
 *   - `alg` — a PBES2 algorithm; any other throws `ERR_JWK_UNSUPPORTED`.
 *   - `salt` — PBKDF2 salt (`p2s`), at least 8 octets (RFC 7518 §4.8.1.1).
 *   - `iterations` — PBKDF2 count (`p2c`), an integer of at least 1000 (RFC 7518 §4.8.1.2);
 *     anything else throws `ERR_INVALID_OPTION`.
 *   - `keyUsage?` — defaults to `["wrapKey", "unwrapKey"]`.
 *   - `extractable?` — defaults to `false`; ignored when `toJWK` is set.
 *   - `toJWK?` — return a `JWK_oct` carrying the inner AES-KW `alg` instead of a `CryptoKey`.
 */
export async function deriveKeyFromPassword<TOptions extends DeriveKeyOptions>(
  password: string | Uint8Array<ArrayBuffer>,
  options: TOptions,
): Promise<DeriveKeyReturn<TOptions, TOptions["alg"]>>;
export async function deriveKeyFromPassword(
  password: string | Uint8Array<ArrayBuffer>,
  options: DeriveKeyOptions,
): Promise<CryptoKey | JWK_oct> {
  assertPlainObject(options, "options");
  if (typeof password !== "string" && !(password instanceof Uint8Array)) {
    throw new JWTError('"password" must be a string or a Uint8Array.', "ERR_INVALID_OPTION");
  }
  const { alg, salt, iterations, extractable, keyUsage } = options;
  assertPBES2Algorithm(alg);
  const exportToJWK = options.toJWK !== undefined && options.toJWK;

  const saltBytes = typeof salt === "string" ? textEncoder.encode(salt) : salt;
  assertPBES2Salt(saltBytes, '"salt"');
  assertPBES2Count(iterations, '"iterations"');

  const passwordBytes = typeof password === "string" ? textEncoder.encode(password) : password;

  const derivedBytes = await deriveKeyPBES2(saltBytes, alg, iterations, passwordBytes);

  const wrappingAlg = innerKeyWrapAlg(alg);
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
 * Derives a `JWK_oct` from a password per PBES2 (RFC 7518 §4.8); its `alg` is the inner AES-KW
 * variant and its `kid` the caller's or its RFC 7638 thumbprint.
 *
 * @param options
 *   - `alg` (PBES2 only, else `ERR_JWK_UNSUPPORTED`), `salt` (at least 8 octets), `iterations`
 *     (integer of at least 1000, else `ERR_INVALID_OPTION`), `keyUsage?` (default
 *     `["wrapKey", "unwrapKey"]`).
 *   - JWK metadata (`kid`, `use`, `x5c`, `x5t`, `x5t#S256`, `x5u`) is merged onto the result;
 *     `alg`, `kty`, `key_ops`, `ext` and key-material members are reserved (`ERR_INVALID_OPTION`).
 */
export async function deriveJWKFromPassword(
  password: string | Uint8Array<ArrayBuffer>,
  options: Omit<DeriveKeyOptions, "toJWK" | "extractable"> & JWKMetadata,
): Promise<JWK_oct> {
  assertPlainObject(options, "options");
  const {
    alg,
    salt,
    iterations,
    keyUsage,
    extractable: _extractable,
    toJWK: _toJWK,
    ...jwkParams
  } = options as DeriveKeyOptions & JWKMetadata;
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
 * Default JWK import cache, keyed by JWK object identity: a copied JWK misses it, and a JWK
 * mutated in place keeps serving the old `CryptoKey`. Rotate by replacing the object.
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
 * Replaces the JWK import cache used by `importKey`, or disables it with `false`.
 *
 * A cache shared across JWK objects keys on the RFC 7638 thumbprint, the pair half (`d` present)
 * and `alg`: the thumbprint covers public members only, and a `kid` may name different keys.
 * `get` and `set` may return promises.
 *
 * @example
 * ```ts
 * const cacheKey = async (jwk: JWK, alg: string) =>
 *   `${await thumbprint(jwk)}:${"d" in jwk ? "private" : "public"}:${alg}`;
 * const map = new Map<string, CryptoKey>();
 * configureJWKCache({
 *   get: async (jwk, alg) => map.get(await cacheKey(jwk, alg)),
 *   set: async (jwk, alg, key) => {
 *     map.set(await cacheKey(jwk, alg), key);
 *   },
 * });
 * ```
 */
export function configureJWKCache(cache: JWKCacheAdapter | false): void {
  _activeCache = cache;
}

/** Resets the JWK import cache to a fresh `WeakMapJWKCache`. */
export function clearJWKCache(): void {
  _activeCache = new WeakMapJWKCache();
}

/** Imports the secret of an `oct` JWK as a `CryptoKey` under `algorithm` and `usage`. */
export async function importKey(
  key: JWK_oct,
  options: {
    asCryptoKey: true;
    /** Algorithm to import the key as (e.g. `{ name: "AES-GCM", length: 256 }`). */
    algorithm: Parameters<typeof crypto.subtle.importKey>[2];
    usage: KeyUsage[];
    /** Mark the key as extractable. Defaults to `false`. */
    extractable?: boolean;
  },
): Promise<CryptoKey>;
/**
 * Imports key material: a `CryptoKey` or `Uint8Array` is returned as is, an `oct` JWK as its raw
 * bytes, an asymmetric JWK as a `CryptoKey` under its own `alg` or the hint. A string throws
 * `ERR_JWK_INVALID`.
 *
 * `expect` and `extractable` apply to asymmetric keys only; `expect` rejects the other pair half
 * with `ERR_JWK_INVALID`. A JWK's `alg` is authoritative (RFC 7517 §4.4): a different requested
 * `alg` throws `ERR_JWK_INVALID`, except an `oct` JWK declaring a content encryption `alg` under
 * `"dir"`.
 */
export async function importKey<K extends CryptoKey | JWK | Uint8Array<ArrayBuffer>>(
  key: K,
  options?:
    | string
    | {
        /** Algorithm hint. Required when `key.alg` is absent on an asymmetric JWK. */
        alg?: string;
        /** Reject on shape mismatch instead of silently importing. */
        expect?: "public" | "private";
        /** Defaults to `false` for private, `true` for public material; JWK `ext: false` wins. */
        extractable?: boolean;
      },
): Promise<ImportedKey<K>>;
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
      const rawBytes = decodeSegment(key.k, { family: "JWK", what: '"k"' });
      assertOctKeyLength(rawBytes, alg ?? key.alg);
      if (typeof algOrOptions === "object" && algOrOptions.asCryptoKey) {
        const { algorithm, usage, extractable: rawExtractable = false } = algOrOptions;
        if (!algorithm || !usage) {
          throw new JWTError(
            "asCryptoKey option requires `algorithm` and `usage` to be provided.",
            "ERR_JWK_INVALID",
          );
        }
        if (typeof algorithm === "object" && algorithm.name === "HMAC") {
          const hash: unknown = "hash" in algorithm ? algorithm.hash : undefined;
          const hashName =
            typeof hash === "string"
              ? hash
              : typeof hash === "object" &&
                  hash !== null &&
                  "name" in hash &&
                  typeof hash.name === "string"
                ? hash.name
                : undefined;
          const minBytes = Number.parseInt(hashName?.slice(-3) ?? "", 10) / 8;
          if (minBytes && rawBytes.length < minBytes) {
            throw new JWTError(
              `HMAC with ${hashName} requires a key of at least ${minBytes} bytes (got ${rawBytes.length})`,
              "ERR_JWK_INVALID",
            );
          }
        }
        return crypto.subtle.importKey("raw", rawBytes, algorithm, rawExtractable, usage);
      }
      return rawBytes;
    } else {
      const effectiveAlg = key.alg || alg;
      if (!effectiveAlg) {
        throw new JWTError(
          "Algorithm must be provided when importing non-oct JWK",
          "ERR_JWK_INVALID",
        );
      }
      assertIntentOnJWK(key, expect);
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

/** RFC 7517 §4.4: a JWK's `alg` is authoritative, except an `oct` CEK consumed by `dir`. */
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
 * Exports an extractable `CryptoKey` as a JWK, merging optional `jwkParams` metadata.
 *
 * The `alg` is WebCrypto's, which knows no JOSE roles: an AES-GCM key minted for `A128GCMKW`
 * exports as `A128GCM`, so key-wrapping keys are minted with `generateJWK` instead.
 *
 * @throws `ERR_INVALID_OPTION` if `key` is not a `CryptoKey` or `jwkParams` sets a reserved member
 *   (`alg`, `kty`, `key_ops`, `ext`, key material); `ERR_JWK_INVALID` for a non-extractable key.
 */
export async function exportKey<T extends JWK = JWK>(
  key: CryptoKey,
  jwkParams?: JWKMetadata,
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

/**
 * Wraps a CEK under a JWA key management algorithm; the result shape follows `alg`.
 *
 * @param wrappingKey A `CryptoKey`, a JWK, or for PBES2 a password string or bytes.
 * @param options `alg` plus its parameters (`p2s`/`p2c` for PBES2, `ecdh` for ECDH-ES, …).
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
  assertPlainObject(options, "options");
  assertKeyBytesArg(keyToWrap, "keyToWrap");
  const { alg } = options;
  const cekBytes =
    keyToWrap instanceof Uint8Array
      ? keyToWrap
      : new Uint8Array(await crypto.subtle.exportKey("raw", keyToWrap));

  if (alg.endsWith("KW")) assertWrappableCEK(cekBytes, alg);
  if (alg.startsWith("PBES2")) assertPBES2Params({ p2s: options.p2s, p2c: options.p2c });

  const importedWrappingKey = await importKey(resolvePasswordKey(alg, wrappingKey), {
    alg,
    expect: "public",
  });

  switch (alg) {
    case "dir": {
      // RFC 7516 §5.2 step 6: direct encryption has an empty JWE Encrypted Key.
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
      assertCryptoKeyFor(alg, importedWrappingKey, "wrapping");
      const encryptedKey = await encryptRSAES(alg, importedWrappingKey, cekBytes);
      return { encryptedKey };
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      assertCryptoKeyFor(alg, importedWrappingKey, "wrapping");
      const enc = options.ecdh?.enc;
      if (alg === "ECDH-ES" && !enc) {
        throw new JWTError(
          "ECDH-ES direct key agreement requires options.ecdh.enc (the target content encryption algorithm)",
          "ERR_JWK_INVALID",
        );
      }

      const { encryptedKey, parameters } = await ecdhesWrap(alg, {
        enc,
        recipientKey: importedWrappingKey,
        cek: cekBytes,
        parameters: buildECDHAgreementParams(options.ecdh),
      });
      const wrapResult: WrapKeyResult<JWK_ECDH_ES> = {
        encryptedKey: encryptedKey ?? new Uint8Array(0),
        epk: parameters.epk,
      };
      if (parameters.apu) wrapResult.apu = parameters.apu;
      if (parameters.apv) wrapResult.apv = parameters.apv;
      return wrapResult;
    }

    default: {
      throw new JWTError(`Unsupported key wrapping algorithm: ${alg}`, "ERR_JWK_UNSUPPORTED");
    }
  }
}

/**
 * Unwraps a CEK under a JWA key management algorithm.
 *
 * @param unwrappingKey A `CryptoKey`, a JWK, or for PBES2 a password string or bytes.
 * @param options `alg`, `format?` (`"cryptokey"` by default, or `"raw"`), plus the algorithm's
 *   parameters (`iv`/`tag`, `p2s`/`p2c`, `epk`, …).
 * @throws `ERR_JWE_DECRYPTION_FAILED` for any failed unwrap, its cause undisclosed (RFC 7516
 *   §11.5); `ERR_INVALID_OPTION` for a malformed `wrappedKey` or `options`; `ERR_JWE_INVALID` for
 *   missing or malformed algorithm parameters.
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
  assertPlainObject(options, "options");
  if (!(wrappedKey instanceof Uint8Array)) {
    throw new JWTError('"wrappedKey" must be a Uint8Array.', "ERR_INVALID_OPTION");
  }
  const { alg } = options;
  const returnRaw = options.format === "raw";
  const defaultExtractable = options.extractable !== false;

  const importedUnwrappingKey = await importKey(resolvePasswordKey(alg, unwrappingKey), {
    alg,
    expect: "private",
  });

  let unwrappedCekBytes: Uint8Array<ArrayBuffer>;

  switch (alg) {
    case "dir": {
      assertDirectKeyRole(unwrappingKey, options.enc);
      if (importedUnwrappingKey instanceof Uint8Array) {
        assertOctKeyLength(importedUnwrappingKey, options.enc);
        unwrappedCekBytes = importedUnwrappingKey;
      } else {
        if (!returnRaw) {
          return importedUnwrappingKey;
        }
        unwrappedCekBytes = new Uint8Array(
          await crypto.subtle.exportKey("raw", importedUnwrappingKey),
        );
      }
      break;
    }

    case "A128KW":
    case "A192KW":
    case "A256KW": {
      unwrappedCekBytes = await unwrapping(aesKwUnwrap(alg, importedUnwrappingKey, wrappedKey));
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
      const p2sBytes = segmentBytes(p2s, "p2s");
      unwrappedCekBytes = await unwrapping(
        pbes2Unwrap(
          alg,
          importedUnwrappingKey,
          wrappedKey,
          p2c,
          p2sBytes,
          minIterations,
          maxIterations,
        ),
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
      const ivBytes = segmentBytes(options.iv, "iv");
      const tagBytes = segmentBytes(options.tag, "tag");
      assertKeyWrapSegmentLength("iv", ivBytes, bitLengthIV(alg) >> 3, alg);
      assertKeyWrapSegmentLength("tag", tagBytes, bitLengthTag(alg) >> 3, alg);
      unwrappedCekBytes = await unwrapping(
        gcmkwDecrypt(alg, importedUnwrappingKey, wrappedKey, ivBytes, tagBytes),
      );
      break;
    }

    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      assertCryptoKeyFor(alg, importedUnwrappingKey, "unwrapping");

      unwrappedCekBytes = await unwrapping(decryptRSAES(alg, importedUnwrappingKey, wrappedKey));

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
      return await crypto.subtle.importKey(
        "raw",
        unwrappedCekBytes,
        inferredAlgorithm,
        defaultExtractable,
        keyUsages,
      );
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
      assertCryptoKeyFor(alg, importedUnwrappingKey, "unwrapping");
      assertECDHKeyAllowed(importedUnwrappingKey);

      const epkCandidate = await normalizeEpk(options.epk, {
        alg,
        recipientKey: importedUnwrappingKey,
      });

      const apuBytes = segmentBytes(options.apu ?? new Uint8Array(0), "apu");
      const apvBytes = segmentBytes(options.apv ?? new Uint8Array(0), "apv");
      assertPartyInfoLength("apu", apuBytes);
      assertPartyInfoLength("apv", apvBytes);

      const infoAlg = alg === "ECDH-ES" ? options.enc : alg;

      if (!infoAlg) {
        throw new JWTError(
          "ECDH-ES requires content encryption algorithm ('enc') to derive the shared secret",
          "ERR_JWE_INVALID",
        );
      }

      const keyLength = ecdhDerivedBits(alg, infoAlg);

      const sharedSecret = await unwrapping(
        deriveECDHESKey(
          epkCandidate,
          importedUnwrappingKey,
          infoAlg,
          keyLength,
          apuBytes,
          apvBytes,
        ),
      );

      if (alg === "ECDH-ES") {
        unwrappedCekBytes = sharedSecret;
      } else {
        const kwAlg = innerKeyWrapAlg(alg);
        if (!(wrappedKey instanceof Uint8Array) || wrappedKey.length === 0) {
          throw new JWTError(
            "ECDH-ES key agreement with key wrapping requires an encrypted key",
            "ERR_JWE_INVALID",
          );
        }
        unwrappedCekBytes = await unwrapping(aesKwUnwrap(kwAlg, sharedSecret, wrappedKey));
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

  return finalKey;
}

/**
 * Imports a PEM key as a JWK carrying `alg`. The type follows the label — `PRIVATE KEY`
 * (PKCS#8), `PUBLIC KEY` (SPKI), `CERTIFICATE` (X.509, only its SPKI kept) — unless
 * `options.pemType` overrides it. The JWK holds the key material in plain JavaScript.
 *
 * @throws `ERR_JWK_INVALID` if the type cannot be inferred or does not match the label;
 *   `ERR_JWK_UNSUPPORTED` for an unknown `pemType`; `ERR_INVALID_OPTION` if `jwkParams` sets
 *   `alg`, `kty`, `key_ops`, `ext` or a key-material member.
 */
export async function importPEM<T extends JWK>(
  pem: string,
  alg: JWKPEMAlgorithm,
  options?: {
    /** PEM type. Inferred from the PEM label when omitted. */
    pemType?: "pkcs8" | "spki" | "x509";
    /** Additional JWK properties merged into the exported key (e.g. `kid`). */
    jwkParams?: JWKMetadata;
  },
): Promise<T>;
export async function importPEM(
  pem: string,
  alg: JWKPEMAlgorithm,
  options?: {
    pemType?: "pkcs8" | "spki" | "x509";
    jwkParams?: JWKMetadata;
  },
): Promise<JWK> {
  if (typeof pem !== "string") {
    throw new JWTError(
      `"pem" must be a PEM-encoded string, got ${pem === null ? "null" : typeof pem}.`,
      "ERR_INVALID_OPTION",
    );
  }
  if (options !== undefined) assertPlainObject(options, "options");
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
  return { ...jwk, alg };
}

/**
 * Exports an asymmetric JWK as PEM: PKCS#8 when it carries `d`, SPKI otherwise.
 *
 * @throws `ERR_JWK_UNSUPPORTED` for `oct` JWKs or an unknown format or algorithm;
 *   `ERR_JWK_INVALID` for a missing `alg` or a `pemFormat` that contradicts the JWK's half.
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
  assertPlainObject(jwk, "jwk");
  if (options !== undefined) assertPlainObject(options, "options");
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
 * Derives ECDH-ES key material (RFC 7518 §4.6): ECDH followed by the Concat KDF.
 *
 * @param publicKey The recipient's static public key (the ephemeral one when decrypting).
 * @param privateKey The ephemeral private key (the recipient's static one when decrypting).
 */
export async function deriveSharedSecret(
  publicKey: CryptoKey | JWK_EC_Public,
  privateKey: CryptoKey | JWK_EC_Private,
  options: {
    /** Algorithm identifier fed to the concat KDF as `AlgorithmID`. */
    enc: JWK_ECDH_ES | ContentEncryptionAlgorithm;
    /** Derived length in bits. Defaults to `enc`'s length; required for `"ECDH-ES"`. */
    keyLength?: number;
    /** Agreement PartyUInfo (apu). */
    partyUInfo?: Uint8Array<ArrayBuffer>;
    /** Agreement PartyVInfo (apv). */
    partyVInfo?: Uint8Array<ArrayBuffer>;
  },
): Promise<Uint8Array<ArrayBuffer>> {
  assertPlainObject(options, "options");
  const { enc: alg, keyLength: requestedKeyLength, partyUInfo, partyVInfo } = options;
  if (requestedKeyLength !== undefined) {
    assertDerivedKeyLength(requestedKeyLength);
  }

  // RFC 7517 §4.4: import under the `ECDH-ES*` alg a JWK may declare.
  const importAlg = (alg as string).startsWith("ECDH-ES") ? (alg as string) : "ECDH-ES";
  const pubCryptoKey = isCryptoKey(publicKey)
    ? publicKey
    : await importKey(publicKey, { alg: importAlg, expect: "public" });
  const privCryptoKey = isCryptoKey(privateKey)
    ? privateKey
    : await importKey(privateKey, { alg: importAlg, expect: "private" });

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
 * Returns the JWKs of a JWK Set, dropping non-JWK entries, optionally narrowed by `filter`.
 * An invalid set throws `ERR_JWK_INVALID`.
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
  const pairUsage = (allowed: readonly KeyUsage[], fallback: KeyUsage[]): KeyUsage[] =>
    assertPairUsages(usage(allowed, fallback), { fallback, alg });

  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      algorithm = {
        name: "HMAC",
        hash: jwsHashOf(alg),
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
        publicExponent: assertPublicExponent(options?.publicExponent),
        hash: jwsHashOf(alg),
      };
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }

    case "PS256":
    case "PS384":
    case "PS512": {
      algorithm = {
        name: "RSA-PSS",
        modulusLength: assertModulusLength(options?.modulusLength),
        publicExponent: assertPublicExponent(options?.publicExponent),
        hash: jwsHashOf(alg),
      };
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }

    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      algorithm = {
        name: "RSA-OAEP",
        modulusLength: assertModulusLength(options?.modulusLength),
        publicExponent: assertPublicExponent(options?.publicExponent),
        hash: rsaOaepHashOf(alg),
      };
      keyUsages = pairUsage(KEY_ENCRYPTION_USAGES, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
      break;
    }

    case "A128KW":
    case "A192KW":
    case "A256KW": {
      algorithm = { name: "AES-KW", length: aesBitsOf(alg) };
      keyUsages = usage(KEY_WRAPPING_USAGES, ["wrapKey", "unwrapKey"]);
      break;
    }

    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      algorithm = { name: "AES-GCM", length: aesBitsOf(alg) };
      // RFC 7518 §4.7: AES-GCMKW wraps by encrypting, so the key encrypts rather than wraps.
      keyUsages = usage(KEY_ENCRYPTION_USAGES, ["encrypt", "decrypt"]);
      break;
    }

    case "ES256":
    case "ES384":
    case "ES512": {
      const namedCurve = ECDSA_CURVES[alg];
      assertNamedCurve(options?.namedCurve, namedCurve, alg);
      algorithm = { name: "ECDSA", namedCurve };
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      break;
    }
    case "Ed25519": {
      assertNamedCurve(options?.namedCurve, "Ed25519", alg);
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      algorithm = { name: "Ed25519" };
      break;
    }
    case "EdDSA": {
      keyUsages = pairUsage(SIGNATURE_USAGES, ["sign", "verify"]);
      const namedCurve = options?.namedCurve ?? "Ed25519";
      if (namedCurve !== "Ed25519") {
        throw new JWTError(
          "Unsupported namedCurve provided. Supported values are: Ed25519",
          "ERR_JWK_UNSUPPORTED",
        );
      }
      algorithm = { name: namedCurve };
      break;
    }

    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      keyUsages = pairUsage(DERIVATION_USAGES, ["deriveBits"]);
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

function inferAesImportAlgorithm(
  enc: ContentEncryptionAlgorithm | undefined,
  cekLengthBytes: number,
): AesKeyAlgorithm | undefined {
  const bitLength = cekLengthBytes << 3;

  if (enc) {
    if (enc.includes("GCM")) {
      return {
        name: "AES-GCM",
        length: aesBitsOf(enc),
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

/** JWK members derived from the key itself, which caller metadata may not set. */
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

/** A `namedCurve` contradicting the curve `alg` fixes is refused, not ignored. */
function assertNamedCurve(requested: string | undefined, expected: string, alg: string): void {
  if (requested === undefined || requested === expected) return;
  throw new JWTError(
    `"namedCurve" ${requested} contradicts ${alg}, which is defined over ${expected}.`,
    "ERR_INVALID_OPTION",
  );
}

/** RSA public exponents are big-endian byte strings — RFC 7518 §6.3.1.2. */
function assertPublicExponent(
  publicExponent: Uint8Array<ArrayBuffer> | undefined,
): Uint8Array<ArrayBuffer> {
  if (publicExponent === undefined) return new Uint8Array([0x01, 0x00, 0x01]);
  if (!(publicExponent instanceof Uint8Array) || publicExponent.length === 0) {
    throw new JWTError(
      '"publicExponent" must be the exponent\'s big-endian bytes as a Uint8Array.',
      "ERR_INVALID_OPTION",
    );
  }
  return publicExponent;
}

/** `key_ops` each algorithm family admits — a caller's `keyUsage` may narrow it. */
const SIGNATURE_USAGES: readonly KeyUsage[] = ["sign", "verify"];
const KEY_WRAPPING_USAGES: readonly KeyUsage[] = ["wrapKey", "unwrapKey"];
const KEY_ENCRYPTION_USAGES: readonly KeyUsage[] = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
const DERIVATION_USAGES: readonly KeyUsage[] = ["deriveBits", "deriveKey"];
const CONTENT_ENCRYPTION_USAGES: readonly KeyUsage[] = ["encrypt", "decrypt"];

/** The caller's `keyUsage` when given (each entry one `alg` admits), else the default. */
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

/** The half of a generated pair each usage belongs to — RFC 7517 §4.3. */
const PRIVATE_KEY_USAGES: readonly KeyUsage[] = [
  "sign",
  "decrypt",
  "unwrapKey",
  "deriveBits",
  "deriveKey",
];
const PUBLIC_KEY_USAGES: readonly KeyUsage[] = ["verify", "encrypt", "wrapKey"];

/** Each pair half the default populates must keep a usage; ECDH public keys carry none. */
function assertPairUsages(
  usages: KeyUsage[],
  options: { fallback: KeyUsage[]; alg: string },
): KeyUsage[] {
  const { fallback, alg } = options;
  for (const [half, side] of [
    [PRIVATE_KEY_USAGES, "private"],
    [PUBLIC_KEY_USAGES, "public"],
  ] as const) {
    const wanted = fallback.filter((entry) => half.includes(entry));
    if (wanted.length === 0 || usages.some((entry) => half.includes(entry))) continue;
    throw new JWTError(
      `"keyUsage" leaves the ${side} half of a ${alg} key pair with no usage; include one of ${wanted.join(", ")}.`,
      "ERR_INVALID_OPTION",
    );
  }
  return usages;
}

/** Name a freshly generated JWK by its RFC 7638 thumbprint. */
async function withThumbprintKid<T extends JWK>(jwk: T): Promise<T> {
  return { ...jwk, kid: await thumbprint(jwk) };
}

/** Algorithms the PEM helpers round-trip; `satisfies` keeps them in lockstep with the union. */
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

/** RFC 3394 §2: AES Key Wrap needs a CEK of two or more whole 64-bit blocks. */
function assertWrappableCEK(cek: Uint8Array<ArrayBuffer>, alg: string): void {
  if (cek.length >= 16 && cek.length % 8 === 0) return;
  throw new JWTError(
    `${alg} wraps a key of 16 or more bytes in whole 8-byte blocks (got ${cek.length}).`,
    "ERR_INVALID_OPTION",
  );
}

/** RFC 7516 §11.5: every unwrap failure surfaces as one indistinguishable error. */
async function unwrapping<T>(operation: Promise<T>): Promise<T> {
  try {
    return await operation;
  } catch (error) {
    throw asDecryptionError(error);
  }
}

function assertPBES2Algorithm(alg: unknown): void {
  const pbes2: readonly string[] = PBES2_ALGORITHMS;
  if (typeof alg === "string" && pbes2.includes(alg)) return;
  throw new JWTError(
    `Password derivation is defined for ${PBES2_ALGORITHMS.join(", ")}, not ${String(alg)}.`,
    "ERR_JWK_UNSUPPORTED",
  );
}

function assertKeyBytesArg(value: unknown, name: string): void {
  if (value instanceof Uint8Array || isCryptoKey(value)) return;
  throw new JWTError(
    `"${name}" must be a Uint8Array or a CryptoKey, got ${value === null ? "null" : typeof value}.`,
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

/** RFC 7518 §4.6.1.2: attacker-supplied `apu`/`apv` feed the Concat KDF, so size is bounded. */
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

/** RSA-OAEP and ECDH-ES run on an asymmetric `CryptoKey`; raw bytes name no key pair. */
function assertCryptoKeyFor(
  alg: string,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  role: "wrapping" | "unwrapping",
): asserts key is CryptoKey {
  if (isCryptoKey(key)) return;
  throw new JWTError(
    `${alg.startsWith("RSA") ? "RSA-OAEP" : "ECDH-ES"} requires the ${role} key to be a CryptoKey`,
    "ERR_JWK_INVALID",
  );
}

/** An `unwrapKey` header parameter, given as its base64url header value or as the decoded bytes. */
function segmentBytes(
  value: string | Uint8Array<ArrayBuffer>,
  name: "p2s" | "iv" | "tag" | "apu" | "apv",
): Uint8Array<ArrayBuffer> {
  return typeof value === "string"
    ? decodeSegment(value, { family: "JWE", what: `"${name}"` })
    : value;
}
