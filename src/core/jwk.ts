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
  assertJWEEncSupported,
} from "./_internal.ts";

import type {
  JWK,
  JWK_oct,
  JWK_Public,
  JWK_Private,
  JWK_EC_Public,
  JWK_EC_Private,
  JWK_ECDH_ES,
  JWK_Asymmetric,
  JWK_Asymmetric_Algorithm,
  JWK_RSA_ENC,
  JWK_AES_GCM_KW,
  JWKPEMAlgorithm,
  JWKAlgorithm,
  ImportedPEMJWK,
  ToPublicJWKReturn,
  PEMType,
  JWKMetadata,
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
  GenerateKeyReturn,
  GenerateJWKOptions,
  GenerateJWKReturn,
  DeriveKeyOptions,
  DeriveKeyReturn,
  JWK_PBES2,
  DeriveJWKOptions,
  DeriveJWKReturn,
  KeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
  WrapKeyOptions,
  WrapKeyResult,
  WrappingKeyFor,
  UnwrapKeyOptions,
  UnwrapKeyResult,
  UnwrappingKeyFor,
} from "./types/index.ts";
import {
  assertPlainObject,
  isAsymmetricJWK,
  isCryptoKey,
  isCryptoKeyPair,
  isJWK,
  isPublicJWK,
} from "./utils/guards.ts";
import { PBES2_ALGORITHMS, isECDHESAlgorithm } from "./utils/algorithms.ts";
import { JWTError } from "./error.ts";
import { importKey } from "./_import-key.ts";
import {
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
} from "./_crypto/index.ts";
import { assertECDHKeyAllowed, ecdhDerivedBits } from "./_crypto/_ecdh.ts";
import { ecdhesWrap } from "./_crypto/_key-encryption.ts";
import {
  ECDSA_CURVES,
  aesBitsOf,
  innerKeyWrapAlg,
  jwsHashOf,
  rsaOaepHashOf,
} from "./_crypto/_key-algorithm.ts";

export type * from "./types/jwk.ts";
export {
  importKey,
  configureJWKCache,
  clearJWKCache,
  WeakMapJWKCache,
  getJWKsFromSet,
} from "./_import-key.ts";
export { thumbprint };
export type { ThumbprintHash } from "./_crypto/index.ts";
export {
  type UnsecureErrorCode,
  JWTError,
  isJWTError,
  UnsecureError,
  isUnsecureError,
} from "./error.ts";
export type { JWTErrorCode, KnownJWTErrorCode, JWTErrorCauseMap } from "./error.ts";

/**
 * Generates a key for a JWA algorithm: a `CryptoKey` for symmetric algorithms, raw bytes for
 * the `A*CBC-HS*` composites, a `CryptoKeyPair` for asymmetric ones; with `toJWK: true`, a JWK
 * (or JWK pair) named by the `kid` option or its RFC 7638 thumbprint. PBES2, `"dir"` and `"none"` are refused.
 *
 * @param options
 *   - `extractable?` — defaults to `true`; ignored when `toJWK` is set.
 *   - `kid?` — with `toJWK`, a string set verbatim or `false` for no `kid`, either skipping the
 *     thumbprint digest; anything else throws `ERR_INVALID_OPTION`.
 *   - `keyUsage?` — narrows the usages derived from `alg`; leaving either half of a pair with
 *     no usage throws `ERR_INVALID_OPTION`.
 *   - `modulusLength?` — RSA only; defaults to `2048`.
 *   - `publicExponent?` — RSA only; big-endian bytes, defaults to `0x010001`.
 *   - `namedCurve?` — EC/OKP only; defaults to `"P-256"` / `"Ed25519"`. One that contradicts
 *     the curve `ES*` or `Ed25519` names throws `ERR_INVALID_OPTION`.
 */
export async function generateKey<
  TAlg extends GenerateKeyAlgorithm,
  ToJWK extends boolean = false,
  Kid extends string | false = string,
>(
  alg: TAlg,
  options?: GenerateKeyOptions<ToJWK, Kid>,
): Promise<GenerateKeyReturn<TAlg, GenerateKeyOptions<ToJWK, Kid>>>;
export async function generateKey(
  alg: GenerateKeyAlgorithm,
  options: GenerateKeyOptions = {},
): Promise<
  CryptoKey | CryptoKeyPair | Uint8Array<ArrayBuffer> | JWK | { privateKey: JWK; publicKey: JWK }
> {
  const exportToJWK = options.toJWK !== undefined && options.toJWK;
  const defaultExtractable = exportToJWK || options.extractable !== false;
  const kid = exportToJWK ? assertKidOption(options.kid) : undefined;

  // Composite AES-CBC+HMAC keys are not importable via WebCrypto, so they stay raw bytes.
  if (alg === "A128CBC-HS256" || alg === "A192CBC-HS384" || alg === "A256CBC-HS512") {
    const keyLength = bitLengthCEK(alg);
    const keyBytes = secureRandomBytes(keyLength >> 3);

    if (exportToJWK) {
      const jwk = await keyToJWK<JWK_oct>(keyBytes);
      const keyOps =
        options.keyUsage === undefined
          ? undefined
          : resolveKeyUsage(options.keyUsage, {
              allowed: CONTENT_ENCRYPTION_USAGES,
              fallback: ["encrypt", "decrypt"],
              alg,
            });
      return withGeneratedKid(kid, withKeyOps({ ...jwk, alg }, keyOps));
    }
    return keyBytes;
  }

  const { algorithm, keyUsages } = getGenerateKeyParams(alg, options);

  const key = await crypto.subtle.generateKey(algorithm, defaultExtractable, keyUsages);

  if (exportToJWK) {
    // Force `alg`: Web Crypto's JWK export drops the `KW` suffix on AES-GCM key wrap algs.
    if (isCryptoKeyPair(key)) {
      const pairAlg = generatedPairAlgorithm(alg);
      const [pub, priv] = await Promise.all([
        exportJWK<JWK_Public>(key.publicKey),
        exportJWK<JWK_Private>(key.privateKey),
      ]);
      const publicKey = await withGeneratedKid(
        kid,
        withKeyOps(withAlg(pub, pairAlg), requestedKeyOps(options, key.publicKey)),
      );
      const named = publicKey.kid === undefined ? undefined : { kid: publicKey.kid };
      return {
        privateKey: {
          ...withKeyOps(withAlg(priv, pairAlg), requestedKeyOps(options, key.privateKey)),
          ...named,
        },
        publicKey,
      };
    }
    return withGeneratedKid(
      kid,
      withKeyOps(
        withAlg(await exportJWK<JWK_oct>(key), generatedSecretAlgorithm(alg)),
        requestedKeyOps(options, key),
      ),
    );
  }

  return key;
}

/**
 * Generates a JWK (or JWK pair) for a JWA algorithm, its `kid` the caller's, none with
 * `kid: false`, or else its RFC 7638 thumbprint. PBES2, `"dir"` and `"none"` are refused.
 *
 * @param options
 *   - `keyUsage?`, `modulusLength?` (default `2048`), `publicExponent?` (default `0x010001`),
 *     `namedCurve?` (default `"P-256"` / `"Ed25519"`); a narrowing that empties a pair half or
 *     a curve that contradicts `alg` throws `ERR_INVALID_OPTION`.
 *   - `kid?` — a string set verbatim or `false` for no `kid`, either skipping the thumbprint
 *     digest; anything else throws `ERR_INVALID_OPTION`.
 *   - JWK metadata (`use`, `x5c`, `x5t`, `x5t#S256`, `x5u`) is merged onto the result;
 *     `alg`, `kty`, `key_ops`, `ext` and key-material members are reserved (`ERR_INVALID_OPTION`).
 */
export async function generateJWK<
  TAlg extends GenerateKeyAlgorithm,
  Kid extends string | false = string,
>(
  alg: TAlg,
  options?: GenerateJWKOptions<Kid> & Omit<JWKMetadata, "kid">,
): Promise<GenerateJWKReturn<TAlg, Kid>>;
export async function generateJWK(
  alg: GenerateKeyAlgorithm,
  options?: GenerateJWKOptions & Omit<JWKMetadata, "kid">,
): Promise<JWK | { privateKey: JWK; publicKey: JWK }> {
  const {
    keyUsage,
    modulusLength,
    publicExponent,
    namedCurve,
    kid,
    extractable: _extractable,
    toJWK: _toJWK,
    ...jwkParams
  } = (options ?? {}) as GenerateJWKOptions &
    Omit<JWKMetadata, "kid"> & {
      extractable?: boolean;
      toJWK?: boolean;
    };
  assertNoReservedJWKParams(jwkParams);

  const result = await generateKey(alg, {
    keyUsage,
    modulusLength,
    publicExponent,
    namedCurve,
    kid,
    toJWK: true,
  });

  if (result && typeof result === "object" && "privateKey" in result && "publicKey" in result) {
    return {
      privateKey: { ...jwkParams, ...result.privateKey },
      publicKey: { ...jwkParams, ...result.publicKey },
    };
  }
  return { ...jwkParams, ...result };
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
    return withKeyOps(
      { ...jwk, alg: wrappingAlg, kty: "oct" },
      requestedKeyOps(options, derivedKey),
    );
  }

  return derivedKey;
}

/**
 * Derives a `JWK_oct` from a password per PBES2 (RFC 7518 §4.8); its `alg` is the inner AES-KW
 * variant and its `kid` the caller's, none with `kid: false`, or else its RFC 7638 thumbprint.
 *
 * @param options
 *   - `alg` (PBES2 only, else `ERR_JWK_UNSUPPORTED`), `salt` (at least 8 octets), `iterations`
 *     (integer of at least 1000, else `ERR_INVALID_OPTION`), `keyUsage?` (default
 *     `["wrapKey", "unwrapKey"]`).
 *   - `kid?` — a string set verbatim or `false` for no `kid`, either skipping the thumbprint
 *     digest; anything else throws `ERR_INVALID_OPTION`.
 *   - JWK metadata (`use`, `x5c`, `x5t`, `x5t#S256`, `x5u`) is merged onto the result;
 *     `alg`, `kty`, `key_ops`, `ext` and key-material members are reserved (`ERR_INVALID_OPTION`).
 */
export async function deriveJWKFromPassword<
  TAlg extends JWK_PBES2,
  Kid extends string | false = string,
>(
  password: string | Uint8Array<ArrayBuffer>,
  options: DeriveJWKOptions<TAlg, Kid> & Omit<JWKMetadata, "kid">,
): Promise<DeriveJWKReturn<TAlg, Kid>>;
export async function deriveJWKFromPassword(
  password: string | Uint8Array<ArrayBuffer>,
  options: DeriveJWKOptions & Omit<JWKMetadata, "kid">,
): Promise<JWK_oct> {
  assertPlainObject(options, "options");
  const {
    alg,
    salt,
    iterations,
    keyUsage,
    kid: kidOption,
    extractable: _extractable,
    toJWK: _toJWK,
    ...jwkParams
  } = options as DeriveKeyOptions & Omit<JWKMetadata, "kid"> & { kid?: string | false };
  assertNoReservedJWKParams(jwkParams);
  const kid = assertKidOption(kidOption);
  const result = await deriveKeyFromPassword(password, {
    alg,
    salt,
    iterations,
    keyUsage,
    toJWK: true,
  });
  return { ...jwkParams, ...(await withGeneratedKid(kid, result)) };
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
export async function exportJWK<T extends JWK = JWK>(
  key: CryptoKey,
  jwkParams?: JWKMetadata,
): Promise<T> {
  if (!isCryptoKey(key)) {
    throw new JWTError("exportJWK expects a CryptoKey.", "ERR_INVALID_OPTION");
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

/** @deprecated Use `exportJWK`; removed in 0.9.0. */
export async function exportKey<T extends JWK = JWK>(
  key: CryptoKey,
  jwkParams?: JWKMetadata,
): Promise<T> {
  return exportJWK<T>(key, jwkParams);
}

/**
 * Utility to derive the public half of an asymmetric JWK, or throw if the input is not asymmetric.
 *
 * @param jwk An asymmetric JWK (EC, OKP, RSA) with a private scalar (`d`).
 * @throws `ERR_JWK_INVALID` if the input is not an asymmetric JWK.
 * @returns A JWK with the same public members, without the private scalar.
 */
export function toPublicJWK<T extends JWK_Asymmetric>(jwk: T): ToPublicJWKReturn<T>;
export function toPublicJWK(jwk: JWK_Asymmetric): JWK_Public {
  if (!isAsymmetricJWK(jwk)) {
    throw new JWTError(
      isJWK(jwk) ? "An oct JWK has no public half." : "toPublicJWK expects an asymmetric JWK.",
      "ERR_JWK_INVALID",
    );
  }
  const copy: Record<string, unknown> = sanitizeObjectCopy({ ...jwk });
  const {
    d: _d,
    p: _p,
    q: _q,
    dp: _dp,
    dq: _dq,
    qi: _qi,
    oth: _oth,
    key_ops,
    ...publicMembers
  } = copy;
  const publicKey =
    key_ops === undefined ? publicMembers : { ...publicMembers, key_ops: publicKeyOps(key_ops) };
  if (!isPublicJWK(publicKey)) {
    throw new JWTError(
      `${jwk.kty} JWK lacks the public members of its key type.`,
      "ERR_JWK_INVALID",
    );
  }
  return publicKey;
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
      if (enc !== undefined) assertJWEEncSupported(enc);
      if (alg === "ECDH-ES" && !enc) {
        throw new JWTError(
          "ECDH-ES direct key agreement requires options.ecdh.enc",
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
          'Cannot infer the RSA-OAEP unwrapped key algorithm, pass "unwrappedKeyAlgorithm".',
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
        throw new JWTError("ECDH-ES requires 'epk' option", "ERR_JWE_INVALID");
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

      if (options.enc !== undefined) assertJWEEncSupported(options.enc);
      const infoAlg = alg === "ECDH-ES" ? options.enc : alg;

      if (!infoAlg) {
        throw new JWTError("ECDH-ES requires 'enc' to derive the shared secret", "ERR_JWE_INVALID");
      }

      const keyLength = ecdhDerivedBits(alg, options.enc);

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
export async function importPEM<
  A extends JWKPEMAlgorithm,
  Type extends PEMType | undefined = undefined,
>(
  pem: string,
  alg: A,
  options?: {
    /** PEM type. Inferred from the PEM label when omitted, which leaves the result public or private. */
    pemType?: Type;
    /** Additional JWK properties merged into the exported key (e.g. `kid`). */
    jwkParams?: JWKMetadata;
  },
): Promise<ImportedPEMJWK<A, Type>> {
  if (typeof pem !== "string") {
    throw new JWTError('"pem" must be a PEM-encoded string.', "ERR_INVALID_OPTION");
  }
  if (options !== undefined) assertPlainObject(options, "options");
  const extractable = true;
  const pemType = options?.pemType ?? inferPEMType(pem);

  if (!pemType) {
    throw new JWTError('Cannot infer PEM type from the input, pass "pemType".', "ERR_JWK_INVALID");
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

  const jwk = await exportJWK<ImportedPEMJWK<A, Type>>(cryptoKey, options?.jwkParams);
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
      "An oct JWK cannot be exported to PKCS8 or SPKI PEM.",
      "ERR_JWK_UNSUPPORTED",
    );
  }

  const effectiveAlg = jwk.alg || options?.alg;
  if (!effectiveAlg && (jwk.kty === "RSA" || jwk.kty === "EC" || jwk.kty === "OKP")) {
    throw new JWTError(
      '"alg" is required, set it on the JWK or pass it in options.',
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
          `Only a private CryptoKey can be exported to PKCS8 PEM (got ${cryptoKey.type}).`,
          "ERR_JWK_INVALID",
        );
      }
      return toPKCS8(cryptoKey);
    }
    case "spki": {
      if (cryptoKey.type !== "public") {
        throw new JWTError(
          `Only a public CryptoKey can be exported to SPKI PEM (got ${cryptoKey.type}).`,
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
  if (!isECDHESAlgorithm(alg)) assertJWEEncSupported(alg);
  if (requestedKeyLength !== undefined) {
    assertDerivedKeyLength(requestedKeyLength);
  }

  // RFC 7517 §4.4: import under the `ECDH-ES*` alg a JWK may declare.
  const importAlg: JWK_ECDH_ES = isECDHESAlgorithm(alg) ? alg : "ECDH-ES";
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
  } else if (isECDHESAlgorithm(alg)) {
    keyLength = aesBitsOf(innerKeyWrapAlg(alg));
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

function getGenerateKeyParams(
  alg: GenerateKeyAlgorithm,
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
        throw new JWTError("Unsupported namedCurve, expected Ed25519", "ERR_JWK_UNSUPPORTED");
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
            "Unsupported namedCurve, expected P-256, P-384, P-521 or X25519",
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
function assertNamedCurve(
  requested: string | undefined,
  expected: string,
  alg: GenerateKeyAlgorithm,
): void {
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
  options: { allowed: readonly KeyUsage[]; fallback: KeyUsage[]; alg: JWKAlgorithm },
): KeyUsage[] {
  const { allowed, fallback, alg } = options;
  if (requested === undefined) return fallback;
  if (!Array.isArray(requested) || requested.length === 0) {
    throw new JWTError('"keyUsage" must be a non-empty array.', "ERR_INVALID_OPTION");
  }
  const rejected = requested.filter((entry) => !allowed.includes(entry));
  if (rejected.length > 0) {
    throw new JWTError(
      `"keyUsage" ${rejected.join(", ")} cannot be served by ${alg}, use ${allowed.join(", ")}.`,
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
  options: { fallback: KeyUsage[]; alg: JWKAlgorithm },
): KeyUsage[] {
  const { fallback, alg } = options;
  for (const [half, side] of [
    [PRIVATE_KEY_USAGES, "private"],
    [PUBLIC_KEY_USAGES, "public"],
  ] as const) {
    const wanted = fallback.filter((entry) => half.includes(entry));
    if (wanted.length === 0 || usages.some((entry) => half.includes(entry))) continue;
    throw new JWTError(
      `"keyUsage" leaves the ${side} half of a ${alg} key pair unusable, add ${wanted.join(" or ")}.`,
      "ERR_INVALID_OPTION",
    );
  }
  return usages;
}

/** A `kid` option is a string, `false` or absent; anything else is refused, not ignored. */
function assertKidOption(kid: unknown): string | false | undefined {
  if (kid === undefined || kid === false || typeof kid === "string") return kid;
  throw new JWTError('"kid" must be a string or false.', "ERR_INVALID_OPTION");
}

/** Names a fresh JWK by the given `kid`, by none for `false`, else by its RFC 7638 thumbprint. */
async function withGeneratedKid<T extends JWK>(
  kid: string | false | undefined,
  jwk: T,
): Promise<T> {
  if (kid === false) return jwk;
  return { ...jwk, kid: kid ?? (await thumbprint(jwk)) };
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
function assertWrappableCEK(cek: Uint8Array<ArrayBuffer>, alg: KeyManagementAlgorithm): void {
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
  throw new JWTError(`"${name}" must be a Uint8Array or a CryptoKey.`, "ERR_INVALID_OPTION");
}

/** RFC 7518 §3.3 — an RSA key is 2048 bits or larger. */
function assertModulusLength(modulusLength: number | undefined): number {
  const length = modulusLength ?? 2048;
  if (!Number.isInteger(length) || length < 2048) {
    throw new JWTError("modulusLength must be at least 2048 bits", "ERR_INVALID_OPTION");
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
  alg: JWK_AES_GCM_KW,
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
  alg: JWK_RSA_ENC | JWK_ECDH_ES,
  key: CryptoKey | Uint8Array<ArrayBuffer>,
  role: "wrapping" | "unwrapping",
): asserts key is CryptoKey {
  if (isCryptoKey(key)) return;
  throw new JWTError(`${alg} requires the ${role} key to be a CryptoKey`, "ERR_JWK_INVALID");
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

/** The JWK with `alg` set to the algorithm it was produced for; `A` must be one its family serves. */
function withAlg<J extends JWK, A extends NonNullable<J["alg"]>>(jwk: J, alg: A): J & { alg: A } {
  return { ...jwk, alg };
}

/** Web Crypto returned a key pair, so `alg` is one of the asymmetric algorithms `generateKey` admits. */
function generatedPairAlgorithm(
  alg: GenerateKeyAlgorithm,
): Extract<GenerateKeyAlgorithm, JWK_Asymmetric_Algorithm> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the pair shape fixes the family; `getGenerateKeyParams` maps each `alg` to one
  return alg as Extract<GenerateKeyAlgorithm, JWK_Asymmetric_Algorithm>;
}

/** Web Crypto returned a single key, so `alg` is one of the symmetric algorithms `generateKey` admits. */
function generatedSecretAlgorithm(
  alg: GenerateKeyAlgorithm,
): Exclude<GenerateKeyAlgorithm, JWK_Asymmetric_Algorithm> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the secret-key shape fixes the family; `getGenerateKeyParams` maps each `alg` to one
  return alg as Exclude<GenerateKeyAlgorithm, JWK_Asymmetric_Algorithm>;
}

const PUBLIC_KEY_OPS = new Map<string, KeyUsage>([
  ["sign", "verify"],
  ["verify", "verify"],
  ["decrypt", "encrypt"],
  ["encrypt", "encrypt"],
  ["unwrapKey", "wrapKey"],
  ["wrapKey", "wrapKey"],
]);

/** The public operations of a private half's `key_ops`; ECDH's `deriveBits`/`deriveKey` have no public counterpart. */
function publicKeyOps(keyOps: unknown): KeyUsage[] {
  if (!Array.isArray(keyOps)) return [];
  const ops: KeyUsage[] = [];
  for (const op of keyOps) {
    const publicOp = typeof op === "string" ? PUBLIC_KEY_OPS.get(op) : undefined;
    if (publicOp !== undefined && !ops.includes(publicOp)) ops.push(publicOp);
  }
  return ops;
}

/** The usages a caller's `keyUsage` left on the key, to travel as `key_ops`; none when the option was not given. */
function requestedKeyOps(
  options: { keyUsage?: KeyUsage[] },
  key: CryptoKey,
): KeyUsage[] | undefined {
  return options.keyUsage === undefined ? undefined : [...key.usages];
}

function withKeyOps<J extends JWK>(jwk: J, keyOps: KeyUsage[] | undefined): J {
  return keyOps === undefined ? jwk : { ...jwk, key_ops: keyOps };
}
