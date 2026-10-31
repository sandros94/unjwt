import { secureRandomBytes } from "unsecure/random";
import type {
  JWK,
  JWK_oct,
  JWK_Public,
  JWK_Private,
  JWKMetadata,
  GenerateKeyAlgorithm,
  GenerateKeyOptions,
  GenerateKeyReturn,
  GenerateJWKOptions,
  GenerateJWKReturn,
} from "../types/index.ts";
import { isCryptoKeyPair } from "../../utils/guards.ts";
import { keyToJWK, bitLengthCEK } from "../_crypto/index.ts";
import { exportJWK } from "./export.ts";
import {
  getGenerateKeyParams,
  CONTENT_ENCRYPTION_USAGES,
  resolveKeyUsage,
  withAlg,
  generatedPairAlgorithm,
  generatedSecretAlgorithm,
} from "./_internal/generate.ts";
import {
  assertNoReservedJWKParams,
  assertKidOption,
  withGeneratedKid,
  requestedKeyOps,
  withKeyOps,
} from "./_internal/members.ts";

/**
 * Generates a key for a JWA algorithm. Returns a `CryptoKey` for a symmetric algorithm,
 * raw bytes for the `A*CBC-HS*` composites and a `CryptoKeyPair` for an asymmetric one.
 * With `toJWK: true` it returns a JWK, or a `{ privateKey, publicKey }` JWK pair sharing one `kid`.
 *
 * @param options
 *   - `extractable?`: ignored with `toJWK`. Defaults to `true`.
 *   - `kid?`: with `toJWK`, a string used as is or `false` for no `kid`. Defaults to the RFC 7638 thumbprint.
 *   - `keyUsage?`: narrows the usages `alg` admits and is written as `key_ops`. Without it the JWK has no `key_ops`.
 *   - `modulusLength?`: RSA only, at least 2048 bits. Defaults to `2048`.
 *   - `publicExponent?`: RSA only, big-endian bytes. Defaults to `0x010001`.
 *   - `namedCurve?`: `ECDH-ES*` and `EdDSA` only. Defaults to `"P-256"` and `"Ed25519"`.
 *     `ES*` and `Ed25519` fix their curve and accept only that one.
 * @throws `ERR_JWK_UNSUPPORTED` if `alg` cannot be generated (PBES2, `"dir"`, `"none"`) or `namedCurve` is unsupported.
 * @throws `ERR_INVALID_OPTION` if an option is invalid for `alg`, or `keyUsage` leaves either half of a pair with no usage.
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

  // Web Crypto cannot import a composite AES-CBC + HMAC key: it stays raw bytes.
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
    // Web Crypto's JWK export drops the `KW` suffix of an AES-GCM key wrap `alg`.
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
 * Generates a JWK for a JWA algorithm, or a `{ privateKey, publicKey }` JWK pair sharing one `kid`.
 *
 * @param options
 *   - `keyUsage?`, `modulusLength?`, `publicExponent?`, `namedCurve?`: as on `generateKey`.
 *   - `kid?`: a string used as is or `false` for no `kid`. Defaults to the RFC 7638 thumbprint.
 *   - JWK metadata (`use`, `x5c`, `x5t`, `x5t#S256`, `x5u`) is copied onto each JWK.
 * @throws `ERR_JWK_UNSUPPORTED` if `alg` cannot be generated (PBES2, `"dir"`, `"none"`) or `namedCurve` is unsupported.
 * @throws `ERR_INVALID_OPTION` if an option is invalid for `alg`, `keyUsage` leaves a pair half with no usage,
 *   or the metadata sets `alg`, `kty`, `key_ops`, `ext` or a key material member.
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
