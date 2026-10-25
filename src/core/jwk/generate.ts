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
