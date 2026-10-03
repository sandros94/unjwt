import type { JWK, JWSAlgorithm, KeyManagementAlgorithm } from "../types";
import { isCryptoKey, isCryptoKeyPair, isJWK, isJWKSet } from "./index";

/**
 * How a JWK Set's entries are read. A set is public-key material: its `oct`
 * entries only contribute when the caller admits symmetric material with
 * `allowSymmetric`.
 */
export interface InferAlgorithmsOptions {
  /** Admit `oct` entries of a JWK Set. Defaults to `false`. */
  allowSymmetric?: boolean;
}

/**
 * Infer the set of JWS signing algorithms a key unambiguously supports.
 * Returns `undefined` when inference is not possible — callers must pass
 * `options.algorithms` explicitly (raw bytes, ambiguous JWK, lookup functions, ...).
 */
export function inferJWSAllowedAlgorithms(
  key: unknown,
  options?: InferAlgorithmsOptions,
): JWSAlgorithm[] | undefined {
  if (!key || typeof key === "function") return undefined;
  if (typeof key === "string" || key instanceof Uint8Array) return undefined;
  if (typeof key !== "object") return undefined;

  if (isCryptoKeyPair(key)) return inferJWSAllowedAlgorithms(key.publicKey);
  if (isJWKSet(key)) return unionFromJWKSet(key.keys, jwsAlgsFromJWK, options);
  if (isCryptoKey(key)) return jwsAlgsFromCryptoKey(key);
  if (isJWK(key)) return jwsAlgsFromJWK(key);

  return undefined;
}

/**
 * Infer the set of JWE key-management algorithms a key unambiguously supports.
 * Returns `undefined` when inference is not possible — callers must pass
 * `options.algorithms` explicitly.
 *
 * A password `string` infers to the three PBES2 variants. Raw `Uint8Array`
 * bytes carry no role of their own and infer to nothing: the caller names the
 * algorithm, as they already do when they encrypt with such a key.
 */
export function inferJWEAllowedAlgorithms(
  key: unknown,
  options?: InferAlgorithmsOptions,
): KeyManagementAlgorithm[] | undefined {
  if (!key || typeof key === "function") return undefined;
  if (typeof key === "string") {
    return ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"];
  }
  if (key instanceof Uint8Array) return undefined;
  if (typeof key !== "object") return undefined;

  if (isCryptoKeyPair(key)) return inferJWEAllowedAlgorithms(key.privateKey);
  if (isJWKSet(key)) return unionFromJWKSet(key.keys, jweAlgsFromJWK, options);
  if (isCryptoKey(key)) return jweAlgsFromCryptoKey(key);
  if (isJWK(key)) return jweAlgsFromJWK(key);

  return undefined;
}

/**
 * Union the algorithms every usable entry of a JWK Set contributes. An entry
 * that is not a JWK, an `oct` entry the caller has not admitted, and an entry
 * whose algorithm cannot be inferred are each skipped — one such entry never
 * decides the policy for the keys around it. `undefined` means no entry
 * contributed at all.
 */
function unionFromJWKSet<T extends string>(
  keys: readonly JWK[],
  mapper: (k: JWK) => T[] | undefined,
  options: InferAlgorithmsOptions | undefined,
): T[] | undefined {
  const algs = new Set<T>();
  for (const k of keys) {
    if (!isJWK(k)) continue;
    if (k.kty === "oct" && !options?.allowSymmetric) continue;
    const mapped = mapper(k);
    if (!mapped) continue;
    for (const a of mapped) algs.add(a);
  }
  return algs.size > 0 ? [...algs] : undefined;
}

function jwsAlgsFromJWK(jwk: JWK): JWSAlgorithm[] | undefined {
  if (jwk.alg) return [jwk.alg as JWSAlgorithm];
  // WebCrypto exports omit `alg` for EC/OKP JWKs; the curve alone identifies the signature alg.
  if (jwk.kty === "EC") {
    const crv = (jwk as JWK & { crv?: string }).crv;
    if (crv === "P-256") return ["ES256"];
    if (crv === "P-384") return ["ES384"];
    if (crv === "P-521") return ["ES512"];
  }
  if (jwk.kty === "OKP") {
    const crv = (jwk as JWK & { crv?: string }).crv;
    // `EdDSA` (RFC 8037) leads: it is the interoperable spelling, so any caller
    // taking the first entry as "the" alg produces a widely accepted token.
    if (crv === "Ed25519") return ["EdDSA", "Ed25519"];
  }
  return undefined;
}

function jweAlgsFromJWK(jwk: JWK): KeyManagementAlgorithm[] | undefined {
  if (jwk.kty === "oct") return jweAlgsFromOctJWK(jwk);
  if (jwk.alg) return [jwk.alg as KeyManagementAlgorithm];
  if (jwk.kty === "EC") {
    const crv = (jwk as JWK & { crv?: string }).crv;
    if (crv === "P-256" || crv === "P-384" || crv === "P-521") {
      return ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"];
    }
  }
  if (jwk.kty === "OKP") {
    const crv = (jwk as JWK & { crv?: string }).crv;
    if (crv === "X25519") {
      return ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"];
    }
  }
  return undefined;
}

/**
 * A symmetric JWK's `alg` names the one role it holds, and roles do not alias.
 * A content encryption algorithm (`A*GCM`, `A*CBC-HS*`) names a CEK, which only
 * `dir` consumes — and `dir` then requires the token's `enc` to be that same
 * algorithm. Every other `alg` — `A*KW`, `A*GCMKW`, PBES2, `dir` itself — names
 * a key management algorithm and admits nothing else.
 */
function jweAlgsFromOctJWK(jwk: JWK): KeyManagementAlgorithm[] | undefined {
  const alg = (jwk as JWK & { alg?: string }).alg;
  if (!alg) return undefined;
  if (isContentEncryptionAlgorithm(alg)) return ["dir"];
  return [alg as KeyManagementAlgorithm];
}

/**
 * The `enc` values RFC 7518 §5 defines, as an `alg` an `oct` JWK may declare.
 * Internal to the library: the `utils` entry point does not re-export it.
 */
export function isContentEncryptionAlgorithm(alg: string): boolean {
  return CONTENT_ENCRYPTION_ALGORITHMS.has(alg);
}

const CONTENT_ENCRYPTION_ALGORITHMS: ReadonlySet<string> = /* @__PURE__ */ new Set([
  "A128GCM",
  "A192GCM",
  "A256GCM",
  "A128CBC-HS256",
  "A192CBC-HS384",
  "A256CBC-HS512",
]);

function jwsAlgsFromCryptoKey(key: CryptoKey): JWSAlgorithm[] | undefined {
  const name = key.algorithm.name;
  const hashName = (key.algorithm as { hash?: { name?: string } }).hash?.name;
  const hashBits = hashName?.startsWith("SHA-") ? hashName.slice(4) : undefined;

  switch (name) {
    case "HMAC":
      return hashBits ? [`HS${hashBits}` as JWSAlgorithm] : undefined;
    case "RSASSA-PKCS1-v1_5":
      return hashBits ? [`RS${hashBits}` as JWSAlgorithm] : undefined;
    case "RSA-PSS":
      return hashBits ? [`PS${hashBits}` as JWSAlgorithm] : undefined;
    case "ECDSA": {
      const curve = (key.algorithm as EcKeyAlgorithm).namedCurve;
      if (curve === "P-256") return ["ES256"];
      if (curve === "P-384") return ["ES384"];
      if (curve === "P-521") return ["ES512"];
      return undefined;
    }
    case "Ed25519":
      return ["EdDSA", "Ed25519"];
    default:
      return undefined;
  }
}

function jweAlgsFromCryptoKey(key: CryptoKey): KeyManagementAlgorithm[] | undefined {
  const name = key.algorithm.name;
  const hashName = (key.algorithm as { hash?: { name?: string } }).hash?.name;
  const length = (key.algorithm as AesKeyAlgorithm).length;

  switch (name) {
    case "AES-KW": {
      if (length === 128) return ["A128KW", "dir"];
      if (length === 192) return ["A192KW", "dir"];
      if (length === 256) return ["A256KW", "dir"];
      return undefined;
    }
    case "AES-GCM": {
      if (length === 128) return ["A128GCMKW", "dir"];
      if (length === 192) return ["A192GCMKW", "dir"];
      if (length === 256) return ["A256GCMKW", "dir"];
      return undefined;
    }
    case "RSA-OAEP": {
      if (hashName === "SHA-1") return ["RSA-OAEP"];
      if (hashName === "SHA-256") return ["RSA-OAEP-256"];
      if (hashName === "SHA-384") return ["RSA-OAEP-384"];
      if (hashName === "SHA-512") return ["RSA-OAEP-512"];
      return undefined;
    }
    case "ECDH":
    case "X25519":
      return ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"];
    default:
      return undefined;
  }
}
