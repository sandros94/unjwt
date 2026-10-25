import type {
  ContentEncryptionAlgorithm,
  JWK,
  JWK_ECDH_ES,
  JWK_PBES2,
  JWSAlgorithm,
  KeyManagementAlgorithm,
} from "../types/index.ts";
import { hashNameOf, lengthOf, namedCurveOf } from "../_crypto/_key-algorithm.ts";
import { hasSymmetricSecret, isCryptoKey, isCryptoKeyPair, isJWK, isJWKSet } from "./guards.ts";

/** RFC 7518 §4.8 — the password-based key management algorithms. */
export const PBES2_ALGORITHMS: readonly JWK_PBES2[] = [
  "PBES2-HS256+A128KW",
  "PBES2-HS384+A192KW",
  "PBES2-HS512+A256KW",
];

const PBES2_ALGORITHM_SET: ReadonlySet<string> = /* @__PURE__ */ new Set(PBES2_ALGORITHMS);

export function isPBES2Algorithm(alg: string): alg is JWK_PBES2 {
  return PBES2_ALGORITHM_SET.has(alg);
}

/** RFC 7518 §3.1 — every JWS `alg` this library implements; `satisfies` keeps the set in lockstep with the union. */
const JWS_ALGORITHMS: ReadonlySet<string> = /* @__PURE__ */ new Set(
  Object.keys({
    HS256: true,
    HS384: true,
    HS512: true,
    RS256: true,
    RS384: true,
    RS512: true,
    PS256: true,
    PS384: true,
    PS512: true,
    ES256: true,
    ES384: true,
    ES512: true,
    Ed25519: true,
    EdDSA: true,
  } satisfies Record<JWSAlgorithm, true>),
);

export function isJWSAlgorithm(alg: string): alg is JWSAlgorithm {
  return JWS_ALGORITHMS.has(alg);
}

/** RFC 7518 §4.1 — every JWE `alg` this library accepts on the wire; the `A*GCM` members of the union are an `oct` JWK shorthand, never a header value. */
const KEY_MANAGEMENT_ALGORITHMS: ReadonlySet<string> = /* @__PURE__ */ new Set(
  Object.keys({
    "dir": true,
    "A128KW": true,
    "A192KW": true,
    "A256KW": true,
    "A128GCMKW": true,
    "A192GCMKW": true,
    "A256GCMKW": true,
    "PBES2-HS256+A128KW": true,
    "PBES2-HS384+A192KW": true,
    "PBES2-HS512+A256KW": true,
    "RSA-OAEP": true,
    "RSA-OAEP-256": true,
    "RSA-OAEP-384": true,
    "RSA-OAEP-512": true,
    "ECDH-ES": true,
    "ECDH-ES+A128KW": true,
    "ECDH-ES+A192KW": true,
    "ECDH-ES+A256KW": true,
  } satisfies Partial<Record<KeyManagementAlgorithm, true>>),
);

export function isKeyManagementAlgorithm(alg: string): alg is KeyManagementAlgorithm {
  return KEY_MANAGEMENT_ALGORITHMS.has(alg);
}

/** RFC 7518 §4.6 — the key agreement algorithms. */
const ECDH_ES_ALGORITHMS: readonly JWK_ECDH_ES[] = [
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW",
];

const ECDH_ES_ALGORITHM_SET: ReadonlySet<string> = /* @__PURE__ */ new Set(ECDH_ES_ALGORITHMS);

export function isECDHESAlgorithm(alg: string): alg is JWK_ECDH_ES {
  return ECDH_ES_ALGORITHM_SET.has(alg);
}

/** How a JWK Set's entries are read during algorithm inference. */
export interface InferAlgorithmsOptions {
  /** Admit `oct` entries of a JWK Set. Defaults to `false`. */
  allowSymmetric?: boolean;
}

/**
 * Infer the JWS algorithms a key unambiguously supports, or `undefined` when it cannot
 * (raw bytes, ambiguous JWK, lookup function) and `options.algorithms` must be passed.
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
 * Infer the JWE key management algorithms a key unambiguously supports, or `undefined`
 * when it cannot; a password string infers the PBES2 variants, raw bytes nothing.
 */
export function inferJWEAllowedAlgorithms(
  key: unknown,
  options?: InferAlgorithmsOptions,
): KeyManagementAlgorithm[] | undefined {
  if (!key || typeof key === "function") return undefined;
  if (typeof key === "string") {
    return [...PBES2_ALGORITHMS];
  }
  if (key instanceof Uint8Array) return undefined;
  if (typeof key !== "object") return undefined;

  if (isCryptoKeyPair(key)) return inferJWEAllowedAlgorithms(key.privateKey);
  if (isJWKSet(key)) return unionFromJWKSet(key.keys, jweAlgsFromJWK, options);
  if (isCryptoKey(key)) return jweAlgsFromCryptoKey(key);
  if (isJWK(key)) return jweAlgsFromJWK(key);

  return undefined;
}

/** Union the algorithms of every usable JWK Set entry; `undefined` when none contributes. */
function unionFromJWKSet<T extends string>(
  keys: readonly JWK[],
  mapper: (k: JWK) => T[] | undefined,
  options: InferAlgorithmsOptions | undefined,
): T[] | undefined {
  const algs = new Set<T>();
  for (const k of keys) {
    if (!isJWK(k)) continue;
    if (!options?.allowSymmetric && hasSymmetricSecret(k)) continue;
    const mapped = mapper(k);
    if (!mapped) continue;
    for (const a of mapped) algs.add(a);
  }
  return algs.size > 0 ? [...algs] : undefined;
}

/** RFC 8037 `EdDSA` and the fully-specified `Ed25519` name the same signature over an Ed25519 key. */
export function isEd25519Signature(alg: string): boolean {
  return alg === "EdDSA" || alg === "Ed25519";
}

/** Whether two `alg` values name the same algorithm, `EdDSA` and `Ed25519` being one. */
export function isSameAlgorithm(a: string, b: string): boolean {
  return a === b || (isEd25519Signature(a) && isEd25519Signature(b));
}

function jwsAlgsFromJWK(jwk: JWK): JWSAlgorithm[] | undefined {
  if (jwk.alg && isEd25519Signature(jwk.alg)) return ["EdDSA", "Ed25519"];
  if (jwk.alg) return isJWSAlgorithm(jwk.alg) ? [jwk.alg] : undefined;
  // WebCrypto exports omit `alg` for EC/OKP JWKs; the curve alone identifies the signature alg.
  if (jwk.kty === "EC") {
    const crv = jwk.crv;
    if (crv === "P-256") return ["ES256"];
    if (crv === "P-384") return ["ES384"];
    if (crv === "P-521") return ["ES512"];
  }
  if (jwk.kty === "OKP") {
    const crv = jwk.crv;
    // `EdDSA` (RFC 8037) leads as the interoperable spelling.
    if (crv === "Ed25519") return ["EdDSA", "Ed25519"];
  }
  return undefined;
}

function jweAlgsFromJWK(jwk: JWK): KeyManagementAlgorithm[] | undefined {
  if (jwk.kty === "oct") return jweAlgsFromOctJWK(jwk);
  if (jwk.alg) return isKeyManagementAlgorithm(jwk.alg) ? [jwk.alg] : undefined;
  if (jwk.kty === "EC") {
    const crv = jwk.crv;
    if (crv === "P-256" || crv === "P-384" || crv === "P-521") {
      return [...ECDH_ES_ALGORITHMS];
    }
  }
  if (jwk.kty === "OKP") {
    const crv = jwk.crv;
    if (crv === "X25519") {
      return [...ECDH_ES_ALGORITHMS];
    }
  }
  return undefined;
}

/** A content encryption `alg` names a CEK (`dir` only); any other `alg` names itself. */
function jweAlgsFromOctJWK(jwk: JWK): KeyManagementAlgorithm[] | undefined {
  const alg = jwk.alg;
  if (!alg) return undefined;
  if (isContentEncryptionAlgorithm(alg)) return ["dir"];
  return isKeyManagementAlgorithm(alg) ? [alg] : undefined;
}

/** Whether `alg` is an `enc` value RFC 7518 §5 defines. */
export function isContentEncryptionAlgorithm(alg: string): alg is ContentEncryptionAlgorithm {
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
  const hashBits = jwsHashBits(hashNameOf(key.algorithm));

  switch (name) {
    case "HMAC":
      return hashBits ? [`HS${hashBits}`] : undefined;
    case "RSASSA-PKCS1-v1_5":
      return hashBits ? [`RS${hashBits}`] : undefined;
    case "RSA-PSS":
      return hashBits ? [`PS${hashBits}`] : undefined;
    case "ECDSA": {
      const curve = namedCurveOf(key.algorithm);
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
  const hashName = hashNameOf(key.algorithm);
  const length = lengthOf(key.algorithm);

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
      return [...ECDH_ES_ALGORITHMS];
    default:
      return undefined;
  }
}

/** The digest sizes a JWS algorithm name can carry (RFC 7518 §3.1). */
function jwsHashBits(hashName: string | undefined): "256" | "384" | "512" | undefined {
  if (hashName === "SHA-256") return "256";
  if (hashName === "SHA-384") return "384";
  if (hashName === "SHA-512") return "512";
  return undefined;
}
