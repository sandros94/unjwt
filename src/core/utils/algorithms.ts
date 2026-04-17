import type { JWK, JWSAlgorithm, KeyManagementAlgorithm } from "../types";
import { isCryptoKey, isCryptoKeyPair, isJWK, isJWKSet } from "./index";

/**
 * Infer the set of JWS signing algorithms a key unambiguously supports.
 * Returns `undefined` when inference is not possible — callers must pass
 * `options.algorithms` explicitly (raw bytes, ambiguous JWK, lookup functions, ...).
 */
export function inferJWSAllowedAlgorithms(key: unknown): JWSAlgorithm[] | undefined {
  if (!key || typeof key === "function") return undefined;
  if (typeof key === "string" || key instanceof Uint8Array) return undefined;
  if (typeof key !== "object") return undefined;

  if (isCryptoKeyPair(key)) return inferJWSAllowedAlgorithms(key.publicKey);
  if (isJWKSet(key)) return unionFromJWKSet(key.keys, jwsAlgsFromJWK);
  if (isCryptoKey(key)) return jwsAlgsFromCryptoKey(key);
  if (isJWK(key)) return jwsAlgsFromJWK(key);

  return undefined;
}

/**
 * Infer the set of JWE key-management algorithms a key unambiguously supports.
 * Returns `undefined` when inference is not possible — callers must pass
 * `options.algorithms` explicitly.
 *
 * Passwords (`string` / `Uint8Array`) infer to the three PBES2 variants.
 */
export function inferJWEAllowedAlgorithms(key: unknown): KeyManagementAlgorithm[] | undefined {
  if (!key || typeof key === "function") return undefined;
  if (typeof key === "string" || key instanceof Uint8Array) {
    return ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"];
  }
  if (typeof key !== "object") return undefined;

  if (isCryptoKeyPair(key)) return inferJWEAllowedAlgorithms(key.privateKey);
  if (isJWKSet(key)) return unionFromJWKSet(key.keys, jweAlgsFromJWK);
  if (isCryptoKey(key)) return jweAlgsFromCryptoKey(key);
  if (isJWK(key)) return jweAlgsFromJWK(key);

  return undefined;
}

// --- Internal helpers ---

function unionFromJWKSet<T extends string>(
  keys: readonly JWK[],
  mapper: (k: JWK) => T[] | undefined,
): T[] | undefined {
  const algs = new Set<T>();
  for (const k of keys) {
    const mapped = mapper(k);
    if (!mapped) return undefined;
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
    if (crv === "Ed25519") return ["Ed25519", "EdDSA"];
    if (crv === "Ed448") return ["EdDSA"];
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
    if (crv === "X25519" || crv === "X448") {
      return ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"];
    }
  }
  return undefined;
}

// Symmetric JWK inference: `dir` is always an option when `enc` matches the key length;
// library convention accepts `A*GCM` JWKs as their `A*GCMKW` wrap counterparts.
function jweAlgsFromOctJWK(jwk: JWK): KeyManagementAlgorithm[] | undefined {
  const alg = (jwk as JWK & { alg?: string }).alg;
  if (!alg) return undefined;
  if (alg === "A128GCM") return ["A128GCMKW", "dir"];
  if (alg === "A192GCM") return ["A192GCMKW", "dir"];
  if (alg === "A256GCM") return ["A256GCMKW", "dir"];
  if (alg === "A128KW" || alg === "A192KW" || alg === "A256KW") return [alg, "dir"];
  if (alg === "A128GCMKW" || alg === "A192GCMKW" || alg === "A256GCMKW") return [alg, "dir"];
  if (alg === "A128CBC-HS256" || alg === "A192CBC-HS384" || alg === "A256CBC-HS512") {
    return ["dir"];
  }
  if (alg === "dir") return ["dir"];
  return [alg as KeyManagementAlgorithm];
}

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
      return ["Ed25519", "EdDSA"];
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
    case "X448":
      return ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"];
    default:
      return undefined;
  }
}
