import type { JWK_HMAC, JWK_oct, JWSAlgorithm } from "../../core/types/index.ts";
import { inferJWSAllowedAlgorithms } from "../../utils/algorithms.ts";
import { isCryptoKey, isJWK, isJWKSet, isSymmetricJWK } from "../../utils/guards.ts";
import { invalidKeyError } from "./contract.ts";
import { type KeyAlgorithms, octBits } from "./key-algorithms.ts";

/** One HMAC secret: an `oct` JWK, or an HMAC `CryptoKey`. */
export type JWSSessionSecret = JWK_oct<JWK_HMAC> | CryptoKey;

/** RFC 7518 §3: a JWK's `alg`, or the curve of an EC or OKP JWK, names its algorithm. Without one, a `CryptoKey` signs with what its algorithm names, raw bytes with each HMAC their length fits (§3.2), and an RSA JWK with each RSA signature. */
export const JWS_KEY_ALGORITHMS: KeyAlgorithms<JWSAlgorithm> = {
  family: "JWS",
  own: (key) => {
    if (!isJWK(key)) return undefined;
    const inferred = inferJWSAllowedAlgorithms(key);
    return key.alg ? (inferred ?? []) : inferred;
  },
  carried: (key) => {
    if (isCryptoKey(key)) return inferJWSAllowedAlgorithms(key) ?? [];
    if (isJWK(key) && key.kty === "RSA") return RSA_SIGNATURES;
    if (!isSymmetricJWK(key)) return [];
    const bits = octBits(key);
    return HMAC_SIGNATURES.filter((alg) => bits >= Number(alg.slice(2)));
  },
};

/** A rotation set of HMAC secrets: `current` and `keys`, each an `oct` JWK or an HMAC `CryptoKey`. */
export function hmacKeys(
  key: { current: unknown; keys?: unknown },
  prefix: string,
): { current: JWSSessionSecret; previous: JWSSessionSecret[] } {
  const previous: unknown = isJWKSet(key.keys) ? key.keys.keys : key.keys;
  if (!Array.isArray(previous)) {
    throw invalidKeyError(
      `${prefix} Invalid JWS session key: "keys" must be a list of HMAC "oct" JWKs and HMAC CryptoKeys, or a JWK Set of "oct" JWKs.`,
      key,
    );
  }
  return {
    current: hmacSecret(key.current, { prefix, what: '"current"' }),
    previous: previous.map((entry: unknown) =>
      hmacSecret(entry, { prefix, what: 'each of "keys"' }),
    ),
  };
}

function hmacSecret(key: unknown, options: { prefix: string; what: string }): JWSSessionSecret {
  if (isHMACJWK(key)) return key;
  if (isCryptoKey(key) && key.algorithm.name === "HMAC") return key;
  throw invalidKeyError(
    `${options.prefix} Invalid JWS session key: ${options.what} must be an HMAC "oct" JWK or an HMAC CryptoKey.`,
    key,
  );
}

function isHMACJWK(key: unknown): key is JWK_oct<JWK_HMAC> {
  return isSymmetricJWK(key) && (key.alg === undefined || /^HS(256|384|512)$/.test(key.alg));
}

const HMAC_SIGNATURES = ["HS256", "HS384", "HS512"] as const;

const RSA_SIGNATURES: readonly JWSAlgorithm[] = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
];
