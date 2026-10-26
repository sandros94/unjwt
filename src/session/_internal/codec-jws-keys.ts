import type {
  JWSHeaderParameters,
  JWSKeyLookup,
  JWK_HMAC,
  JWK_oct,
  JWKSet,
  JWSAlgorithm,
  JWSAsymmetricPrivateJWK,
  JWSAsymmetricPublicJWK,
  JWSSignJWK,
  JWSVerifyJWK,
} from "../../core/types/index.ts";
import { inferJWSAllowedAlgorithms } from "../../utils/algorithms.ts";
import { isCryptoKey, isJWK, isJWKSet, isPublicJWK, isSymmetricJWK } from "../../utils/guards.ts";
import { assertKeyMaterial, invalidKeyError } from "./contract.ts";
import { assertKeyPair, isKeyPair } from "./codec.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import {
  type KeyAlgorithms,
  type SessionKeyEntry,
  assertPinnedKey,
  octBits,
  servedAlgorithms,
} from "./key-algorithms.ts";

/** An HMAC `oct` JWK, a `CryptoKey`, or a pair: `privateKey` signs, `publicKey` (a JWK, a JWK list, a JWK Set or a `CryptoKey`) verifies. A signing key without `alg` (any `CryptoKey`) requires a pinned `jws.signOptions.alg`. */
export type JWSSessionKey =
  | CryptoKey
  | JWK_oct<JWK_HMAC>
  | {
      privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
      publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
    };

interface PinOptions {
  pin: JWSAlgorithm | undefined;
  prefix: string;
}

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

/** The key that signs: a symmetric key or a `CryptoKey`, or a pair's `privateKey`. It must serve the pinned `alg`, and needs one pinned when it names none. */
export function getSignKey(key: JWSSessionKey, options: PinOptions): JWSSignJWK | CryptoKey {
  const { prefix } = options;
  assertKeyMaterial(key, { prefix });

  let resolved: JWSSignJWK | CryptoKey | undefined;
  if (isCryptoKey(key) || isSymmetricJWK(key)) {
    resolved = key;
  } else if (isKeyPair(key)) {
    assertJWSKeyPair(key, prefix);
    resolved = key.privateKey;
  }

  if (!resolved) {
    throw invalidKeyError(
      `${prefix} Invalid JWS key, expected a symmetric JWK, a key pair or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlg(resolved, {
    ...options,
    subject: isKeyPair(key) ? 'The session key "privateKey"' : "The session key",
  });
  return resolved;
}

/**
 * Resolves and checks the keys that verify, each with the algorithms it serves. `algorithms` is what they serve together,
 * the `alg` values an incoming token may carry. A JWK Set offers each token only its entries that serve the token's `alg`.
 */
export function resolveVerifyKeys(
  key: JWSSessionKey,
  options: PinOptions & { listed: JWSAlgorithm[] | undefined; lookup: boolean },
): {
  key: JWSVerifyJWK | JWKSet | CryptoKey | JWSKeyLookup<JWKSet>;
  entries: { key: unknown; algorithms: readonly JWSAlgorithm[] }[];
  algorithms: JWSAlgorithm[];
} {
  const { pin, listed, lookup, prefix } = options;
  const resolved = getVerifyKey(key, options);
  const set = isJWKSet(resolved) ? resolved.keys : undefined;
  const pair = isKeyPair(key);
  const named: SessionKeyEntry[] = (set ?? [resolved]).map((entry, index) => ({
    key: entry,
    subject: set
      ? `The session key "publicKey[${index}]"${isJWK(entry) && entry.kid !== undefined ? ` (kid ${quoteTokenValue(entry.kid)})` : ""}`
      : pair
        ? 'The session key "publicKey"'
        : "The session key",
    pin,
  }));
  const served = servedAlgorithms(named, {
    algorithms: JWS_KEY_ALGORITHMS,
    listed,
    listPath: "jws.verifyOptions.algorithms",
    lookup,
    prefix,
  });
  const entries = named.map((entry, index) => ({ key: entry.key, algorithms: served.each[index] }));
  const narrowed = set
    ? (header: JWSHeaderParameters) => ({
        keys: set.filter(
          (_, index) => header.alg !== undefined && served.each[index].includes(header.alg),
        ),
      })
    : resolved;
  return { key: narrowed, entries, algorithms: served.all };
}

/** The key that verifies: the symmetric key, or a pair's `publicKey` (a list as a JWK Set). A single public half must serve the pinned `alg`. */
function getVerifyKey(key: JWSSessionKey, options: PinOptions): JWSVerifyJWK | JWKSet | CryptoKey {
  const { prefix } = options;
  assertKeyMaterial(key, { prefix });

  let resolved: JWSVerifyJWK | JWKSet | CryptoKey | undefined;
  if (isCryptoKey(key) || isSymmetricJWK(key)) {
    resolved = key;
  } else if (isKeyPair(key)) {
    assertJWSKeyPair(key, prefix);
    resolved = Array.isArray(key.publicKey) ? { keys: key.publicKey } : key.publicKey;
  }

  if (!resolved) {
    throw invalidKeyError(
      `${prefix} Invalid JWS key, expected a symmetric JWK, a key pair or a CryptoKey.`,
      key,
    );
  }

  if (isKeyPair(key) && (isJWK(resolved) || isCryptoKey(resolved))) {
    assertPinnedAlg(resolved, { ...options, subject: 'The session key "publicKey"' });
  }
  return resolved;
}

function assertJWSKeyPair(
  key: { privateKey?: unknown; publicKey?: unknown },
  prefix: string,
): void {
  assertKeyPair(key, {
    prefix,
    family: "JWS",
    isPublic: (half) =>
      isCryptoKey(half) ||
      isPublicJWK(half) ||
      isPublicKeyList(Array.isArray(half) ? half : isJWKSet(half) ? half.keys : undefined),
    publicHalf: "a public JWK, a non-empty JWK set or a CryptoKey",
  });
}

function isPublicKeyList(keys: readonly unknown[] | undefined): boolean {
  return keys !== undefined && keys.length > 0 && keys.every((candidate) => isPublicJWK(candidate));
}

function assertPinnedAlg(key: unknown, options: PinOptions & { subject: string }): void {
  assertPinnedKey(key, {
    algorithms: JWS_KEY_ALGORITHMS,
    pinned: Boolean(options.pin),
    pinPath: "jws.signOptions.alg",
    hint: '"jws.signOptions.alg"',
    ...options,
  });
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
