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
import { isCryptoKey, isJWK, isJWKSet, isPublicJWK, isSymmetricJWK } from "../../utils/guards.ts";
import type { JWTError } from "../../error.ts";
import { assertKeyMaterial, invalidKeyError } from "./contract.ts";
import { assertKeyPair, isKeyPair } from "./codec.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { type SessionKeyEntry, assertPinnedKey, servedAlgorithms } from "./key-algorithms.ts";
import { type JWSSessionSecret, JWS_KEY_ALGORITHMS, hmacKeys } from "./key-algorithms-jws.ts";
import { type SessionOpeners, resolveKeySet, rotationSet } from "./key-set.ts";

export type { JWSSessionSecret } from "./key-algorithms-jws.ts";

/**
 * An HMAC `oct` JWK, a `CryptoKey`, a pair, or a rotation set of HMAC secrets. A pair's `privateKey` signs and its `publicKey`
 * (a JWK, a JWK list, a JWK Set or a `CryptoKey`) verifies. A rotation set's `current` signs (its `kid` is written to the header) and
 * verifies, and `keys` verify too: a token that names a `kid` is tried with the keys of that `kid` alone, one that names none with
 * every key; of those, the keys that serve its `alg` are tried in order, `current` first. A signing key without `alg` (any `CryptoKey`)
 * requires a pinned `jws.signOptions.alg`.
 */
export type JWSSessionKey =
  | CryptoKey
  | JWK_oct<JWK_HMAC>
  | {
      privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
      publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
    }
  | {
      /** Signs every token, and verifies. */
      current: JWSSessionSecret;
      /**
       * Verify too, `current` need not be repeated: HMAC `oct` JWKs and HMAC `CryptoKey`s, or a JWK Set of `oct` JWKs.
       * At most `jws.verifyOptions.limits.keyCandidates` keys, `current` included, may lack a `kid`, as any `CryptoKey` does.
       */
      keys: JWSSessionSecret[] | JWKSet<JWK_oct<JWK_HMAC>[]>;
    };

interface PinOptions {
  pin: JWSAlgorithm | undefined;
  prefix: string;
}

/** The key that signs: a symmetric key or a `CryptoKey`, or a pair's `privateKey`. It must serve the pinned `alg`, and needs one pinned when it names none. */
export function getSignKey(key: JWSSessionKey, options: PinOptions): JWSSignJWK | CryptoKey {
  const { prefix } = options;
  assertKeyMaterial(key, { prefix });

  const set = rotationSet(key);
  let resolved: JWSSignJWK | CryptoKey | undefined;
  let subject = "The session key";
  if (isCryptoKey(key) || isSymmetricJWK(key)) {
    resolved = key;
  } else if (isKeyPair(key)) {
    assertJWSKeyPair(key, prefix);
    resolved = key.privateKey;
    subject = 'The session key "privateKey"';
  } else if (set) {
    resolved = hmacKeys(set, prefix).current;
    subject = 'The session key "current"';
  }

  if (!resolved) throw unknownKeyError(key, prefix);
  assertPinnedAlg(resolved, { ...options, subject });
  return resolved;
}

/**
 * Resolves and checks the keys that verify, each with the algorithms it serves. `algorithms` is what they serve together,
 * the `alg` values an incoming token may carry. A JWK Set offers each token only its entries that serve the token's `alg`.
 */
export function resolveVerifyKeys(
  key: JWSSessionKey,
  options: PinOptions & {
    listed: JWSAlgorithm[] | undefined;
    keyCandidates: number;
    lookup: boolean;
  },
):
  | SessionOpeners<JWSSessionSecret, JWSAlgorithm>
  | {
      key: JWSVerifyJWK | JWKSet | CryptoKey | JWSKeyLookup<JWKSet>;
      entries: { key: unknown; algorithms: readonly JWSAlgorithm[] }[];
      algorithms: JWSAlgorithm[];
    } {
  const { pin, listed, lookup, prefix } = options;
  const rotation = rotationSet(key);
  if (rotation) {
    const { current, previous } = hmacKeys(rotation, prefix);
    return resolveKeySet(current, previous, {
      ...options,
      algorithms: JWS_KEY_ALGORITHMS,
      optionsPath: "jws.verifyOptions",
    });
  }
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

  if (!resolved) throw unknownKeyError(key, prefix);

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

function unknownKeyError(key: unknown, prefix: string): JWTError<"ERR_SESSION_KEY_INVALID"> {
  return invalidKeyError(
    `${prefix} Invalid JWS key, expected a symmetric JWK, a key pair, a CryptoKey or { current, keys }.`,
    key,
  );
}
