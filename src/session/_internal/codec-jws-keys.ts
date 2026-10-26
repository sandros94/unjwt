import type {
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
import {
  type KeyAlgorithms,
  type SessionKeyEntry,
  assertPinnedKey,
  kidLabel,
  octBits,
  openingKey,
  rotationEntries,
  rotationSet,
  servedAlgorithms,
} from "./key-algorithms.ts";

/** One HMAC secret of a rotation set: an `oct` JWK. */
export type JWSSessionSecret = JWK_oct<JWK_HMAC>;

/**
 * An HMAC `oct` JWK, a `CryptoKey`, a pair, or a rotation set of HMAC `oct` JWKs. A pair's `privateKey` signs and its `publicKey`
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
       * Verify too, `current` need not be repeated: HMAC `oct` JWKs, or a JWK Set of them. At most
       * `jws.verifyOptions.limits.keyCandidates` keys, `current` included, may lack a `kid`. A `CryptoKey` goes in as a JWK
       * (`exportJWK`), or is served from `onKeyLookup`.
       */
      keys: JWSSessionSecret[] | JWKSet<JWSSessionSecret[]>;
    };

/** RFC 7518 §3: a JWK's `alg`, or the curve of an EC or OKP JWK, names its algorithm. Without one, a `CryptoKey` signs with what its algorithm names, an `oct` JWK with each HMAC its length fits (§3.2), and an RSA JWK with each RSA signature. */
const JWS_KEY_ALGORITHMS: KeyAlgorithms<JWSAlgorithm> = {
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

/**
 * Resolves and checks the configured keys: the key that signs, a symmetric key or a `CryptoKey`, a pair's `privateKey` or a
 * rotation set's `current`, and the key or JWK Set that verifies. `algorithms` is what they serve together, the `alg` values an
 * incoming token may carry. A JWK Set offers each token only the keys of its `kid` and its `alg`, in order. The signing key and a
 * single public half must serve the pinned `alg`, and need one pinned when they name none.
 */
export function resolveSessionKeys(
  key: JWSSessionKey,
  options: {
    pin: JWSAlgorithm | undefined;
    listed: JWSAlgorithm[] | undefined;
    keyCandidates: number;
    lookup: boolean;
    prefix: string;
  },
): {
  issueKey: JWSSignJWK | CryptoKey;
  key: JWSVerifyJWK | JWKSet | CryptoKey;
  algorithms: JWSAlgorithm[];
} {
  const { pin, prefix } = options;
  assertKeyMaterial(key, { prefix });
  const rotation = rotationSet(key);
  let entries: SessionKeyEntry<JWSVerifyJWK | CryptoKey>[];
  let issuing: SessionKeyEntry<JWSSignJWK | CryptoKey>;
  let set = rotation !== undefined;
  if (isCryptoKey(key) || isSymmetricJWK(key)) {
    issuing = { key, subject: "The session key", pin };
    entries = [issuing];
  } else if (isKeyPair(key)) {
    assertJWSKeyPair(key, prefix);
    issuing = { key: key.privateKey, subject: 'The session key "privateKey"', pin };
    const half = key.publicKey;
    const list = Array.isArray(half) ? half : isJWKSet(half) ? half.keys : undefined;
    set = list !== undefined;
    entries = (list ?? [half]).map((entry, index) => ({
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a pair's public JWK Set holds public JWKs, checked with the pair
      key: entry as JWSVerifyJWK | CryptoKey,
      subject: list
        ? `The session key "publicKey[${index}]"${kidLabel(entry)}`
        : 'The session key "publicKey"',
      pin,
    }));
  } else if (rotation) {
    const secrets = rotationEntries(rotation, {
      ...options,
      isKey: isHMACJWK,
      expected: 'HMAC "oct" JWK',
      optionsPath: "jws.verifyOptions",
    });
    [issuing] = secrets;
    entries = secrets;
  } else {
    throw invalidKeyError(
      `${prefix} Invalid JWS key, expected a symmetric JWK, a key pair, a CryptoKey or { current, keys }.`,
      key,
    );
  }
  assertPinnedAlg(issuing, options);
  if (!set && issuing !== entries[0]) assertPinnedAlg(entries[0], options);
  const { keys, all } = servedAlgorithms(entries, {
    ...options,
    algorithms: JWS_KEY_ALGORITHMS,
    listPath: "jws.verifyOptions.algorithms",
  });
  return { issueKey: issuing.key, key: openingKey(keys, { set }), algorithms: all };
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

function isHMACJWK(key: unknown): key is JWSSessionSecret {
  return isSymmetricJWK(key) && (key.alg === undefined || /^HS(256|384|512)$/.test(key.alg));
}

function assertPinnedAlg(
  entry: SessionKeyEntry,
  options: { pin: JWSAlgorithm | undefined; prefix: string },
): void {
  assertPinnedKey(entry.key, {
    algorithms: JWS_KEY_ALGORITHMS,
    pin: options.pin,
    pinned: Boolean(options.pin),
    pinPath: "jws.signOptions.alg",
    hint: '"jws.signOptions.alg"',
    subject: entry.subject,
    prefix: options.prefix,
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
