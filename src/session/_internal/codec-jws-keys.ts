import type { JWTError } from "../../error.ts";
import type {
  JOSELimits,
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
import {
  isAsymmetricJWK,
  isCryptoKey,
  isJWK,
  isJWKSet,
  isPrivateJWK,
  isPublicJWK,
  isSymmetricJWK,
} from "../../utils/guards.ts";
import { assertKeyMaterial, invalidKeyError } from "./contract.ts";
import {
  type ResolvedSessionKeys,
  type SessionKeyEntry,
  type SessionKeyRules,
  assertPinnedKey,
  isKeyPair,
  kidLabel,
  octBits,
  servedAlgorithms,
  sessionKeySetEntries,
} from "./key-algorithms.ts";

/**
 * A symmetric key that signs and verifies, an HMAC `oct` JWK or a secret `CryptoKey`, a JWK Set of HMAC `oct` JWKs, or a pair:
 * `privateKey` signs and `publicKey` (a JWK, a JWK list, a JWK Set or a `CryptoKey`) verifies. A key without `alg` (a `CryptoKey`, an
 * `oct` JWK without `alg`) requires a pinned `jws.signOptions.alg`. A JWK Set's first key signs and every key verifies, each checked as
 * a lone key, the pin naming the first alone; a token of a key without `kid` may meet at most
 * `jws.verifyOptions.limits.keyCandidates` keys, those whose `alg` serves it and those without `alg`. A lone
 * asymmetric key throws `ERR_SESSION_KEY_INVALID`: it signs with one half and verifies with the other, so pass both as a pair.
 */
export type JWSSessionKey =
  | CryptoKey
  | JWK_oct<JWK_HMAC>
  | JWKSet<JWK_oct<JWK_HMAC>[]>
  | {
      privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
      publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
    };

/** RFC 7518 §3: a JWK's `alg`, or the curve of an EC or OKP JWK, names its algorithm. Without one, a `CryptoKey` signs with what its algorithm names, an `oct` JWK with each HMAC its length fits (§3.2), and an RSA JWK with each RSA signature. */
const JWS_KEY_RULES: SessionKeyRules<JWSAlgorithm> = {
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
  pinPath: "jws.signOptions.alg",
  hint: '"jws.signOptions.alg"',
  listPath: "jws.verifyOptions.algorithms",
  limitPath: "jws.verifyOptions.limits.keyCandidates",
};

/**
 * Resolves and checks the configured keys: the key that signs, a symmetric key, a JWK Set's first key or a pair's `privateKey`, and
 * the key or JWK Set that verifies. A pair's JWK Set offers a key without `alg` to a token only under the algorithms it serves. The
 * signing key and a single public half must serve the pinned `alg`, and need one pinned when they name none.
 */
export function resolveSessionKeys(
  key: JWSSessionKey,
  options: {
    alg: JWSAlgorithm | undefined;
    listed: JWSAlgorithm[] | undefined;
    limits: JOSELimits | undefined;
    lookup: boolean;
    prefix: string;
  },
): ResolvedSessionKeys<JWSSignJWK | CryptoKey, JWSVerifyJWK | JWKSet | CryptoKey, JWSAlgorithm> {
  const { alg: pin, prefix } = options;
  assertKeyMaterial(key, { prefix });
  let issuing: SessionKeyEntry<JWSSignJWK | CryptoKey>;
  let entries: SessionKeyEntry<JWSVerifyJWK | CryptoKey>[];
  let list: readonly unknown[] | undefined;
  if ((isCryptoKey(key) && key.type === "secret") || isSymmetricJWK(key)) {
    issuing = { key, subject: "The session key", pin };
    entries = [issuing];
  } else if (isJWKSet(key)) {
    const set = sessionKeySetEntries(key.keys, { ...options, pin, rules: JWS_KEY_RULES });
    [issuing] = set;
    entries = set;
  } else if (isKeyPair(key)) {
    assertJWSKeyPair(key, prefix);
    issuing = { key: key.privateKey, subject: 'The session key "privateKey"', pin };
    const half = key.publicKey;
    list = Array.isArray(half) ? half : isJWKSet(half) ? half.keys : undefined;
    entries = (list ?? [half]).map((entry, index) => ({
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a pair's public JWK Set holds public JWKs, checked with the pair
      key: entry as JWSVerifyJWK | CryptoKey,
      subject: list
        ? `The session key "publicKey[${index}]"${kidLabel(entry)}`
        : 'The session key "publicKey"',
      pin,
    }));
  } else {
    throw invalidJWSKeyError(key, prefix);
  }
  const pinning = { rules: JWS_KEY_RULES, pinned: Boolean(pin), prefix };
  assertPinnedKey(issuing, pinning);
  if (!list && issuing !== entries[0]) assertPinnedKey(entries[0], pinning);
  const { each, all } = servedAlgorithms(entries, { ...options, rules: JWS_KEY_RULES });
  const verifying = isJWKSet(key)
    ? key
    : list
      ? { keys: entries.flatMap(({ key: entry }, index) => servedCopies(entry, each[index])) }
      : entries[0].key;
  return { issueKey: issuing.key, key: verifying, algorithms: all };
}

/** A JWK without `alg` as one copy per algorithm it serves, so a JWK Set offers it to a token of those alone. */
function servedCopies(
  key: JWSVerifyJWK | CryptoKey,
  served: readonly JWSAlgorithm[],
): JWSVerifyJWK[] {
  if (!isJWK(key)) return [];
  if (JWS_KEY_RULES.own(key)) return [key];
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- each copy names an algorithm its material carries
  return served.map((alg) => ({ ...key, alg }) as JWSVerifyJWK);
}

/** A pair's halves are what they are named: a private JWK or `CryptoKey` signs, public ones verify. */
function assertJWSKeyPair(
  pair: { privateKey?: unknown; publicKey?: unknown },
  prefix: string,
): void {
  const { privateKey, publicKey } = pair;
  if (!isPrivateJWK(privateKey) && !isCryptoKeyOf(privateKey, "private")) {
    throw invalidKeyError(
      `${prefix} Invalid JWS session key: "privateKey" must be a private JWK or a private CryptoKey.`,
      pair,
    );
  }
  if (!isPublicHalf(publicKey)) {
    throw invalidKeyError(
      `${prefix} Invalid JWS session key: "publicKey" must be a public JWK, a non-empty list or JWK Set of them, or a public CryptoKey.`,
      pair,
    );
  }
}

function isPublicHalf(half: unknown): boolean {
  if (isCryptoKeyOf(half, "public") || isPublicJWK(half)) return true;
  const keys = Array.isArray(half) ? half : isJWKSet(half) ? half.keys : undefined;
  return keys !== undefined && keys.length > 0 && keys.every((candidate) => isPublicJWK(candidate));
}

function isCryptoKeyOf(key: unknown, type: KeyType): key is CryptoKey {
  return isCryptoKey(key) && key.type === type;
}

/** A lone asymmetric key cannot both sign and verify. Anything else is not a JWS session key. */
function invalidJWSKeyError(key: unknown, prefix: string): JWTError {
  return invalidKeyError(
    isCryptoKey(key) || isAsymmetricJWK(key)
      ? `${prefix} Invalid JWS session key: an asymmetric key signs with its private half and verifies with its public half, pass both as { privateKey, publicKey }.`
      : `${prefix} Invalid JWS session key: expected an HMAC "oct" JWK, a JWK Set of them, a secret CryptoKey or a key pair.`,
    key,
  );
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
