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
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { inferJWSAllowedAlgorithms } from "../../utils/algorithms.ts";
import { isCryptoKey, isJWK, isJWKSet, isPublicJWK, isSymmetricJWK } from "../../utils/guards.ts";
import { assertKeyMaterial, invalidKeyError } from "./contract.ts";
import { assertKeyPair, isKeyPair } from "./codec.ts";
import {
  type KeyAlgorithms,
  type SessionKeyEntry,
  assertPinnedKey,
  octBits,
  servedAlgorithms,
} from "./key-algorithms.ts";

/**
 * An HMAC `oct` JWK, a `CryptoKey`, or a pair: `privateKey` signs and `publicKey` (a JWK, a JWK list, a JWK Set or a `CryptoKey`)
 * verifies. A signing key without `alg` (any `CryptoKey`) requires a pinned `jws.signOptions.alg`.
 */
export type JWSSessionKey =
  | CryptoKey
  | JWK_oct<JWK_HMAC>
  | {
      privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
      publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
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
 * Resolves and checks the configured keys: the key that signs, a symmetric key or a `CryptoKey` or a pair's `privateKey`, and the
 * key or JWK Set that verifies. `algorithms` is what they serve together, the `alg` values an incoming token may carry. A pair's JWK
 * Set offers a key without `alg` to a token only under the algorithms it serves. The signing key and a single public half must serve
 * the pinned `alg`, and need one pinned when they name none.
 */
export function resolveSessionKeys(
  key: JWSSessionKey,
  options: {
    pin: JWSAlgorithm | undefined;
    listed: JWSAlgorithm[] | undefined;
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
  let issuing: SessionKeyEntry<JWSSignJWK | CryptoKey>;
  let entries: SessionKeyEntry<JWSVerifyJWK | CryptoKey>[];
  let list: readonly unknown[] | undefined;
  if (isCryptoKey(key) || isSymmetricJWK(key)) {
    issuing = { key, subject: "The session key", pin };
    entries = [issuing];
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
    throw invalidKeyError(
      `${prefix} Invalid JWS key, expected a symmetric JWK, a key pair or a CryptoKey.`,
      key,
    );
  }
  assertPinnedAlg(issuing, options);
  if (!list && issuing !== entries[0]) assertPinnedAlg(entries[0], options);
  const { each, all } = servedAlgorithms(entries, {
    ...options,
    algorithms: JWS_KEY_ALGORITHMS,
    listPath: "jws.verifyOptions.algorithms",
  });
  const verifying = list
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
  if (JWS_KEY_ALGORITHMS.own(key)) return [key];
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- each copy names an algorithm its material carries
  return served.map((alg) => ({ ...key, alg }) as JWSVerifyJWK);
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

function kidLabel(key: unknown): string {
  return isJWK(key) && key.kid !== undefined ? ` (kid ${quoteTokenValue(key.kid)})` : "";
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
