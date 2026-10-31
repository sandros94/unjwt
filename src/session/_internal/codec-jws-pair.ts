import { isCryptoKey, isJWK, isJWKSet, isPrivateJWK, isPublicJWK } from "../../utils/guards.ts";
import { invalidKeyError } from "./contract.ts";
import type { SessionKeyEntry, SessionKeyRules } from "./key-algorithms.ts";

/** A pair's halves are what they are named: a private JWK or `CryptoKey` signs, public ones verify. */
export function assertJWSKeyPair(
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

/**
 * A pair's public half verifies what it issues under `alg`: a single half that names an algorithm names `alg`, and a list or JWK Set
 * holds an entry that serves it, by its own `alg` or, for an entry without one, by what its material carries.
 * @throws `ERR_SESSION_KEY_INVALID` for a public half that cannot verify `alg`.
 */
export function assertVerifiesIssued(
  entries: readonly SessionKeyEntry[],
  options: { alg: string; by: string; list: boolean; rules: SessionKeyRules; prefix: string },
): void {
  const { alg, by, list, rules, prefix } = options;
  const served = entries.map(({ key }) => rules.own(key) ?? rules.carried(key));
  if (served.some((algorithms) => algorithms.includes(alg))) return;
  const [{ key }] = entries;
  const own = list ? undefined : rules.own(key);
  const what = own
    ? `names "${(isJWK(key) ? key.alg : undefined) ?? own[0]}"`
    : `serves ${[...new Set(served.flat())].join(", ") || "no algorithm"}`;
  throw invalidKeyError(
    `${prefix} The session key "publicKey" ${what}, not the "${alg}" that ${by}.`,
    list ? entries.map((entry) => entry.key) : key,
  );
}

function isPublicHalf(half: unknown): boolean {
  if (isCryptoKeyOf(half, "public") || isPublicJWK(half)) return true;
  const keys = Array.isArray(half) ? half : isJWKSet(half) ? half.keys : undefined;
  return keys !== undefined && keys.length > 0 && keys.every((candidate) => isPublicJWK(candidate));
}

function isCryptoKeyOf(key: unknown, type: KeyType): key is CryptoKey {
  return isCryptoKey(key) && key.type === type;
}
