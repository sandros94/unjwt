import { isJWK } from "../../utils/guards.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { invalidConfigError } from "./contract.ts";
import { type KeyAlgorithms, type SessionKeyEntry, servedAlgorithms } from "./key-algorithms.ts";

/** A key that opens tokens: its `kid`, the algorithms it serves and, should it serve `dir`, the `enc` values it decrypts. */
export interface KeySetEntry<K, A extends string> {
  key: K;
  kid: string | undefined;
  algorithms: readonly A[];
  encryptions?: readonly string[];
}

/** The configured keys that open tokens, in order, `current` first, with the algorithms they serve together. `rotation` is set for a `{ current, keys }` set. */
export interface SessionOpeners<K, A extends string> {
  entries: readonly KeySetEntry<K, A>[];
  rotation: boolean;
  algorithms: A[];
}

export function rotationSet(key: unknown): { current: unknown; keys?: unknown } | undefined {
  return typeof key === "object" && key !== null && "current" in key ? key : undefined;
}

/**
 * Checks `current` and the rotation keys as a set, `current` first and once: what each serves, `listed` included,
 * and at most `keyCandidates` keys without `kid`, unless a key lookup opens tokens.
 * @throws `ERR_SESSION_CONFIG_INVALID` for more keys without `kid` than `keyCandidates`, or a rule of {@link servedAlgorithms}.
 */
export function resolveKeySet<K, A extends string>(
  current: K,
  previous: readonly K[] | undefined,
  options: {
    algorithms: KeyAlgorithms<A>;
    pin: A | undefined;
    listed: readonly A[] | undefined;
    optionsPath: string;
    keyCandidates: number;
    lookup: boolean;
    prefix: string;
  },
): SessionOpeners<K, A> {
  const { pin, optionsPath, keyCandidates, lookup, prefix } = options;
  const subject = previous ? 'The session key "current"' : "The session key";
  const named: (SessionKeyEntry & { key: K })[] = [{ key: current, subject, pin }];
  previous?.forEach((entry, index) => {
    if (entry === current) return;
    const kid = kidOf(entry);
    const owned = kid === undefined ? "" : ` (kid ${quoteTokenValue(kid)})`;
    named.push({ key: entry, subject: `The session key "keys[${index}]"${owned}` });
  });
  const kidless = named.filter((entry) => kidOf(entry.key) === undefined).length;
  if (!lookup && kidless > keyCandidates) {
    throw invalidConfigError(
      `${prefix} ${kidless} session keys carry no "kid", over the limit of ${keyCandidates} ("${optionsPath}.limits.keyCandidates"): give each JWK a "kid", drop former keys, or raise the limit.`,
    );
  }
  const served = servedAlgorithms(named, {
    algorithms: options.algorithms,
    listed: options.listed,
    listPath: `${optionsPath}.algorithms`,
    lookup,
    prefix,
  });
  return {
    entries: named.map((entry, index) => ({
      key: entry.key,
      kid: kidOf(entry.key),
      algorithms: served.each[index],
    })),
    rotation: previous !== undefined,
    algorithms: served.all,
  };
}

function kidOf(key: unknown): string | undefined {
  return isJWK(key) ? key.kid : undefined;
}
