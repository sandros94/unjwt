import type { JWK, JWKSet } from "../../core/types/index.ts";
import type { JWTError } from "../../error.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { isCryptoKey, isJWK, isJWKSet } from "../../utils/guards.ts";
import { invalidConfigError, invalidKeyError } from "./contract.ts";

/** The algorithms a family reads from a key: those it names itself, else those its material can carry. */
export interface KeyAlgorithms<A extends string = string> {
  /** A JWK's `alg`, or what its shape names. `undefined` for a key that names none. */
  own: (key: unknown) => readonly A[] | undefined;
  /** The algorithms the material of a key that names none can carry. */
  carried: (key: unknown) => readonly A[];
}

/** A configured key and how messages name it. `pin` is the pinned `alg`, for a key the pin names. */
export interface SessionKeyEntry<K = unknown> {
  key: K;
  subject: string;
  pin?: string;
}

export function rotationSet(key: unknown): { current: unknown; keys?: unknown } | undefined {
  return typeof key === "object" && key !== null && "current" in key ? key : undefined;
}

/**
 * The keys of a rotation set, `current` first and once, each one `isKey` takes. At most `keyCandidates` of them may lack a `kid`,
 * unless a key lookup opens tokens.
 * @throws `ERR_SESSION_KEY_INVALID` if `keys` is not a list or a JWK Set, or a key is a `CryptoKey` or one `isKey` refuses.
 * @throws `ERR_SESSION_CONFIG_INVALID` for more keys without `kid` than `keyCandidates`.
 */
export function rotationEntries<K extends JWK>(
  set: { current: unknown; keys?: unknown },
  options: {
    isKey: (key: unknown) => key is K;
    refuse?: (key: unknown) => JWTError | undefined;
    expected: string;
    pin: string | undefined;
    optionsPath: string;
    keyCandidates: number;
    lookup: boolean;
    prefix: string;
  },
): SessionKeyEntry<K>[] {
  const { current, keys } = set;
  const { keyCandidates, prefix, expected } = options;
  const listed: unknown = isJWKSet(keys) ? keys.keys : keys;
  if (!Array.isArray(listed)) {
    throw invalidKeyError(
      `${prefix} The session key "keys" must be a list or a JWK Set of ${expected}s.`,
      set,
    );
  }
  const entries: SessionKeyEntry<K>[] = [];
  [current, ...listed].forEach((key: unknown, index) => {
    if (index > 0 && key === current) return;
    const subject = index
      ? `The session key "keys[${index - 1}]"${kidLabel(key)}`
      : 'The session key "current"';
    if (options.isKey(key)) {
      entries.push({ key, subject, pin: index ? undefined : options.pin });
      return;
    }
    throw (
      options.refuse?.(key) ??
      invalidKeyError(
        isCryptoKey(key)
          ? `${prefix} ${subject} is a CryptoKey: export it as a JWK (exportJWK), or serve it from onKeyLookup.`
          : `${prefix} ${subject} must be an ${expected}.`,
        key,
      )
    );
  });
  const kidless = entries.filter(({ key }) => key.kid === undefined).length;
  if (!options.lookup && kidless > keyCandidates) {
    throw invalidConfigError(
      `${prefix} ${kidless} session keys carry no "kid", over the limit of ${keyCandidates} ("${options.optionsPath}.limits.keyCandidates"): give each JWK a "kid", drop former keys, or raise the limit.`,
    );
  }
  return entries;
}

/**
 * A key that names its algorithm must serve `pin`. A key that names none needs the pin, and must carry it.
 * @throws `ERR_SESSION_CONFIG_INVALID` for a key that names no algorithm and nothing pins one.
 * @throws `ERR_SESSION_KEY_INVALID` for a key that cannot serve the pin.
 */
export function assertPinnedKey(
  key: unknown,
  options: {
    algorithms: KeyAlgorithms;
    pin: string | undefined;
    pinned: boolean;
    pinPath: string;
    hint: string;
    subject: string;
    prefix: string;
  },
): void {
  const { algorithms, pin, subject, prefix } = options;
  const own = algorithms.own(key);
  if (own === undefined && (!pin || !options.pinned)) {
    throw invalidConfigError(
      `${prefix} ${subject} names no algorithm, set ${options.hint}${isJWK(key) ? ', or its "alg"' : ""}.`,
    );
  }
  const served = own ?? algorithms.carried(key);
  if (!pin || served.includes(pin)) return;
  throw invalidKeyError(
    `${prefix} ${subject} serves ${served.join(", ") || "no algorithm"}, not the "${pin}" that "${options.pinPath}" pins.`,
    key,
  );
}

/**
 * Returns the keys that open tokens and the algorithms they serve together: a key's own, and for a key that names none, those it
 * carries that `listed` or its pin names. A JWK that names none opens as one copy per algorithm it serves, named by `rename`
 * when it returns a name, so a JWK Set offers each token only the keys of its `alg`. With `lookup`, a key lookup hook opens tokens,
 * so `listed` may name algorithms no key serves.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `listed` is empty, a key that names no algorithm carries none it names, or `listed` names one no key serves.
 * @throws `ERR_SESSION_KEY_INVALID` if a key that names no algorithm carries none of its family.
 */
export function servedAlgorithms<K, A extends string>(
  entries: readonly SessionKeyEntry<K>[],
  options: {
    algorithms: KeyAlgorithms<A>;
    listed: readonly A[] | undefined;
    listPath: string;
    lookup: boolean;
    prefix: string;
    rename?: (entry: SessionKeyEntry<K>, alg: A) => string | undefined;
  },
): { keys: K[]; all: A[] } {
  const { algorithms, listed, listPath, prefix } = options;
  if (listed?.length === 0) {
    throw invalidConfigError(
      `${prefix} "${listPath}" is empty, list the algorithms the session keys serve or leave it unset.`,
    );
  }
  const all = new Set<A>();
  const keys = entries.flatMap((entry): K[] => {
    const { key, pin } = entry;
    const own = algorithms.own(key);
    const carried = own ? [] : algorithms.carried(key);
    const served = own ?? carried.filter((alg) => alg === pin || listed?.includes(alg));
    if (served.length === 0) throw unservedKeyError(entry, { carried, listPath, prefix });
    for (const alg of served) all.add(alg);
    if (!isJWK(key)) return [key];
    const names = served.map((alg) => options.rename?.(entry, alg) ?? alg);
    return own && names.every((alg, index) => alg === served[index] || alg === key.alg)
      ? [key]
      : names.map((alg) => ({ ...key, alg }));
  });
  if (!options.lookup) {
    for (const alg of listed ?? []) {
      if (all.has(alg)) continue;
      throw invalidConfigError(
        `${prefix} "${listPath}" lists "${alg}", which no session key serves. Remove it, or add a key for it.`,
      );
    }
  }
  return { keys, all: [...all] };
}

/** One key opens alone. Several, or a set, open as a JWK Set, in order. */
export function openingKey<K>(keys: readonly K[], options: { set: boolean }): K | JWKSet {
  return keys.length === 1 && !options.set ? keys[0] : { keys: keys.filter((key) => isJWK(key)) };
}

/** A key's `kid` for a message: ` (kid "x")`, or nothing. */
export function kidLabel(key: unknown): string {
  return isJWK(key) && key.kid !== undefined ? ` (kid ${quoteTokenValue(key.kid)})` : "";
}

/** The bit length of an `oct` JWK's `k`, from its unpadded base64url length. */
export function octBits(key: { k: string }): number {
  return Math.floor((key.k.length * 6) / 8) * 8;
}

function unservedKeyError(
  entry: SessionKeyEntry,
  options: { carried: readonly string[]; listPath: string; prefix: string },
): JWTError {
  const { carried, prefix } = options;
  if (carried.length === 0) {
    return invalidKeyError(`${prefix} ${entry.subject} serves no algorithm.`, entry.key);
  }
  return invalidConfigError(
    `${prefix} ${entry.subject} names no algorithm, list one it serves (${carried.join(", ")}) in "${options.listPath}", or set its "alg".`,
  );
}
