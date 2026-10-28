import type { JOSELimits } from "../../core/types/index.ts";
import { resolveLimit } from "../../core/_internal/limits.ts";
import type { JWTError } from "../../error.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { isJWK, isSymmetricJWK } from "../../utils/guards.ts";
import { invalidConfigError, invalidKeyError } from "./contract.ts";

/** How a family reads the algorithms of its keys, and the options its messages name. */
export interface SessionKeyRules<A extends string = string> {
  /** A JWK's `alg`, or what its shape names. `undefined` for a key that names none. */
  own: (key: unknown) => readonly A[] | undefined;
  /** The algorithms the material of a key that names none can carry. */
  carried: (key: unknown) => readonly A[];
  /** The option that pins the `alg` each token is issued with. */
  pinPath: string;
  /** What a key that names no algorithm must have pinned. */
  hint: string;
  /** The option that lists the algorithms an incoming token may carry. */
  listPath: string;
  /** The option that caps the keys a token is offered. */
  limitPath: string;
}

/** A configured key and how messages name it. `pin` is the pinned `alg`, for a key the pin names. */
export interface SessionKeyEntry<K = unknown> {
  key: K;
  subject: string;
  pin?: string;
}

/** The configured keys of a session: the key that issues, the key or JWK Set that opens, and the `alg` values an incoming token may carry. */
export interface ResolvedSessionKeys<IssueKey, OpenKey, A extends string> {
  issueKey: IssueKey;
  key: OpenKey;
  algorithms: A[];
}

/**
 * The entries of a JWK Set session key, each an `oct` JWK named by its index and `kid`. The first issues, so it alone carries `pin`.
 * @throws `ERR_SESSION_KEY_INVALID` for an empty Set, or an entry that is not an `oct` JWK.
 * @throws `ERR_SESSION_CONFIG_INVALID` for more entries without `kid` than `limits.keyCandidates`.
 */
export function sessionKeySetEntries<K>(
  keys: readonly K[],
  options: {
    pin: string | undefined;
    limits: JOSELimits | undefined;
    rules: SessionKeyRules;
    prefix: string;
  },
): SessionKeyEntry<K>[] {
  const { prefix } = options;
  if (keys.length === 0) {
    throw invalidKeyError(`${prefix} The session key is an empty JWK Set.`);
  }
  let kidless = 0;
  const entries = keys.map((key, index) => {
    const subject = `The session key "keys[${index}]"${kidLabel(key)}`;
    if (!isSymmetricJWK(key)) {
      throw invalidKeyError(`${prefix} ${subject} must be an "oct" JWK.`, key);
    }
    if (key.kid === undefined) kidless++;
    return { key, subject, pin: index ? undefined : options.pin };
  });
  const limit = resolveLimit(options.limits, "keyCandidates");
  if (kidless > limit) {
    throw invalidConfigError(
      `${prefix} ${kidless} session keys without "kid" exceed the limit of ${limit} ("${options.rules.limitPath}").`,
    );
  }
  return entries;
}

/**
 * A key that names its algorithm must serve `pin`. A key that names none needs the pin, `pinned` when the family needs more than `alg`,
 * and must carry it.
 * @throws `ERR_SESSION_CONFIG_INVALID` for a key that names no algorithm and nothing pins one.
 * @throws `ERR_SESSION_KEY_INVALID` for a key that cannot serve the pin.
 */
export function assertPinnedKey(
  entry: SessionKeyEntry,
  options: { rules: SessionKeyRules; pinned: boolean; prefix: string },
): void {
  const { rules, prefix } = options;
  const { key, pin, subject } = entry;
  const own = rules.own(key);
  if (own === undefined && (!pin || !options.pinned)) {
    throw invalidConfigError(
      `${prefix} ${subject} names no algorithm, set ${rules.hint}${isJWK(key) ? ', or its "alg"' : ""}.`,
    );
  }
  const served = own ?? rules.carried(key);
  if (!pin || served.includes(pin)) return;
  throw invalidKeyError(
    `${prefix} ${subject} serves ${served.join(", ") || "no algorithm"}, not the "${pin}" that "${rules.pinPath}" pins.`,
    key,
  );
}

/**
 * Returns the algorithms each key serves, and those a token may carry: what the keys serve together, a key's own and for a key that
 * names none those it carries that `listed` or its pin names. With `lookup`, a key lookup hook opens tokens, so `listed` may name
 * algorithms no key serves, and a token may carry them too.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `listed` is empty, a key that names no algorithm carries none it names, or `listed` names one no key serves.
 * @throws `ERR_SESSION_KEY_INVALID` if a key carries no algorithm of its family.
 */
export function servedAlgorithms<A extends string>(
  entries: readonly SessionKeyEntry[],
  options: {
    rules: SessionKeyRules<A>;
    listed: readonly A[] | undefined;
    lookup: boolean;
    prefix: string;
  },
): { each: (readonly A[])[]; all: A[] } {
  const { rules, listed, prefix } = options;
  const { listPath } = rules;
  if (listed?.length === 0) {
    throw invalidConfigError(
      `${prefix} "${listPath}" is empty, list the algorithms the session keys serve or leave it unset.`,
    );
  }
  const all = new Set<A>();
  const each = entries.map((entry) => {
    const own = rules.own(entry.key);
    const carried = own ? [] : rules.carried(entry.key);
    const served = own ?? carried.filter((alg) => alg === entry.pin || listed?.includes(alg));
    if (served.length === 0) throw unservedKeyError(entry, { carried, listPath, prefix });
    for (const alg of served) all.add(alg);
    return served;
  });
  for (const alg of listed ?? []) {
    if (all.has(alg)) continue;
    if (!options.lookup) {
      throw invalidConfigError(
        `${prefix} "${listPath}" lists "${alg}", which no session key serves. Remove it, or add a key for it.`,
      );
    }
    all.add(alg);
  }
  return { each, all: [...all] };
}

export function isKeyPair(key: unknown): key is { privateKey?: unknown; publicKey?: unknown } {
  return typeof key === "object" && key !== null && ("privateKey" in key || "publicKey" in key);
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
