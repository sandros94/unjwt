import type { JWTError } from "../../error.ts";
import { isCryptoKey, isJWK } from "../../utils/guards.ts";
import { invalidConfigError, invalidKeyError } from "./contract.ts";

/** The algorithms a family reads from a key: those it names itself, else those its material can carry. */
export interface KeyAlgorithms<A extends string = string> {
  family: "JWS" | "JWE";
  /** A JWK's `alg`, or what its shape names. `undefined` for a key that names none. */
  own: (key: unknown) => readonly A[] | undefined;
  /** The algorithms the material of a key that names none can carry. */
  carried: (key: unknown) => readonly A[];
}

/** A configured key and how messages name it. `pin` is the pinned `alg`, for a key the pin names. */
export interface SessionKeyEntry {
  key: unknown;
  subject: string;
  pin?: string;
}

/** What a key is, for a message: `a CryptoKey (AES-GCM)` or `a JWK without "alg"`. */
export function describeKey(key: unknown): string {
  return isCryptoKey(key) ? `a CryptoKey (${key.algorithm.name})` : 'a JWK without "alg"';
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
  const { algorithms, pin, pinPath, subject, prefix } = options;
  const own = algorithms.own(key);
  if (own === undefined) {
    if (!pin || !options.pinned) {
      const alg = isJWK(key) ? ', or its "alg"' : "";
      throw invalidConfigError(
        `${prefix} ${subject} is ${describeKey(key)} and carries no algorithm, set ${options.hint}${alg}.`,
      );
    }
    const carried = algorithms.carried(key);
    if (carried.includes(pin)) return;
    throw invalidKeyError(
      `${prefix} ${subject} is ${describeKey(key)}, which serves ${carried.join(", ") || "no algorithm"}, not the "${pin}" that "${pinPath}" pins.`,
      key,
    );
  }
  if (!pin || own.includes(pin)) return;
  const named = isJWK(key) && key.alg ? `its "alg" is "${key.alg}"` : `it serves ${own.join(", ")}`;
  throw invalidKeyError(
    `${prefix} Invalid ${algorithms.family} key, ${named} but "${pinPath}" pins "${pin}".`,
    key,
  );
}

/**
 * Returns the algorithms each key serves, and all of them together: a key's own, and for a key that names none, those it carries
 * that `listed` or its pin names. With `lookup`, a key lookup hook opens tokens, so `listed` may name algorithms no key serves.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `listed` is empty, a key that names no algorithm carries none it names, or `listed` names one no key serves.
 * @throws `ERR_SESSION_KEY_INVALID` if a key that names no algorithm carries none of its family.
 */
export function servedAlgorithms<A extends string>(
  entries: readonly SessionKeyEntry[],
  options: {
    algorithms: KeyAlgorithms<A>;
    listed: readonly A[] | undefined;
    listPath: string;
    lookup: boolean;
    prefix: string;
  },
): { each: (readonly A[])[]; all: A[] } {
  const { algorithms, listed, listPath, prefix } = options;
  if (listed?.length === 0) {
    throw invalidConfigError(
      `${prefix} "${listPath}" is empty, list the algorithms the session keys serve or leave it unset.`,
    );
  }
  const all = new Set<A>();
  const each = entries.map(({ key, subject, pin }) => {
    const own = algorithms.own(key);
    if (own) {
      for (const alg of own) all.add(alg);
      return own;
    }
    const carried = algorithms.carried(key);
    const served = carried.filter((alg) => alg === pin || listed?.includes(alg));
    if (served.length === 0) throw unservedKeyError(key, { carried, subject, listPath, prefix });
    for (const alg of served) all.add(alg);
    return served;
  });
  if (!options.lookup) {
    for (const alg of listed ?? []) {
      if (all.has(alg)) continue;
      throw invalidConfigError(
        `${prefix} "${listPath}" lists "${alg}", which no session key serves. Remove it, or add a key for it.`,
      );
    }
  }
  return { each, all: [...all] };
}

/** The bit length of an `oct` JWK's `k`, from its unpadded base64url length. */
export function octBits(key: { k: string }): number {
  return Math.floor((key.k.length * 6) / 8) * 8;
}

function unservedKeyError(
  key: unknown,
  options: { carried: readonly string[]; subject: string; listPath: string; prefix: string },
): JWTError {
  const { carried, subject, listPath, prefix } = options;
  if (carried.length === 0) {
    return invalidKeyError(
      `${prefix} ${subject} is ${describeKey(key)} and serves no algorithm.`,
      key,
    );
  }
  const alg = isJWK(key) ? ', or set its "alg"' : "";
  return invalidConfigError(
    `${prefix} ${subject} is ${describeKey(key)} and carries no algorithm, list one it serves (${carried.join(", ")}) in "${listPath}"${alg}.`,
  );
}
