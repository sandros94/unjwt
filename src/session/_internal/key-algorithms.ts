import { isCryptoKey, isJWK } from "../../utils/guards.ts";
import { invalidConfigError, invalidKeyError } from "./contract.ts";

/** The algorithms a family reads from a key: those it names itself, else those its material can carry. */
export interface KeyAlgorithms {
  family: "JWS" | "JWE";
  /** A JWK's `alg`, or what its shape names. `undefined` for a key that names none. */
  own: (key: unknown) => readonly string[] | undefined;
  /** The algorithms the material of a key that names none can carry. */
  carried: (key: unknown) => readonly string[];
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

/** The bit length of an `oct` JWK's `k`, from its unpadded base64url length. */
export function octBits(key: { k: string }): number {
  return Math.floor((key.k.length * 6) / 8) * 8;
}
