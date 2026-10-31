import type { JOSELimits } from "../types/index.ts";
import { JWTError } from "../../error.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { DEFAULT_PBES2_ITERATIONS } from "../_crypto/index.ts";

/** RFC 7518 §4.6.1.2 and §4.6.1.3: the maximum size of `apu` and `apv`, in bytes. */
export const MAX_PARTY_INFO_BYTES = 1024;

export { DEFAULT_PBES2_ITERATIONS };

/**
 * Default per-call work limits: 16 signatures, 16 recipients, 8 JWK Set candidates and
 * 16 key attempts per multi call. The PBKDF2 iteration budget equals four default-cost PBES2 attempts.
 */
export const DEFAULT_JOSE_LIMITS: Readonly<Required<JOSELimits>> = /* @__PURE__ */ Object.freeze({
  signatures: 16,
  recipients: 16,
  keyCandidates: 8,
  keyAttempts: 16,
  pbes2Iterations: 4 * DEFAULT_PBES2_ITERATIONS,
});

/** Returns one limit or its default. A value that is not a positive integer is `ERR_INVALID_OPTION`. */
export function resolveLimit(limits: JOSELimits | undefined, name: keyof JOSELimits): number {
  const value = limits?.[name];
  if (value === undefined) return DEFAULT_JOSE_LIMITS[name];
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new JWTError(`"limits.${name}" must be a positive integer.`, "ERR_INVALID_OPTION");
  }
  return value;
}

/** RFC 7515 §7.2.1 and RFC 7516 §7.2.1: a signature or recipient count above `limit` is `ERR_JWS_INVALID` or `ERR_JWE_INVALID`. */
export function assertEntryLimit(
  count: number,
  limit: number,
  options: { family: "JWS" | "JWE"; what: "signatures" | "recipients" },
): void {
  if (count <= limit) return;
  throw new JWTError(
    `Invalid ${options.family}: ${count} ${options.what} exceed the limit of ${limit}.`,
    `ERR_${options.family}_INVALID`,
  );
}

/** A candidate key count above `limit` is `ERR_JWK_KEY_NOT_FOUND`. */
export function assertCandidateLimit(count: number, limit: number): void {
  if (count <= limit) return;
  throw new JWTError(
    `${count} candidate keys exceed the limit of ${limit}, narrow them with a "kid".`,
    "ERR_JWK_KEY_NOT_FOUND",
  );
}

/** The key trials one multi-signature or multi-recipient call has left. */
export interface KeyAttemptBudget {
  /** Counts one key trial. Past the limit it throws `ERR_JWK_KEY_NOT_FOUND` and stores the error on `exhausted`. */
  spend(): void;
  /** The error once the budget is spent. The call rethrows it instead of trying the next entry. */
  readonly exhausted: JWTError | undefined;
}

export function createKeyAttemptBudget(limit: number): KeyAttemptBudget {
  let remaining = limit;
  let exhausted: JWTError | undefined;
  return {
    get exhausted() {
      return exhausted;
    },
    spend() {
      if (remaining > 0) {
        remaining--;
        return;
      }
      exhausted ??= new JWTError(
        `Key attempt budget of ${limit} ("limits.keyAttempts") exhausted, narrow the keys with a "kid".`,
        "ERR_JWK_KEY_NOT_FOUND",
      );
      throw exhausted;
    },
  };
}

/** Refuses an empty or over-limit JWK Set candidate list with `ERR_JWK_KEY_NOT_FOUND`. */
export function assertJWKSetCandidates(
  candidates: readonly unknown[],
  options: { limit: number; kid: unknown },
): void {
  if (candidates.length === 0) {
    const { kid } = options;
    throw new JWTError(
      `No key found in JWK Set${kid ? ` with kid ${quoteTokenValue(kid)}` : ""}.`,
      "ERR_JWK_KEY_NOT_FOUND",
    );
  }
  assertCandidateLimit(candidates.length, options.limit);
}
