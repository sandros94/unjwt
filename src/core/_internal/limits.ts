import type { JOSELimits } from "../types/index.ts";
import { JWTError } from "../../error.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { DEFAULT_PBES2_ITERATIONS } from "../_crypto/index.ts";

/** RFC 7518 §4.6.1.2 / §4.6.1.3 — size bound on `apu` / `apv`. */
export const MAX_PARTY_INFO_BYTES = 1024;

export { DEFAULT_PBES2_ITERATIONS };

/**
 * Default per-call work limits: 16 signatures, 16 recipients, 8 JWK Set candidates,
 * and PBKDF2 iterations for four default-cost PBES2 attempts in total.
 */
export const DEFAULT_JOSE_LIMITS: Readonly<Required<JOSELimits>> = /* @__PURE__ */ Object.freeze({
  signatures: 16,
  recipients: 16,
  keyCandidates: 8,
  pbes2Iterations: 4 * DEFAULT_PBES2_ITERATIONS,
});

/** Read one limit or its default; a malformed value is `ERR_INVALID_OPTION`. */
export function resolveLimit(limits: JOSELimits | undefined, name: keyof JOSELimits): number {
  const value = limits?.[name];
  if (value === undefined) return DEFAULT_JOSE_LIMITS[name];
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new JWTError(`"limits.${name}" must be a positive integer.`, "ERR_INVALID_OPTION");
  }
  return value;
}

/** RFC 7515 §7.2.1 / RFC 7516 §7.2.1 — bound the signatures / recipients count. */
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

export function assertCandidateLimit(count: number, limit: number): void {
  if (count <= limit) return;
  throw new JWTError(
    `${count} candidate keys exceed the limit of ${limit}, narrow them with a "kid".`,
    "ERR_JWK_KEY_NOT_FOUND",
  );
}

/** Refuse an empty or over-limit JWK Set candidate list with `ERR_JWK_KEY_NOT_FOUND`. */
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
