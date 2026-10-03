import type { JWTClaims, JWTClaimValidationOptions, Duration } from "../types";
import { maybeArray } from "./index";
import { JWTError } from "../error";

/**
 * Returns true when headers indicate JSON content: a `typ` naming JWT, or a
 * JSON `cty`. A `typ` or `cty` that is not a string indicates nothing.
 */
export function isJWTContent(header: { typ?: string; cty?: string } | undefined): boolean {
  if (!header) return false;
  const typ: unknown = header.typ;
  if (typeof typ === "string" && typ.toLowerCase().includes("jwt")) return true;
  const declared: unknown = header.cty;
  if (typeof declared !== "string") return false;
  const cty = declared.toLowerCase();
  return cty === "json" || cty === "application/json" || cty.endsWith("+json");
}

const TIME_CONSTANTS = Object.freeze({
  s: 1,
  second: 1,
  seconds: 1,
  m: 60,
  minute: 60,
  minutes: 60,
  h: 3600,
  hour: 3600,
  hours: 3600,
  D: 86_400,
  day: 86_400,
  days: 86_400,
  W: 604_800,
  week: 604_800,
  weeks: 604_800,
  M: 2_592_000,
  month: 2_592_000,
  months: 2_592_000,
  Y: 31_536_000,
  year: 31_536_000,
  years: 31_536_000,
});
const DURATION_REGEX =
  /^(\d+)(s|second|seconds|m|minute|minutes|h|hour|hours|D|day|days|W|week|weeks|M|month|months|Y|year|years)?$/;

/**
 * Parse a {@link Duration} into an integer number of seconds, zero and
 * negatives included. Internal to the library: the `utils` entry point does
 * not re-export it.
 */
export function parseDurationSeconds(value: Duration): number {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new JWTError("Duration must be an integer number of seconds.", "ERR_INVALID_OPTION");
    }
    return value;
  }
  if (typeof value === "string") {
    const match = value.match(DURATION_REGEX);
    if (!match || !match[1]) {
      throw new JWTError(
        "Invalid duration format. Must be an integer or a string like '10m', '2h', '7D', etc.",
        "ERR_INVALID_OPTION",
      );
    }
    const n = Number.parseInt(match[1], 10);
    const unit = (match[2] || "s") as keyof typeof TIME_CONSTANTS;
    return n * TIME_CONSTANTS[unit];
  }
  throw new JWTError(
    "Duration must be a number or a string representing time.",
    "ERR_INVALID_OPTION",
  );
}

/**
 * Parse a {@link Duration} (integer seconds or shorthand string like `"10m"`)
 * into a positive integer number of seconds. Used for `expiresIn`-style inputs
 * where `0` / negatives are invalid. A malformed value is an `ERR_INVALID_OPTION`.
 *
 * For inputs that legitimately permit `0` (e.g. `notBeforeIn: 0`), compute the
 * bounds at the call site instead.
 */
export function computeDurationInSeconds(duration: Duration): number {
  const seconds = parseDurationSeconds(duration);
  if (seconds <= 0) {
    throw new JWTError(
      "Duration must be a positive integer number of seconds.",
      "ERR_INVALID_OPTION",
    );
  }
  return seconds;
}

/**
 * Validate JWT claims under JWS verification rules (or custom JWE implementations).
 *
 * Each expectation is checked when it is set: `issuer`, `audience` and `subject`
 * name non-empty strings, `requiredClaims` is an array of claim names, and
 * `maxTokenAge` is a positive duration. An empty or malformed expectation is
 * `ERR_INVALID_OPTION` rather than a check that is skipped; an empty `audience`
 * or `issuer` list is a check no token satisfies.
 */
export function validateJwtClaims(
  jwtClaims: JWTClaims,
  options: JWTClaimValidationOptions = {},
): void {
  assertClaimValidationOptions(options);
  const clockTolerance = _normalizeClockTolerance(options.clockTolerance);
  const currentTime = Math.round((options.currentDate ?? new Date()).getTime() / 1000);

  // Skip the Set allocations for the common "no required claims" path.
  if (
    options.requiredClaims !== undefined ||
    options.issuer !== undefined ||
    options.audience !== undefined ||
    options.subject !== undefined ||
    options.maxTokenAge !== undefined
  ) {
    const allRequiredClaims = new Set<string>(options.requiredClaims);
    if (options.issuer !== undefined) allRequiredClaims.add("iss");
    if (options.audience !== undefined) allRequiredClaims.add("aud");
    if (options.subject !== undefined) allRequiredClaims.add("sub");
    if (options.maxTokenAge !== undefined) allRequiredClaims.add("iat");

    const missingClaims: string[] = [];
    for (const claimName of allRequiredClaims) {
      if (!Object.hasOwn(jwtClaims, claimName)) missingClaims.push(claimName);
    }
    if (missingClaims.length > 0) {
      throw new JWTError(
        `Missing required JWT Claims: ${missingClaims.join(", ")}`,
        "ERR_JWT_CLAIM_MISSING",
      );
    }
  }

  // RFC 7519 §2 — `exp`, `nbf`, `iat` are NumericDate: a finite, non-negative number of
  // seconds since the epoch. Fractional values are explicitly allowed.
  _assertNumericDate(jwtClaims.exp, "exp", "Expiration Time");
  _assertNumericDate(jwtClaims.nbf, "nbf", "Not Before");
  _assertNumericDate(jwtClaims.iat, "iat", "Issued At");

  if (options.issuer !== undefined) {
    const expectedIssuers = maybeArray(options.issuer);
    if (!jwtClaims.iss || !expectedIssuers.includes(jwtClaims.iss)) {
      throw new JWTError(
        `Invalid JWT "iss" (Issuer) Claim: Expected ${expectedIssuers.join(" or ")}, got ${jwtClaims.iss}`,
        "ERR_JWT_CLAIM_INVALID",
      );
    }
  }

  if (options.subject !== undefined && jwtClaims.sub !== options.subject) {
    throw new JWTError(
      `Invalid JWT "sub" (Subject) Claim: Expected ${options.subject}, got ${jwtClaims.sub}`,
      "ERR_JWT_CLAIM_INVALID",
    );
  }

  if (options.audience !== undefined) {
    const expectedAudiences = maybeArray(options.audience);
    const claimAudience = maybeArray(jwtClaims.aud || []);
    if (!claimAudience.some((aud) => expectedAudiences.includes(aud))) {
      throw new JWTError(
        `Invalid JWT "aud" (Audience) Claim: Expected ${expectedAudiences.join(" or ")}, got ${claimAudience.join(", ")}`,
        "ERR_JWT_CLAIM_INVALID",
      );
    }
  }

  if (typeof jwtClaims.nbf === "number" && jwtClaims.nbf > currentTime + clockTolerance) {
    throw new JWTError(
      `JWT "nbf" (Not Before) Claim validation failed: Token is not yet valid (nbf: ${new Date(jwtClaims.nbf * 1000).toISOString()})`,
      "ERR_JWT_NBF",
    );
  }

  if (typeof jwtClaims.exp === "number" && jwtClaims.exp <= currentTime - clockTolerance) {
    throw new JWTError(
      `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(jwtClaims.exp * 1000).toISOString()})`,
      "ERR_JWT_EXPIRED",
      { jti: jwtClaims.jti, iat: jwtClaims.iat, exp: jwtClaims.exp },
    );
  }

  if (options.maxTokenAge !== undefined) {
    if (typeof jwtClaims.iat !== "number") {
      throw new JWTError(
        'JWT "iat" (Issued At) Claim must be a number when maxTokenAge is set.',
        "ERR_JWT_CLAIM_INVALID",
      );
    }
    if (jwtClaims.iat > currentTime + clockTolerance) {
      throw new JWTError(
        `JWT "iat" (Issued At) Claim validation failed: Token was issued in the future (iat: ${new Date(jwtClaims.iat * 1000).toISOString()})`,
        "ERR_JWT_CLAIM_INVALID",
      );
    }
    if (
      jwtClaims.iat <
      currentTime - computeDurationInSeconds(options.maxTokenAge) - clockTolerance
    ) {
      throw new JWTError(
        `JWT "iat" (Issued At) Claim validation failed: Token is too old (maxTokenAge: ${options.maxTokenAge}, iat: ${new Date(jwtClaims.iat * 1000).toISOString()})`,
        "ERR_JWT_EXPIRED",
        { jti: jwtClaims.jti, iat: jwtClaims.iat, exp: jwtClaims.exp },
      );
    }
  }
}

/**
 * The shape of every {@link JWTClaimValidationOptions} expectation, checked
 * before any claim is read. Internal to the library: the `utils` entry point
 * does not re-export it.
 */
export function assertClaimValidationOptions(options: JWTClaimValidationOptions): void {
  _assertExpectedValues(options.issuer, "issuer");
  _assertExpectedValues(options.audience, "audience");
  const subject: unknown = options.subject;
  if (subject !== undefined && !_isNonEmptyString(subject)) {
    throw new JWTError('"subject" must be a non-empty string.', "ERR_INVALID_OPTION");
  }
  if (options.maxTokenAge !== undefined) computeDurationInSeconds(options.maxTokenAge);
  assertStringList(options.requiredClaims, "requiredClaims");
  _normalizeClockTolerance(options.clockTolerance);
}

/**
 * A list option (an allowlist, claim or header names) is an array of strings
 * when present. Internal to the library: the `utils` entry point does not
 * re-export it.
 */
export function assertStringList(value: unknown, name: string): void {
  if (value === undefined) return;
  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) return;
  throw new JWTError(`"${name}" must be an array of strings.`, "ERR_INVALID_OPTION");
}

/** Normalize `clockTolerance` (seconds or a {@link Duration}) into non-negative seconds. */
function _normalizeClockTolerance(value: number | Duration | undefined): number {
  if (value === undefined) return 0;
  let seconds: number;
  if (typeof value === "number") {
    seconds = value;
  } else if (typeof value === "string") {
    try {
      seconds = computeDurationInSeconds(value);
    } catch {
      throw _invalidClockTolerance();
    }
  } else {
    throw _invalidClockTolerance();
  }
  if (!Number.isFinite(seconds) || seconds < 0) throw _invalidClockTolerance();
  return seconds;
}

function _invalidClockTolerance(): JWTError {
  return new JWTError(
    "clockTolerance must be a non-negative number of seconds or a Duration.",
    "ERR_INVALID_OPTION",
  );
}

/** An expected `iss` / `aud`: one non-empty string, or a list of them. */
function _assertExpectedValues(value: unknown, name: "issuer" | "audience"): void {
  if (value === undefined || _isNonEmptyString(value)) return;
  if (Array.isArray(value) && value.every((entry) => _isNonEmptyString(entry))) return;
  throw new JWTError(
    `"${name}" must be a non-empty string or an array of non-empty strings.`,
    "ERR_INVALID_OPTION",
  );
}

function _isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}

/** RFC 7519 §2 — a NumericDate is a finite, non-negative number (fractions allowed). */
function _assertNumericDate(value: unknown, claim: string, label: string): void {
  if (value === undefined) return;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new JWTError(
      `JWT "${claim}" (${label}) Claim must be a number.`,
      "ERR_JWT_CLAIM_INVALID",
    );
  }
  if (value < 0) {
    throw new JWTError(
      `JWT "${claim}" (${label}) Claim must be a non-negative NumericDate.`,
      "ERR_JWT_CLAIM_INVALID",
    );
  }
}
