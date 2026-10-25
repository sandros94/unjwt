import type { JWTClaims, JWTClaimValidationOptions, Duration } from "../core/types/index.ts";
import { maybeArray } from "./array.ts";
import { JWTError, type JWTErrorCauseMap } from "../error.ts";

/** Whether headers declare JSON content: a string `typ` naming JWT, or a JSON `cty`. */
export function isJWTContent(header: { typ?: string; cty?: string } | undefined): boolean {
  if (!header) return false;
  const typ: unknown = header.typ;
  if (typeof typ === "string" && typ.toLowerCase().includes("jwt")) return true;
  const declared: unknown = header.cty;
  if (typeof declared !== "string") return false;
  const cty = declared.toLowerCase();
  return cty === "json" || cty === "application/json" || cty.endsWith("+json");
}

const TIME_CONSTANTS: Readonly<Record<string, number>> = Object.freeze({
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

/** Parse a `Duration` into integer seconds, zero and negatives included. */
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
        "Duration must be an integer or a string like '10m' or '7D'.",
        "ERR_INVALID_OPTION",
      );
    }
    const n = Number.parseInt(match[1], 10);
    const unit = match[2] || "s";
    return n * TIME_CONSTANTS[unit];
  }
  throw new JWTError(
    "Duration must be a number or a string representing time.",
    "ERR_INVALID_OPTION",
  );
}

/** Parse a `Duration` (e.g. `3600` or `"10m"`) into positive integer seconds; else `ERR_INVALID_OPTION`. */
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

/** The `ERR_JWT_EXPIRED` message for a token whose `exp` (NumericDate seconds) has passed. */
export function expiredClaimMessage(exp: number): string {
  return `JWT "exp" is in the past (${_formatNumericDate(exp)}).`;
}

/**
 * Validate JWT claims against the set expectations. A malformed expectation throws
 * `ERR_INVALID_OPTION`; an empty `audience` or `issuer` list matches no token.
 */
export function validateJwtClaims(
  jwtClaims: JWTClaims,
  options: JWTClaimValidationOptions = {},
): void {
  assertClaimValidationOptions(options);
  const clockTolerance = _normalizeClockTolerance(options.clockTolerance);
  const currentTime = (options.currentDate ?? new Date()).getTime() / 1000;

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

  _assertNumericDate(jwtClaims.exp, "exp");
  _assertNumericDate(jwtClaims.nbf, "nbf");
  _assertNumericDate(jwtClaims.iat, "iat");

  if (options.issuer !== undefined) {
    const expectedIssuers = maybeArray(options.issuer);
    if (!jwtClaims.iss || !expectedIssuers.includes(jwtClaims.iss)) {
      throw new JWTError(
        `Invalid JWT "iss": expected ${expectedIssuers.join(" or ")}, got ${jwtClaims.iss}`,
        "ERR_JWT_CLAIM_INVALID",
      );
    }
  }

  if (options.subject !== undefined && jwtClaims.sub !== options.subject) {
    throw new JWTError(
      `Invalid JWT "sub": expected ${options.subject}, got ${jwtClaims.sub}`,
      "ERR_JWT_CLAIM_INVALID",
    );
  }

  if (options.audience !== undefined) {
    const expectedAudiences = maybeArray(options.audience);
    const claimAudience = maybeArray(jwtClaims.aud || []);
    if (!claimAudience.some((aud) => expectedAudiences.includes(aud))) {
      throw new JWTError(
        `Invalid JWT "aud": expected ${expectedAudiences.join(" or ")}, got ${claimAudience.join(", ")}`,
        "ERR_JWT_CLAIM_INVALID",
      );
    }
  }

  if (typeof jwtClaims.nbf === "number" && jwtClaims.nbf > currentTime + clockTolerance) {
    throw new JWTError(
      `JWT "nbf" is in the future (${_formatNumericDate(jwtClaims.nbf)}).`,
      "ERR_JWT_NBF",
    );
  }

  if (typeof jwtClaims.exp === "number" && jwtClaims.exp <= currentTime - clockTolerance) {
    throw new JWTError(
      expiredClaimMessage(jwtClaims.exp),
      "ERR_JWT_EXPIRED",
      _expiredCause(jwtClaims),
    );
  }

  if (options.maxTokenAge !== undefined) {
    if (typeof jwtClaims.iat !== "number") {
      throw new JWTError(
        'JWT "iat" must be a number when maxTokenAge is set.',
        "ERR_JWT_CLAIM_INVALID",
      );
    }
    if (jwtClaims.iat > currentTime + clockTolerance) {
      throw new JWTError(
        `JWT "iat" is in the future (${_formatNumericDate(jwtClaims.iat)}).`,
        "ERR_JWT_CLAIM_INVALID",
      );
    }
    if (
      jwtClaims.iat <
      currentTime - computeDurationInSeconds(options.maxTokenAge) - clockTolerance
    ) {
      throw new JWTError(
        `JWT "iat" is older than maxTokenAge ${options.maxTokenAge}.`,
        "ERR_JWT_EXPIRED",
        _expiredCause(jwtClaims),
      );
    }
  }
}

/** Assert every claim validation expectation is well-formed. */
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

/** Assert a list option is an array of strings when present. */
export function assertStringList(value: unknown, name: string): void {
  if (value === undefined) return;
  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) return;
  throw new JWTError(`"${name}" must be an array of strings.`, "ERR_INVALID_OPTION");
}

/** Normalize `clockTolerance` (seconds or a `Duration`) into non-negative seconds. */
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
function _assertNumericDate(value: unknown, claim: string): void {
  if (value === undefined) return;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new JWTError(`JWT "${claim}" must be a number.`, "ERR_JWT_CLAIM_INVALID");
  }
  if (value < 0) {
    throw new JWTError(
      `JWT "${claim}" must be a non-negative NumericDate.`,
      "ERR_JWT_CLAIM_INVALID",
    );
  }
}

/** A NumericDate as an ISO instant, or as the number when it lies outside the `Date` range. */
function _formatNumericDate(seconds: number): string {
  const date = new Date(seconds * 1000);
  return Number.isFinite(date.getTime()) ? date.toISOString() : String(seconds);
}

function _expiredCause(claims: JWTClaims): JWTErrorCauseMap["ERR_JWT_EXPIRED"] {
  const { jti, iat, exp } = claims;
  return { jti: typeof jti === "string" ? jti : undefined, iat, exp };
}
