import { textEncoder } from "unsecure/utils";
import { base64UrlParse } from "./base64";
import { safeJsonParse } from "unsecure/sanitize";

import type {
  JWTClaims,
  JWTClaimValidationOptions,
  JOSEPayloadMode,
  Duration,
  ExpiresIn,
} from "../types";
import { maybeArray } from "./index";
import { JWTError } from "../error";
import type { JWTErrorCode } from "../error";

/**
 * Apply default typ/cty semantics shared by JWS & JWE.
 * - If typ is undefined and payload is a non-Uint8Array object, set typ="JWT".
 * - If typ is "JWT" and payload is a non-Uint8Array object, ensure cty defaults to "application/json".
 */
export function applyTypCtyDefaults<T extends { typ?: string; cty?: string }>(
  header: T,
  payload: unknown,
): T {
  const isObjectPayload =
    typeof payload === "object" && payload !== null && !(payload instanceof Uint8Array);
  if (!isObjectPayload) return header;

  let typ = header.typ;
  if (typ === undefined) {
    header.typ = typ = "JWT";
  }
  // Skip the `toLowerCase` allocation for the literal `"JWT"` / `"jwt"` fast path.
  if (typ === "JWT" || typ === "jwt" || typ.toLowerCase().includes("jwt")) {
    header.cty ||= "application/json";
  }
  return header;
}

/** Returns true when headers indicate JSON content. */
export function isJWTContent(header: { typ?: string; cty?: string } | undefined): boolean {
  if (!header) return false;
  if (header.typ?.toLowerCase().includes("jwt")) return true;
  const cty = header.cty?.toLowerCase();
  return cty === "json" || cty === "application/json" || (!!cty && cty.endsWith("+json"));
}

/** Options for {@link decodePayloadFromBytes} and {@link decodePayloadFromB64UrlSegment}. */
export interface DecodePayloadOptions {
  /**
   * How to interpret the payload bytes — see {@link JOSEPayloadMode}.
   *
   * @default "json"
   */
  payload?: JOSEPayloadMode;
  /**
   * JOSE family the rejection is reported under, selecting between
   * `ERR_JWS_INVALID` and `ERR_JWE_INVALID`.
   *
   * @default "JWS"
   */
  family?: "JWS" | "JWE";
}

/**
 * Decode payload bytes under the caller-declared {@link JOSEPayloadMode}.
 *
 * `"json"` (the default) requires valid UTF-8 that parses to a non-null,
 * non-array object; `"string"` requires valid UTF-8; `"bytes"` returns the
 * input. A payload that does not meet the declared mode throws
 * `ERR_JWS_INVALID` / `ERR_JWE_INVALID`.
 */
export function decodePayloadFromBytes<T = JWTClaims>(
  bytes: Uint8Array<ArrayBuffer>,
  options?: DecodePayloadOptions,
): T | string | Uint8Array<ArrayBuffer> {
  const mode = options?.payload ?? "json";
  if (mode === "bytes") return bytes;

  const family = options?.family ?? "JWS";
  let text: string;
  try {
    text = _utf8Decoder.decode(bytes);
  } catch (error) {
    throw new JWTError(
      `Invalid ${family}: Payload is not valid UTF-8.`,
      `ERR_${family}_INVALID` as JWTErrorCode,
      error,
    );
  }
  if (mode === "string") return text;
  return _parsePayloadObject<T>(text, family);
}

/** {@link decodePayloadFromBytes} over a Base64URL-encoded payload segment. */
export function decodePayloadFromB64UrlSegment<T = JWTClaims>(
  payloadEncoded: string,
  options?: DecodePayloadOptions,
): T | string | Uint8Array<ArrayBuffer> {
  return decodePayloadFromBytes<T>(
    base64UrlParse(payloadEncoded, { returnAs: "uint8array" }),
    options,
  );
}

/**
 * Convert plaintext input to bytes, shared by JWS & JWE when preparing payload.
 *
 * A payload that is neither text, bytes nor an object, and one whose members
 * `JSON.stringify` refuses (a `BigInt`, a circular reference), are both caller
 * input rather than key or token material: they fail as `ERR_INVALID_OPTION`.
 */
export function getPlaintextBytes(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, unknown>,
): Uint8Array<ArrayBuffer> {
  if (payload instanceof Uint8Array) return payload;
  if (typeof payload === "string") return textEncoder.encode(payload);
  if (typeof payload === "object" && payload !== null) {
    let json: string;
    try {
      json = JSON.stringify(payload);
    } catch (error) {
      throw new JWTError("Payload is not JSON-serializable.", "ERR_INVALID_OPTION", error);
    }
    return textEncoder.encode(json);
  }
  throw new JWTError(
    "Plaintext must be a string, Uint8Array, or a JSON-serializable object.",
    "ERR_INVALID_OPTION",
  );
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

function _parseDurationSeconds(value: Duration): number {
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
  const seconds = _parseDurationSeconds(duration);
  if (seconds <= 0) {
    throw new JWTError(
      "Duration must be a positive integer number of seconds.",
      "ERR_INVALID_OPTION",
    );
  }
  return seconds;
}

/** Options for {@link computeJwtTimeClaims}. */
export interface ComputeJwtTimeClaimsOptions {
  /** Reference moment for `iat` (and for `expiresIn` / `notBeforeIn` math). Defaults to `new Date()`. */
  currentDate?: Date;
  /** Duration until `exp`, relative to `currentDate`. Mutually exclusive with `expiresAt`. */
  expiresIn?: ExpiresIn;
  /** Absolute moment for `exp`. Mutually exclusive with `expiresIn`. */
  expiresAt?: Date;
  /**
   * Duration from `iat` before which the JWT must not be accepted.
   * `0` is allowed and means `nbf = iat` (explicit temporal floor at sign time).
   * Mutually exclusive with `notBeforeAt`.
   */
  notBeforeIn?: ExpiresIn;
  /** Absolute moment for `nbf` (RFC 7519 §4.1.5). Mutually exclusive with `notBeforeIn`. */
  notBeforeAt?: Date;
}

/**
 * Compute `iat` + optional `exp` / `nbf` for any JSON-object payload.
 *
 * Returns a shallow-cloned payload with the time claims added, or `undefined`
 * when no hint applies (no expiry/nbf provided, non-object payload, or the
 * payload already carries the corresponding claim).
 *
 * `expiresIn` / `expiresAt` and `notBeforeIn` / `notBeforeAt` are each mutually
 * exclusive pairs — passing both within a pair throws `ERR_JWT_CLAIM_INVALID`.
 * Invalid `Date` inputs (NaN `.getTime()`) and negative `notBeforeIn` durations
 * also throw.
 */
export function computeJwtTimeClaims(
  payload: unknown,
  options?: ComputeJwtTimeClaimsOptions,
): JWTClaims | undefined {
  const { currentDate, expiresIn, expiresAt, notBeforeIn, notBeforeAt } = options ?? {};

  if (expiresIn !== undefined && expiresAt !== undefined) {
    throw new JWTError(
      '"expiresIn" and "expiresAt" are mutually exclusive; pass only one.',
      "ERR_JWT_CLAIM_INVALID",
    );
  }
  if (notBeforeIn !== undefined && notBeforeAt !== undefined) {
    throw new JWTError(
      '"notBeforeIn" and "notBeforeAt" are mutually exclusive; pass only one.',
      "ERR_JWT_CLAIM_INVALID",
    );
  }

  const hasExpHint = expiresIn !== undefined || expiresAt !== undefined;
  const hasNbfHint = notBeforeIn !== undefined || notBeforeAt !== undefined;
  if (!hasExpHint && !hasNbfHint) return undefined;
  if (!payload || typeof payload !== "object" || payload instanceof Uint8Array) return undefined;

  const typedPayload = payload as JWTClaims;
  const wantsExp = hasExpHint && typedPayload.exp === undefined;
  const wantsNbf = hasNbfHint && typedPayload.nbf === undefined;
  if (!wantsExp && !wantsNbf) return undefined;

  const now = Math.round((currentDate ?? new Date()).getTime() / 1000);
  const claims: JWTClaims = { ...typedPayload };
  claims.iat ||= now;

  if (wantsExp) {
    if (expiresAt !== undefined) {
      claims.exp = Math.floor(_instantOf(expiresAt, "expiresAt") / 1000);
    } else {
      claims.exp = claims.iat + computeDurationInSeconds(expiresIn!);
    }
  }

  if (wantsNbf) {
    if (notBeforeAt !== undefined) {
      claims.nbf = Math.floor(_instantOf(notBeforeAt, "notBeforeAt") / 1000);
    } else {
      const offset = _parseDurationSeconds(notBeforeIn!);
      if (offset < 0) {
        throw new JWTError(
          '"notBeforeIn" must be zero or a positive duration.',
          "ERR_JWT_CLAIM_INVALID",
        );
      }
      claims.nbf = claims.iat + offset;
    }
  }

  return claims;
}

/** Validate JWT claims under JWS verification rules (or custom JWE implementations). */
export function validateJwtClaims(
  jwtClaims: JWTClaims,
  options: JWTClaimValidationOptions = {},
): void {
  const clockTolerance = _normalizeClockTolerance(options.clockTolerance);
  const currentTime = Math.round((options.currentDate ?? new Date()).getTime() / 1000);

  // Skip the Set allocations for the common "no required claims" path.
  if (
    options.requiredClaims ||
    options.issuer ||
    options.audience ||
    options.subject ||
    options.maxTokenAge
  ) {
    const allRequiredClaims = new Set<string>(options.requiredClaims || []);
    if (options.issuer) allRequiredClaims.add("iss");
    if (options.audience) allRequiredClaims.add("aud");
    if (options.subject) allRequiredClaims.add("sub");
    if (options.maxTokenAge) allRequiredClaims.add("iat");

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

  if (options.issuer) {
    const expectedIssuers = maybeArray(options.issuer);
    if (!jwtClaims.iss || !expectedIssuers.includes(jwtClaims.iss)) {
      throw new JWTError(
        `Invalid JWT "iss" (Issuer) Claim: Expected ${expectedIssuers.join(" or ")}, got ${jwtClaims.iss}`,
        "ERR_JWT_CLAIM_INVALID",
      );
    }
  }

  if (options.subject && jwtClaims.sub !== options.subject) {
    throw new JWTError(
      `Invalid JWT "sub" (Subject) Claim: Expected ${options.subject}, got ${jwtClaims.sub}`,
      "ERR_JWT_CLAIM_INVALID",
    );
  }

  if (options.audience) {
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

  if (options.maxTokenAge) {
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

// RFC 7515 §4.1.11 / RFC 7516 §4.1.13 — `crit` entries must be extension parameters the recipient
// actively processes. Every parameter registered by RFC 7515/7516/7518 is rejected outright by
// `_assertCritShape`, so only `b64` (RFC 7797, an extension) is understood without opt-in.
const BASE_PROCESSED_JWS = ["b64"];
const BASE_PROCESSED_JWE: string[] = [];

/** Validate critical headers in JWS semantics. */
export function validateCriticalHeadersJWS(
  protectedHeader: { crit?: string[] } & Record<string, any>,
  recognizedHeaders: string[] = [],
): void {
  if (protectedHeader.crit === undefined) return;
  assertCritShape(protectedHeader.crit, { family: "JWS" });
  const missingHeaderParams = new Set<string>();
  const recognizedParams = new Set<string>([...recognizedHeaders, ...BASE_PROCESSED_JWS]);

  for (const param of protectedHeader.crit) {
    // RFC 7515 §4.1.11 — a listed parameter must be present, `b64` (RFC 7797) included.
    if (recognizedParams.has(param) && Object.hasOwn(protectedHeader, param)) continue;
    missingHeaderParams.add(param);
  }

  if (missingHeaderParams.size > 0) {
    throw new JWTError(
      `Missing critical header parameters: ${[...missingHeaderParams].join(", ")}`,
      "ERR_JWS_INVALID",
    );
  }
}

/** Validate critical headers in JWE semantics. */
export function validateCriticalHeadersJWE(
  protectedHeader: { crit?: string[] } & Record<string, any>,
  recognizedHeaders?: string[],
): void {
  if (protectedHeader.crit === undefined) return;
  assertCritShape(protectedHeader.crit, { family: "JWE" });
  const understoodParams = new Set<string>([...(recognizedHeaders || []), ...BASE_PROCESSED_JWE]);

  for (const critParam of protectedHeader.crit) {
    if (!Object.prototype.hasOwnProperty.call(protectedHeader, critParam)) {
      throw new JWTError(
        `Critical header parameter "${critParam}" listed in "crit" but not present in the protected header.`,
        "ERR_JWE_INVALID",
      );
    }
    if (!understoodParams.has(critParam)) {
      throw new JWTError(`Unprocessed critical header parameters: ${critParam}`, "ERR_JWE_INVALID");
    }
  }
}

// RFC 7515 §4.1 / RFC 7516 §4.1 / RFC 7518 — Header Parameter names registered by the JOSE
// specs. RFC 7515 §4.1.11 forbids listing any of them in `crit`; `b64` (RFC 7797) is an
// extension and is therefore absent from this set.
const REGISTERED_HEADER_PARAMS = new Set([
  "alg",
  "enc",
  "zip",
  "jku",
  "jwk",
  "kid",
  "x5u",
  "x5c",
  "x5t",
  "x5t#S256",
  "typ",
  "cty",
  "crit",
  "epk",
  "apu",
  "apv",
  "iv",
  "tag",
  "p2s",
  "p2c",
]);

/**
 * Shared `crit` shape gate for JWS and JWE (RFC 7515 §4.1.11 / RFC 7516 §4.1.13):
 * a non-empty array of strings, none of them a parameter the JOSE specs
 * register. The `code` decides whose mistake it is — a token's on the consumer
 * side, the caller's options on the producer side.
 */
export function assertCritShape(
  crit: unknown,
  options: { family: "JWS" | "JWE"; code?: JWTErrorCode },
): asserts crit is string[] {
  const { family } = options;
  const code = options.code ?? (`ERR_${family}_INVALID` as JWTErrorCode);
  if (
    !Array.isArray(crit) ||
    crit.length === 0 ||
    crit.some((param) => typeof param !== "string")
  ) {
    throw new JWTError(`Invalid ${family}: "crit" must be a non-empty array of strings.`, code);
  }
  for (const param of crit) {
    if (REGISTERED_HEADER_PARAMS.has(param)) {
      throw new JWTError(
        `Invalid ${family}: "crit" must not list registered header parameters.`,
        code,
      );
    }
  }
}

/**
 * The instant an absolute time option names. Only a `Date` names one — a number
 * of seconds, an ISO string or anything else is a malformed option rather than
 * a claim the token could carry.
 */
function _instantOf(value: Date, name: "expiresAt" | "notBeforeAt"): number {
  const ms = value instanceof Date ? value.getTime() : Number.NaN;
  if (!Number.isFinite(ms)) {
    throw new JWTError(`"${name}" must be a valid Date.`, "ERR_INVALID_OPTION");
  }
  return ms;
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

// RFC 7515 §2 / RFC 7516 §2 — payload text is UTF-8. A lenient decoder would turn
// malformed bytes into U+FFFD and hand back a string the signer never wrote.
const _utf8Decoder = /* @__PURE__ */ new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** RFC 7519 §3 — a JWT payload is a JSON object; arrays and scalars are not claims. */
function _parsePayloadObject<T>(text: string, family: "JWS" | "JWE"): T {
  const code = `ERR_${family}_INVALID` as JWTErrorCode;
  const message = `Invalid ${family}: Payload is not a JSON object.`;
  let parsed: unknown;
  try {
    parsed = safeJsonParse(text);
  } catch (error) {
    throw new JWTError(message, code, error);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new JWTError(message, code);
  }
  return parsed as T;
}
