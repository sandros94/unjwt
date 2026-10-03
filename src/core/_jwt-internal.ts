import { textEncoder } from "unsecure/utils";
import { safeJsonParse } from "unsecure/sanitize";

import type { JWTClaims, JOSEPayloadMode, ExpiresIn } from "./types";
import type { JWTErrorCode } from "./error";
import { JWTError } from "./error";
import { base64UrlParse } from "./utils/base64";
import { computeDurationInSeconds, parseDurationSeconds } from "./utils/jwt";

/**
 * Apply default typ/cty semantics shared by JWS & JWE.
 * - If typ is undefined and payload is a non-Uint8Array object, set typ="JWT".
 * - If typ is "JWT" and payload is a non-Uint8Array object, ensure cty defaults to "application/json".
 */
export function applyTypCtyDefaults<T extends { typ?: string; cty?: string }>(
  header: T,
  payload: unknown,
): T {
  const declared: unknown = header.typ;
  if (declared !== undefined && typeof declared !== "string") {
    throw new JWTError('"typ" must be a string.', "ERR_INVALID_OPTION");
  }
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

/** Options for {@link parsePayloadBytes} and {@link parsePayloadSegment}. */
export interface ParsePayloadOptions {
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
 * Parse payload bytes under the caller-declared {@link JOSEPayloadMode}.
 *
 * `"json"` (the default) requires valid UTF-8 that parses to a non-null,
 * non-array object; `"string"` requires valid UTF-8; `"bytes"` returns the
 * input. A payload that does not meet the declared mode throws
 * `ERR_JWS_INVALID` / `ERR_JWE_INVALID`.
 */
export function parsePayloadBytes<T = JWTClaims>(
  bytes: Uint8Array<ArrayBuffer>,
  options?: ParsePayloadOptions,
): T | string | Uint8Array<ArrayBuffer> {
  const mode = options?.payload ?? "json";
  if (mode === "bytes") return bytes;

  const family = options?.family ?? "JWS";
  const text = parsePayloadText(bytes, { family });
  if (mode === "string") return text;
  return _parsePayloadObject<T>(text, family);
}

/**
 * Payload bytes as text, refusing anything that is not UTF-8 with
 * `ERR_JWS_INVALID` / `ERR_JWE_INVALID` (per `family`, default `"JWS"`).
 */
export function parsePayloadText(
  bytes: Uint8Array<ArrayBuffer>,
  options?: Pick<ParsePayloadOptions, "family">,
): string {
  const family = options?.family ?? "JWS";
  try {
    return _utf8Decoder.decode(bytes);
  } catch (error) {
    throw new JWTError(
      `Invalid ${family}: Payload is not valid UTF-8.`,
      `ERR_${family}_INVALID` as JWTErrorCode,
      error,
    );
  }
}

/** {@link parsePayloadBytes} over a Base64URL-encoded payload segment. */
export function parsePayloadSegment<T = JWTClaims>(
  payloadEncoded: string,
  options?: ParsePayloadOptions,
): T | string | Uint8Array<ArrayBuffer> {
  return parsePayloadBytes<T>(base64UrlParse(payloadEncoded, { returnAs: "uint8array" }), options);
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
    } else if (expiresIn !== undefined) {
      claims.exp = claims.iat + computeDurationInSeconds(expiresIn);
    }
  }

  if (wantsNbf) {
    if (notBeforeAt !== undefined) {
      claims.nbf = Math.floor(_instantOf(notBeforeAt, "notBeforeAt") / 1000);
    } else if (notBeforeIn !== undefined) {
      const offset = parseDurationSeconds(notBeforeIn);
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

// RFC 7515 §4.1.11 / RFC 7516 §4.1.13 — `crit` entries must be extension parameters the recipient
// actively processes. Every parameter registered by RFC 7515/7516/7518 is rejected outright by
// `assertCritShape`, so only `b64` (RFC 7797, an extension) is understood without opt-in.
const BASE_PROCESSED_JWS = ["b64"];
const BASE_PROCESSED_JWE: string[] = [];

/** Validate critical headers in JWS semantics. */
export function validateCriticalHeadersJWS(
  protectedHeader: { crit?: string[] } & Record<string, unknown>,
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
  protectedHeader: { crit?: string[] } & Record<string, unknown>,
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
