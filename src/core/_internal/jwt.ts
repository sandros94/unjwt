import { textEncoder } from "unsecure/utils";
import { safeJsonParse } from "unsecure/sanitize";

import type {
  JOSEPayload,
  JWTClaims,
  JOSEPayloadMode,
  JWTTimeClaimOptions,
  PayloadOf,
} from "../types/index.ts";
import type { JWTErrorCode } from "../../error.ts";
import { JWTError } from "../../error.ts";
import { base64UrlParse } from "../../utils/base64.ts";
import { isPlainObject } from "../../utils/guards.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import { computeDurationInSeconds, parseDurationSeconds } from "../../utils/jwt.ts";

/** Set `typ: "JWT"` on a header without `typ` when the payload is an object (not a `Uint8Array`). */
export function applyTypDefault<T extends { typ?: string }>(header: T, payload: unknown): T {
  const declared: unknown = header.typ;
  if (declared !== undefined && typeof declared !== "string") {
    throw new JWTError('"typ" must be a string.', "ERR_INVALID_OPTION");
  }
  if (
    declared === undefined &&
    typeof payload === "object" &&
    payload !== null &&
    !(payload instanceof Uint8Array)
  ) {
    header.typ = "JWT";
  }
  return header;
}

/** Options for {@link parsePayloadBytes} and {@link parsePayloadSegment}. */
export interface ParsePayloadOptions<Mode extends JOSEPayloadMode = JOSEPayloadMode> {
  /** How to interpret the payload bytes; the return type follows it. @default "json" */
  payload?: Mode;
  /** Family the rejection is reported under (`ERR_JWS_INVALID` / `ERR_JWE_INVALID`). @default "JWS" */
  family?: "JWS" | "JWE";
}

/** Parse payload bytes under the declared mode: `"json"` needs a UTF-8 JSON object, `"string"` UTF-8; throws `ERR_JWS_INVALID` / `ERR_JWE_INVALID`. */
// oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- the claims type is the caller's return contract, as on verify
export function parsePayloadBytes<T = JWTClaims>(
  bytes: Uint8Array<ArrayBuffer>,
  options?: ParsePayloadOptions<"json">,
): T;
export function parsePayloadBytes<Mode extends JOSEPayloadMode = JOSEPayloadMode>(
  bytes: Uint8Array<ArrayBuffer>,
  options?: ParsePayloadOptions<Mode>,
): PayloadOf<Mode>;
export function parsePayloadBytes(
  bytes: Uint8Array<ArrayBuffer>,
  options?: ParsePayloadOptions,
): PayloadOf<JOSEPayloadMode> {
  const mode = options?.payload ?? "json";
  if (mode === "bytes") return bytes;

  const family = options?.family ?? "JWS";
  const text = parsePayloadText(bytes, { family });
  if (mode === "string") return text;
  return _parsePayloadObject(text, family);
}

/** Decode payload bytes as UTF-8; throws `ERR_JWS_INVALID` / `ERR_JWE_INVALID` otherwise. */
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
      `ERR_${family}_INVALID`,
      error,
    );
  }
}

/** {@link parsePayloadBytes} over a Base64URL-encoded payload segment. */
// oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- the claims type is the caller's return contract, as on verify
export function parsePayloadSegment<T = JWTClaims>(
  payloadEncoded: string,
  options?: ParsePayloadOptions<"json">,
): T;
export function parsePayloadSegment<Mode extends JOSEPayloadMode = JOSEPayloadMode>(
  payloadEncoded: string,
  options?: ParsePayloadOptions<Mode>,
): PayloadOf<Mode>;
export function parsePayloadSegment(
  payloadEncoded: string,
  options?: ParsePayloadOptions,
): PayloadOf<JOSEPayloadMode> {
  return parsePayloadBytes(base64UrlParse(payloadEncoded, { returnAs: "uint8array" }), options);
}

/** Encode a payload to bytes; a non-serializable one throws `ERR_INVALID_OPTION`. */
export function getPlaintextBytes(payload: JOSEPayload): Uint8Array<ArrayBuffer> {
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
export type ComputeJwtTimeClaimsOptions = JWTTimeClaimOptions;

/**
 * Return a copy of an object payload with `iat` and the requested `exp` / `nbf`, or `undefined` when none applies.
 * `currentDate` is the clock: `iat` when written, and the base of `expiresIn` / `notBeforeIn`;
 * `issuedAt` writes `iat` alone, a `Date` as that instant. Both members of `expiresIn`/`expiresAt` or `notBeforeIn`/`notBeforeAt` throw `ERR_JWT_CLAIM_INVALID`;
 * any of them with a string or bytes payload is `ERR_INVALID_OPTION`.
 */
export function computeJwtTimeClaims(
  payload: unknown,
  options?: ComputeJwtTimeClaimsOptions,
): JWTClaims | undefined {
  const { currentDate, issuedAt, expiresIn, expiresAt, notBeforeIn, notBeforeAt } = options ?? {};

  if (issuedAt !== undefined && typeof issuedAt !== "boolean" && !(issuedAt instanceof Date)) {
    throw new JWTError('"issuedAt" must be a boolean or a Date.', "ERR_INVALID_OPTION");
  }

  if (expiresIn !== undefined && expiresAt !== undefined) {
    throw new JWTError(
      '"expiresIn" and "expiresAt" are mutually exclusive.',
      "ERR_JWT_CLAIM_INVALID",
    );
  }
  if (notBeforeIn !== undefined && notBeforeAt !== undefined) {
    throw new JWTError(
      '"notBeforeIn" and "notBeforeAt" are mutually exclusive.',
      "ERR_JWT_CLAIM_INVALID",
    );
  }

  const hasExpHint = expiresIn !== undefined || expiresAt !== undefined;
  const hasNbfHint = notBeforeIn !== undefined || notBeforeAt !== undefined;
  const hasIatHint = issuedAt === true || issuedAt instanceof Date;
  if (!hasExpHint && !hasNbfHint && !hasIatHint) return undefined;
  if (!payload || typeof payload !== "object" || payload instanceof Uint8Array) {
    const option =
      Object.entries({ expiresIn, expiresAt, notBeforeIn, notBeforeAt }).find(
        ([, value]) => value !== undefined,
      )?.[0] ?? "issuedAt";
    throw new JWTError(
      `"${option}" needs a JSON payload: pass an object payload or drop the option.`,
      "ERR_INVALID_OPTION",
    );
  }

  const wantsExp = hasExpHint && (!("exp" in payload) || payload.exp === undefined);
  const wantsNbf = hasNbfHint && (!("nbf" in payload) || payload.nbf === undefined);
  const wantsIat = hasIatHint && (!("iat" in payload) || payload.iat === undefined);
  if (!wantsExp && !wantsNbf && !wantsIat) return undefined;

  const now = Math.floor((currentDate ?? new Date()).getTime() / 1000);
  const claims: JWTClaims = { ...payload };
  claims.iat ??=
    issuedAt instanceof Date ? Math.floor(_instantOf(issuedAt, "issuedAt") / 1000) : now;

  if (wantsExp) {
    if (expiresAt !== undefined) {
      claims.exp = Math.floor(_instantOf(expiresAt, "expiresAt") / 1000);
    } else if (expiresIn !== undefined) {
      claims.exp = now + computeDurationInSeconds(expiresIn);
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
      claims.nbf = now + offset;
    }
  }

  return claims;
}

// RFC 7515 §4.1.11 / RFC 7516 §4.1.13 — extensions understood without opt-in.
const BASE_PROCESSED: Readonly<Record<"JWS" | "JWE", readonly string[]>> =
  /* @__PURE__ */ Object.freeze({
    JWS: ["b64"],
    JWE: [],
  });

/** Validate critical headers in JWS semantics. */
export function validateCriticalHeadersJWS(
  protectedHeader: { crit?: string[] } & Record<string, unknown>,
  recognizedHeaders?: string[],
): void {
  validateCriticalHeaders(protectedHeader, { family: "JWS", recognizedHeaders });
}

/** Validate critical headers in JWE semantics. */
export function validateCriticalHeadersJWE(
  protectedHeader: { crit?: string[] } & Record<string, unknown>,
  recognizedHeaders?: string[],
): void {
  validateCriticalHeaders(protectedHeader, { family: "JWE", recognizedHeaders });
}

// RFC 7515 §4.1.11 — registered header names, forbidden in `crit`.
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

/** Assert `crit` is a non-empty string array with no registered header name (RFC 7515 §4.1.11 / RFC 7516 §4.1.13). */
export function assertCritShape(
  crit: unknown,
  options: { family: "JWS" | "JWE"; code?: JWTErrorCode },
): asserts crit is string[] {
  const { family } = options;
  const code = options.code ?? `ERR_${family}_INVALID`;
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

function _instantOf(value: Date, name: "issuedAt" | "expiresAt" | "notBeforeAt"): number {
  const ms = value instanceof Date ? value.getTime() : Number.NaN;
  if (!Number.isFinite(ms)) {
    throw new JWTError(`"${name}" must be a valid Date.`, "ERR_INVALID_OPTION");
  }
  return ms;
}

// RFC 7515 §2 / RFC 7516 §2 — payload text is strict UTF-8.
const _utf8Decoder = /* @__PURE__ */ new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** RFC 7519 §3 — a JWT payload is a JSON object. */
function _parsePayloadObject(text: string, family: "JWS" | "JWE"): JWTClaims {
  const code = `ERR_${family}_INVALID` as JWTErrorCode;
  const message = `Invalid ${family}: Payload is not a JSON object.`;
  let parsed: unknown;
  try {
    parsed = safeJsonParse(text);
  } catch (error) {
    throw new JWTError(message, code, error);
  }
  if (!isPlainObject(parsed)) {
    throw new JWTError(message, code);
  }
  return parsed;
}

/** RFC 7515 §4.1.11 / RFC 7516 §4.1.13 — each `crit` entry is present and understood. */
function validateCriticalHeaders(
  protectedHeader: { crit?: string[] } & Record<string, unknown>,
  options: { family: "JWS" | "JWE"; recognizedHeaders: string[] | undefined },
): void {
  const { crit } = protectedHeader;
  if (crit === undefined) return;
  const { family, recognizedHeaders = [] } = options;
  assertCritShape(crit, { family });
  for (const param of crit) {
    if (!Object.hasOwn(protectedHeader, param)) {
      throw new JWTError(
        `Critical header parameter ${quoteTokenValue(param)} is missing from the protected header.`,
        `ERR_${family}_INVALID`,
      );
    }
    if (!recognizedHeaders.includes(param) && !BASE_PROCESSED[family].includes(param)) {
      throw new JWTError(
        `Unprocessed critical header parameters: ${quoteTokenValue(param)}`,
        `ERR_${family}_INVALID`,
      );
    }
  }
}
