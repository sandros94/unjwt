import type { JWTClaims, JWTClaimValidationOptions, ExpiresIn } from "../types";
import { base64UrlDecode, textDecoder, textEncoder, maybeArray, safeJsonParse } from "./index";
import { JWTError } from "../error";

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

/** Parse a decoded string as JSON when it looks like a JSON object or array, otherwise return the string verbatim. */
export function decodeMaybeJWTString<T = unknown>(decodedString: string): T | string {
  const looksLikeJson =
    (decodedString.startsWith("{") && decodedString.endsWith("}")) ||
    (decodedString.startsWith("[") && decodedString.endsWith("]"));
  if (looksLikeJson) {
    try {
      return safeJsonParse<T>(decodedString);
    } catch {
      // fallthrough to return string if malformed
    }
  }
  return decodedString;
}

/** Decode raw payload bytes honoring `forceUint8Array`. */
export function decodePayloadFromBytes<T = unknown>(
  bytes: Uint8Array<ArrayBuffer>,
  forceUint8Array?: boolean,
): T | Uint8Array<ArrayBuffer> | string {
  if (forceUint8Array) return bytes;
  return decodeMaybeJWTString<T>(textDecoder.decode(bytes));
}

/** Decode a Base64URL-encoded payload segment honoring `forceUint8Array`. */
export function decodePayloadFromB64UrlSegment<T = unknown>(
  payloadEncoded: string,
  forceUint8Array?: boolean,
): T | Uint8Array<ArrayBuffer> | string {
  if (forceUint8Array) return base64UrlDecode(payloadEncoded, false);
  return decodeMaybeJWTString<T>(base64UrlDecode(payloadEncoded));
}

/** Convert plaintext input to bytes, shared by JWS & JWE when preparing payload. */
export function getPlaintextBytes(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, unknown>,
): Uint8Array<ArrayBuffer> {
  if (payload instanceof Uint8Array) return payload;
  if (typeof payload === "string") return textEncoder.encode(payload);
  if (typeof payload === "object" && payload !== null)
    return textEncoder.encode(JSON.stringify(payload));
  throw new TypeError("Plaintext must be a string, Uint8Array, or a JSON-serializable object.");
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
const EXPIRES_IN_REGEX =
  /^(\d+)(s|second|seconds|m|minute|minutes|h|hour|hours|D|day|days|W|week|weeks|M|month|months|Y|year|years)?$/;

export function computeExpiresInSeconds(expiresIn: ExpiresIn): number {
  if (typeof expiresIn === "number") {
    if (!Number.isInteger(expiresIn) || expiresIn <= 0) {
      throw new TypeError(
        "If 'expiresIn' is a number, it must be a positive integer representing seconds.",
      );
    }
    return expiresIn;
  }

  if (typeof expiresIn === "string") {
    const match = expiresIn.match(EXPIRES_IN_REGEX);
    if (!match || !match[1]) {
      throw new TypeError(
        "Invalid 'expiresIn' format. Must be a positive integer or a string like '10m', '2h', '7D', etc.",
      );
    }

    const value = Number.parseInt(match[1], 10);
    const unit = (match[2] || "s") as keyof typeof TIME_CONSTANTS;

    return value * TIME_CONSTANTS[unit];
  }

  throw new TypeError("'expiresIn' must be a number or a string representing time duration.");
}
export const computeMaxTokenAgeSeconds: (expiresIn: ExpiresIn) => number = computeExpiresInSeconds;

/** Compute iat/exp for any JSON-object payload when `expiresIn` is set and `exp` is not already present. */
export function computeJwtTimeClaims(
  payload: unknown,
  expiresIn?: ExpiresIn,
  currentDate?: Date,
): JWTClaims | undefined {
  if (
    expiresIn === undefined ||
    !(payload && typeof payload === "object") ||
    payload instanceof Uint8Array ||
    (payload as any).exp
  ) {
    return undefined;
  }

  const now = Math.round((currentDate ?? new Date()).getTime() / 1000);
  const claims: JWTClaims = { ...(payload as JWTClaims) };
  claims.iat ||= now;
  claims.exp = claims.iat + computeExpiresInSeconds(expiresIn);
  return claims;
}

/** Validate JWT claims under JWS verification rules (or custom JWE implementations). */
export function validateJwtClaims(
  jwtClaims: JWTClaims,
  options: JWTClaimValidationOptions = {},
): void {
  const clockTolerance = options.clockTolerance ?? 0;
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
      if (!(claimName in jwtClaims)) missingClaims.push(claimName);
    }
    if (missingClaims.length > 0) {
      throw new JWTError(
        `Missing required JWT Claims: ${missingClaims.join(", ")}`,
        "ERR_JWT_CLAIM_MISSING",
      );
    }
  }

  // RFC 7519 §4.1 — `exp`, `nbf`, `iat` are NumericDate and must be finite numbers if present.
  if (jwtClaims.exp !== undefined && !Number.isFinite(jwtClaims.exp)) {
    throw new JWTError(
      'JWT "exp" (Expiration Time) Claim must be a number.',
      "ERR_JWT_CLAIM_INVALID",
    );
  }
  if (jwtClaims.nbf !== undefined && !Number.isFinite(jwtClaims.nbf)) {
    throw new JWTError('JWT "nbf" (Not Before) Claim must be a number.', "ERR_JWT_CLAIM_INVALID");
  }
  if (jwtClaims.iat !== undefined && !Number.isFinite(jwtClaims.iat)) {
    throw new JWTError('JWT "iat" (Issued At) Claim must be a number.', "ERR_JWT_CLAIM_INVALID");
  }

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
      currentTime - computeMaxTokenAgeSeconds(options.maxTokenAge) - clockTolerance
    ) {
      throw new JWTError(
        `JWT "iat" (Issued At) Claim validation failed: Token is too old (maxTokenAge: ${options.maxTokenAge}s, iat: ${new Date(jwtClaims.iat * 1000).toISOString()})`,
        "ERR_JWT_EXPIRED",
        { jti: jwtClaims.jti, iat: jwtClaims.iat, exp: jwtClaims.exp },
      );
    }
  }
}

// RFC 7515 §4.1.11 / RFC 7516 §4.1.13 — `crit` entries must be parameters the recipient actively
// processes. Registered-but-unprocessed params (`jwk`, `jku`, `x5c`, `x5t`, `x5u`) are excluded.
const BASE_PROCESSED_JWS = ["alg", "typ", "cty", "kid", "b64"];
const BASE_PROCESSED_JWE = [
  "alg",
  "enc",
  "typ",
  "cty",
  "kid",
  "iv",
  "tag",
  "p2s",
  "p2c",
  "epk",
  "apu",
  "apv",
];

/** Validate critical headers in JWS semantics. */
export function validateCriticalHeadersJWS(
  protectedHeader: { crit?: string[] } & Record<string, any>,
  recognizedHeaders: string[] = [],
): void {
  if (!protectedHeader.crit) return;
  const missingHeaderParams = new Set<string>();
  const recognizedParams = new Set<string>([...recognizedHeaders, ...BASE_PROCESSED_JWS]);

  for (const param of protectedHeader.crit) {
    // `b64` (RFC 7797) is special: its absence defaults to `true` and is still valid.
    if (recognizedParams.has(param) && (param in protectedHeader || param === "b64")) {
      continue;
    }
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
  if (!protectedHeader.crit) return;
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
