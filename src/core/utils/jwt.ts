import type { JWTClaims, JWTClaimValidationOptions, ExpiresIn } from "../types";
import { base64UrlDecode, textDecoder, textEncoder, maybeArray } from "./index";
import { sanitizeObject } from "./index";

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
    typeof payload === "object" &&
    payload !== null &&
    !(payload instanceof Uint8Array);
  if (header.typ === undefined && isObjectPayload) {
    header.typ = "JWT";
  }
  if (header.typ?.toLowerCase().includes("jwt") && isObjectPayload) {
    header.cty ||= "application/json";
  }
  return header;
}

/** Returns true when headers indicate JSON content. */
export function isJWTContent(
  header: { typ?: string; cty?: string } | undefined,
): boolean {
  if (!header) return false;
  if (header.typ?.toLowerCase().includes("jwt")) return true;
  const cty = header.cty?.toLowerCase();
  return (
    cty === "json" ||
    cty === "application/json" ||
    (!!cty && cty.endsWith("+json"))
  );
}

/**
 * Given a decoded string and JOSE headers, return an object if JSON, otherwise the string.
 */
export function decodeMaybeJWTString<T = unknown>(
  decodedString: string,
  header: { typ?: string; cty?: string } | undefined,
): T | string {
  if (isJWTContent(header)) {
    const looksLikeJson =
      (decodedString.startsWith("{") && decodedString.endsWith("}")) ||
      (decodedString.startsWith("[") && decodedString.endsWith("]"));
    if (looksLikeJson) {
      try {
        const obj = JSON.parse(decodedString);
        return sanitizeObject(obj as any) as unknown as T;
      } catch {
        // fallthrough to return string if malformed
      }
    }
  }
  return decodedString;
}

/**
 * Decode a payload that is represented as raw bytes into T | string, honoring forceUint8Array and headers.
 */
export function decodePayloadFromBytes<T = unknown>(
  bytes: Uint8Array<ArrayBuffer>,
  header: { typ?: string; cty?: string } | undefined,
  forceUint8Array?: boolean,
): T | Uint8Array<ArrayBuffer> | string {
  if (forceUint8Array) return bytes;
  const decodedString = textDecoder.decode(bytes);
  return decodeMaybeJWTString<T>(decodedString, header);
}

/**
 * Decode a payload that is a Base64URL segment into T | string | Uint8Array based on flags and headers.
 */
export function decodePayloadFromB64UrlSegment<T = unknown>(
  payloadEncoded: string,
  header: { typ?: string; cty?: string } | undefined,
  forceUint8Array?: boolean,
): T | Uint8Array<ArrayBuffer> | string {
  if (forceUint8Array) return base64UrlDecode(payloadEncoded, false);
  const decodedString = base64UrlDecode(payloadEncoded);
  return decodeMaybeJWTString<T>(decodedString, header);
}

/** Convert plaintext input to bytes, shared by JWS & JWE when preparing payload. */
export function getPlaintextBytes(
  payload: string | Uint8Array<ArrayBuffer> | Record<string, any>,
): Uint8Array<ArrayBuffer> {
  if (payload instanceof Uint8Array) return payload;
  if (typeof payload === "string") return textEncoder.encode(payload);
  if (typeof payload === "object" && payload !== null)
    return textEncoder.encode(JSON.stringify(payload));
  throw new TypeError(
    "Plaintext must be a string, Uint8Array, or a JSON-serializable object.",
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

  throw new TypeError(
    "'expiresIn' must be a number or a string representing time duration.",
  );
}
export const computeMaxTokenAgeSeconds = computeExpiresInSeconds;

/** Optionally compute iat/exp when signing JWTs. */
export function computeJwtTimeClaims(
  payload: unknown,
  headerTyp: string | undefined,
  expiresIn?: ExpiresIn,
  currentDate: Date = new Date(),
): JWTClaims | undefined {
  if (
    expiresIn === undefined ||
    !headerTyp?.toLowerCase().includes("jwt") ||
    !(payload && typeof payload === "object") ||
    payload instanceof Uint8Array ||
    (payload as any).exp
  ) {
    return undefined;
  }

  const now = Math.round(currentDate.getTime() / 1000);
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
  const clockTolerance = options.clockTolerance ?? 0; // seconds
  const currentTime = Math.round(
    (options.currentDate ?? new Date()).getTime() / 1000,
  );

  const allRequiredClaims = new Set<string>(options.requiredClaims || []);
  const missingClaims = new Set<string>();
  if (options.issuer) allRequiredClaims.add("iss");
  if (options.audience) allRequiredClaims.add("aud");
  if (options.subject) allRequiredClaims.add("sub");
  if (options.maxTokenAge) allRequiredClaims.add("iat");

  for (const claimName of allRequiredClaims) {
    if (!(claimName in jwtClaims)) missingClaims.add(claimName);
  }
  if (missingClaims.size > 0) {
    throw new Error(
      `Missing required JWT Claims: ${[...missingClaims].join(", ")}`,
    );
  }

  if (options.issuer) {
    const expectedIssuers = maybeArray(options.issuer);
    if (!jwtClaims.iss || !expectedIssuers.includes(jwtClaims.iss)) {
      throw new Error(
        `Invalid JWT "iss" (Issuer) Claim: Expected ${expectedIssuers.join(" or ")}, got ${jwtClaims.iss}`,
      );
    }
  }

  if (options.subject && jwtClaims.sub !== options.subject) {
    throw new Error(
      `Invalid JWT "sub" (Subject) Claim: Expected ${options.subject}, got ${jwtClaims.sub}`,
    );
  }

  if (options.audience) {
    const expectedAudiences = maybeArray(options.audience);
    const claimAudience = maybeArray(jwtClaims.aud || []);
    if (!claimAudience.some((aud) => expectedAudiences.includes(aud))) {
      throw new Error(
        `Invalid JWT "aud" (Audience) Claim: Expected ${expectedAudiences.join(" or ")}, got ${claimAudience.join(", ")}`,
      );
    }
  }

  if (
    typeof jwtClaims.nbf === "number" &&
    jwtClaims.nbf > currentTime + clockTolerance
  ) {
    throw new Error(
      `JWT "nbf" (Not Before) Claim validation failed: Token is not yet valid (nbf: ${new Date(jwtClaims.nbf * 1000).toISOString()})`,
    );
  }

  if (
    typeof jwtClaims.exp === "number" &&
    jwtClaims.exp <= currentTime - clockTolerance
  ) {
    throw new Error(
      `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(jwtClaims.exp * 1000).toISOString()})`,
    );
  }

  if (options.maxTokenAge) {
    if (typeof jwtClaims.iat !== "number") {
      throw new TypeError(
        'JWT "iat" (Issued At) Claim must be a number when maxTokenAge is set.',
      );
    }
    // iat must not be in the future (beyond clock tolerance)
    if (jwtClaims.iat > currentTime + clockTolerance) {
      throw new Error(
        `JWT "iat" (Issued At) Claim validation failed: Token was issued in the future (iat: ${new Date(jwtClaims.iat * 1000).toISOString()})`,
      );
    }
    if (
      jwtClaims.iat <
      currentTime -
        computeMaxTokenAgeSeconds(options.maxTokenAge) -
        clockTolerance
    ) {
      throw new Error(
        `JWT "iat" (Issued At) Claim validation failed: Token is too old (maxTokenAge: ${options.maxTokenAge}s, iat: ${new Date(jwtClaims.iat * 1000).toISOString()})`,
      );
    }
  }
}

/** Validate critical headers in JWS semantics. */
export function validateCriticalHeadersJWS(
  protectedHeader: { crit?: string[] } & Record<string, any>,
  requiredHeaders: string[] = [],
): void {
  if (!protectedHeader.crit) return;
  const missingHeaderParams = new Set<string>();
  const recognizedParams = new Set<string>([
    ...requiredHeaders,
    "alg",
    "typ",
    "cty",
    "kid",
    "jwk",
    "jku",
    "x5c",
    "x5t",
    "x5u",
    "b64",
  ]);

  for (const param of protectedHeader.crit) {
    // `b64` is special: its absence should still be considered valid
    if (
      recognizedParams.has(param) &&
      (param in protectedHeader || param === "b64")
    ) {
      continue;
    }
    missingHeaderParams.add(param);
  }

  if (missingHeaderParams.size > 0) {
    throw new Error(
      `Missing critical header parameters: ${[...missingHeaderParams].join(", ")}`,
    );
  }
}

/** Validate critical headers in JWE semantics. */
export function validateCriticalHeadersJWE(
  protectedHeader: { crit?: string[] } & Record<string, any>,
  understoodFromOptions?: string[],
): void {
  if (protectedHeader.crit && !understoodFromOptions) {
    throw new Error(
      `Unprocessed critical header parameters: ${protectedHeader.crit.join(", ")}`,
    );
  }
  if (!protectedHeader.crit) return;

  const understoodParams = new Set<string>([
    ...(understoodFromOptions || []),
    // JWE specific standard headers:
    "alg",
    "enc",
    "typ",
    "cty",
    "kid",
    "jwk",
    "jku",
    "x5c",
    "x5t",
    "x5u",
    "iv",
    "tag",
    "p2s",
    "p2c",
    "epk",
    "apu",
    "apv",
  ]);

  for (const critParam of protectedHeader.crit) {
    // Parameter must also be present in the protected header
    if (!Object.prototype.hasOwnProperty.call(protectedHeader, critParam)) {
      throw new Error(
        `Critical header parameter "${critParam}" listed in "crit" but not present in the protected header.`,
      );
    }
    if (!understoodParams.has(critParam)) {
      throw new Error(`Unprocessed critical header parameters: ${critParam}`);
    }
  }
}
