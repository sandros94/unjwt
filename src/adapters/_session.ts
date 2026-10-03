import { JWTError, isJWTError } from "../core/error";
import { decodeProtectedHeader } from "../core/_internal";
import { importKey } from "../core/jwk";
import { computeDurationInSeconds, isJWK } from "../core/utils";
import type { ExpiresIn } from "../core/types";

/**
 * Claims the adapters own. They are minted fresh on every issue, stripped from
 * every `update()` payload, and dropped from a decoded token before it becomes
 * `session.data`.
 */
export const RESERVED_CLAIMS: readonly string[] = ["jti", "iat", "exp", "nbf"];

/** `cty` every adapter writes, and requires on every token it accepts. */
export const SESSION_CONTENT_TYPE = "application/json";

const FORBIDDEN_KEYS: readonly string[] = ["__proto__", "constructor", "prototype"];

/** Per-issue overrides for a single `update()` call. */
export interface SessionIssueOptions {
  /** Lifetime for this issue only, overriding the config's `maxAge`. */
  maxAge?: ExpiresIn;
}

/** The parts of a session config that decide where the token is read from. */
export interface SessionTokenSource {
  /** Request header to read the token from, or `false` for cookies only. */
  sessionHeader?: false | string;
  /** Cookie options, or `false` for header only. */
  cookie?: false | object;
}

export function invalidKeyError(
  message: string,
  cause?: unknown,
): JWTError<"ERR_SESSION_KEY_INVALID"> {
  return new JWTError(message, "ERR_SESSION_KEY_INVALID", cause);
}

export function invalidConfigError(
  message: string,
  cause?: unknown,
): JWTError<"ERR_SESSION_CONFIG_INVALID"> {
  return new JWTError(message, "ERR_SESSION_CONFIG_INVALID", cause);
}

export function invalidTokenError(
  message: string,
  cause?: unknown,
): JWTError<"ERR_SESSION_TOKEN_INVALID"> {
  return new JWTError(message, "ERR_SESSION_TOKEN_INVALID", cause);
}

export function readOnlyEventError(message: string): JWTError<"ERR_SESSION_READONLY_EVENT"> {
  return new JWTError(message, "ERR_SESSION_READONLY_EVENT");
}

/**
 * The error an in-memory session raises once its `expiresAt` instant has
 * passed, shaped like the core claim-validation failure so `onExpire` receives
 * the same class, code and `cause` on both the verify and the in-memory path.
 */
export function expiredSessionError(options: {
  id: string | undefined;
  expiresAt: number;
}): JWTError<"ERR_JWT_EXPIRED"> {
  const { id, expiresAt } = options;
  return new JWTError(
    `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(expiresAt).toISOString()})`,
    "ERR_JWT_EXPIRED",
    { jti: id, exp: Math.floor(expiresAt / 1000) },
  );
}

/**
 * Turn a read-path failure into the session-adapter contract: the expiry of a
 * session token passes through untouched, everything else — including the
 * expiry of a token that is not a session — becomes `ERR_SESSION_TOKEN_INVALID`
 * with the original error as its `cause`.
 */
export function rethrowAsInvalidToken(
  error: unknown,
  options: { prefix: string; token: string; family: "JWS" | "JWE" },
): never {
  if (isJWTError(error, "ERR_JWT_EXPIRED")) {
    // Expiry is only raised once the token was verified, so its protected
    // header is authentic and decides whether this was a session at all.
    const [encoded] = options.token.split(".", 1);
    const header = decodeProtectedHeader<{ cty?: unknown }>(encoded, options.family);
    assertSessionContentType(header.cty, { prefix: options.prefix, cause: error });
    throw error;
  }
  const message = error instanceof Error ? error.message : String(error);
  throw invalidTokenError(`${options.prefix} Invalid session token: ${message}`, error);
}

/**
 * RFC 6265 §4.1.1 — a cookie name is an RFC 7230 token, and so is the header
 * name a session's `name` also spells. A name outside those characters cannot
 * be written: some frameworks refuse it outright, others emit a header no
 * client will parse back, so it is refused where it is configured.
 */
const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~\w]+$/;

export function assertSessionName(name: string, options: { prefix: string }): void {
  if (typeof name === "string" && COOKIE_NAME.test(name)) return;
  throw invalidConfigError(
    `${options.prefix} Session "name" must be a cookie name (RFC 6265 §4.1.1): letters, digits and !#$%&'*+-.^_\`|~ only. Got ${JSON.stringify(name)}.`,
  );
}

/** Whether a config leaves the adapter somewhere to read the token from. */
export function hasTokenSource(source: SessionTokenSource): boolean {
  return source.cookie !== false || source.sessionHeader !== false;
}

/** Reject a config that leaves the adapter with nowhere to read the token from. */
export function assertTokenSource(source: SessionTokenSource, options: { prefix: string }): void {
  if (!hasTokenSource(source)) {
    throw invalidConfigError(
      `${options.prefix} Session has no token source: "cookie" and "sessionHeader" are both disabled.`,
    );
  }
}

/**
 * Reject a token whose content type is not the one the adapters write. Media
 * type names compare case-insensitively and parameters are not part of the
 * type (RFC 2045 §5.1, RFC 7515 §4.1.10).
 */
export function assertSessionContentType(
  cty: unknown,
  options: { prefix: string; cause?: unknown },
): void {
  const type = typeof cty === "string" ? cty.split(";", 1)[0]!.trim().toLowerCase() : undefined;
  if (type !== SESSION_CONTENT_TYPE) {
    throw invalidTokenError(
      `${options.prefix} Session token is not a session: "cty" must be "${SESSION_CONTENT_TYPE}", got ${cty === undefined ? "none" : JSON.stringify(cty)}.`,
      options.cause,
    );
  }
}

/** Reject a password string where key material is required. */
export function assertKeyMaterial(key: unknown, options: { prefix: string }): void {
  if (typeof key === "string") {
    throw invalidKeyError(
      `${options.prefix} Session "key" must be a JWK or a CryptoKey, not a password string. Derive one once with deriveJWKFromPassword() and pass the result.`,
    );
  }
  if (!key) {
    throw invalidKeyError(`${options.prefix} Session "key" is required.`);
  }
}

/**
 * Import a configured JWK once, so key material the session cannot use is a
 * key failure raised where the session is opened rather than an unreadable
 * token. An asymmetric JWK whose algorithm neither it nor the config names is
 * left to the token it opens.
 */
export async function assertImportableKey(
  key: unknown,
  options: { alg: string | undefined; prefix: string },
): Promise<void> {
  if (!isJWK(key)) return;
  const alg = key.alg ?? options.alg;
  if (key.kty !== "oct" && !alg) return;
  try {
    await importKey(key, { alg });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw invalidKeyError(`${options.prefix} Invalid session key: ${message}`, error);
  }
}

/** The `typ` a session writes and requires: the configured one, else `"JWT"`. */
export function sessionTyp(configured: unknown): string {
  return typeof configured === "string" && configured ? configured : "JWT";
}

/** The header name a session reads its token from. */
export function sessionHeaderName(
  sessionName: string,
  configured: false | string | undefined,
): string {
  return typeof configured === "string"
    ? configured.toLowerCase()
    : `x-${sessionName.toLowerCase()}-session`;
}

/**
 * The token carried by a session header value, with an optional `Bearer`
 * prefix removed (case-insensitive, RFC 7235 §2.1). An absent, empty or
 * whitespace-only value yields `undefined` so it never hides the cookie.
 */
export function headerToken(value: string | null | undefined): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  const token = /^bearer\s+/i.test(trimmed) ? trimmed.replace(/^bearer\s+/i, "") : trimmed;
  return token || undefined;
}

/** The first candidate that actually carries a token. */
export function pickToken(...candidates: (string | undefined)[]): string | undefined {
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.length > 0) return candidate;
  }
  return undefined;
}

/** `exp` in ms for a session issued at `createdAt`, or `undefined` for no expiry. */
export function resolveExpiresAt(
  createdAt: number,
  options: { maxAge: ExpiresIn | undefined },
): number | undefined {
  return options.maxAge === undefined
    ? undefined
    : createdAt + computeDurationInSeconds(options.maxAge) * 1000;
}

/**
 * Claims an incoming token must carry: always `jti` and `iat`, plus `exp` when
 * the session has a `maxAge`. A token's `exp` is what bounds its life, so a
 * session with a lifetime refuses a token that carries none.
 */
export function sessionRequiredClaims(
  configured: string[] | undefined,
  options: { maxAge: ExpiresIn | undefined },
): string[] {
  const required = new Set([...(configured || []), "jti", "iat"]);
  if (options.maxAge !== undefined) required.add("exp");
  return [...required];
}

/**
 * An `update()` payload with the adapter-owned claims removed, rejecting keys
 * that would poison the prototype of the session data.
 */
export function sanitizeSessionUpdate<T extends Record<string, any>>(
  update: T,
  options: { prefix: string },
): Partial<T> {
  if (!isPlainObject(update)) {
    throw new JWTError(
      `${options.prefix} Session data must be a plain object, got ${Array.isArray(update) ? "an array" : typeof update}.`,
      "ERR_INVALID_OPTION",
    );
  }
  const sanitized: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(update)) {
    if (FORBIDDEN_KEYS.includes(key)) {
      throw new JWTError(
        `${options.prefix} Session data cannot carry the key "${key}".`,
        "ERR_INVALID_OPTION",
      );
    }
    if (RESERVED_CLAIMS.includes(key)) continue;
    sanitized[key] = update[key];
  }
  return sanitized as Partial<T>;
}

/** A decoded token payload with the adapter-owned claims split off. */
export function splitSessionClaims<T extends Record<string, any>>(
  payload: T,
): { jti: string; iat: number; exp: number | undefined; data: Record<string, any> } {
  const data: Record<string, any> = Object.create(null);
  for (const key of Object.keys(payload)) {
    if (RESERVED_CLAIMS.includes(key)) continue;
    data[key] = payload[key];
  }
  return { jti: payload.jti, iat: payload.iat, exp: payload.exp, data };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
