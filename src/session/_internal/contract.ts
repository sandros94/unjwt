import { JWTError, isJWTError } from "../../error.ts";
import { importKey } from "../../core/_internal/import-key.ts";
import { computeDurationInSeconds, expiredClaimMessage } from "../../utils/jwt.ts";
import { isJWK, isPlainObject } from "../../utils/guards.ts";
import { quoteTokenValue } from "../../utils/_internal/text.ts";
import type { ExpiresIn, JWKAlgorithm } from "../../core/types/index.ts";

/** Claims the session sets on every issue, stripped from `update()` data and from `session.data`. */
export const RESERVED_CLAIMS: readonly string[] = ["jti", "iat", "exp", "nbf"];

const SESSION_TYP = "session+jwt";

const FORBIDDEN_KEYS: readonly string[] = ["__proto__", "constructor", "prototype"];

const importedKeys = /* @__PURE__ */ new WeakMap<object, Map<string, Promise<void>>>();

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

/** The `ERR_JWT_EXPIRED` the core claim check throws, with `{ jti, iat, exp }` as `cause`, for both expiry checks. */
export function expiredSessionError(options: {
  id: string | undefined;
  createdAt?: number;
  expiresAt: number;
}): JWTError<"ERR_JWT_EXPIRED"> {
  const { id, createdAt, expiresAt } = options;
  const exp = Math.floor(expiresAt / 1000);
  const iat = createdAt === undefined ? undefined : Math.floor(createdAt / 1000);
  return new JWTError(expiredClaimMessage(exp), "ERR_JWT_EXPIRED", { jti: id, iat, exp });
}

/** Whether a read failure is the token's own. A key lookup that threw says nothing about the token. */
export function isTokenFailure(error: JWTError<"ERR_SESSION_TOKEN_INVALID">): boolean {
  return !(isJWTError(error.cause, "ERR_JWK_KEY_NOT_FOUND") && error.cause.cause !== undefined);
}

/** Passes `ERR_JWT_EXPIRED` through. Any other error becomes `ERR_SESSION_TOKEN_INVALID`. */
export function rethrowAsInvalidToken(error: unknown, options: { prefix: string }): never {
  if (isJWTError(error, "ERR_JWT_EXPIRED")) throw error;
  throw invalidTokenError(`${options.prefix} Invalid session token: ${messageOf(error)}`, error);
}

/** RFC 7230 token: required of a cookie name (RFC 6265 §4.1.1) and of a header name. */
const TOKEN = /^[!#$%&'*+\-.^_`|~\w]+$/;

/** `<name>.<n>` is the cookie holding chunk `n` of the session called `<name>`. */
const CHUNK_SUFFIX = /\.\d+$/;

/** A session name is an RFC 6265 §4.1.1 cookie name that does not end like a chunk cookie. */
export function assertSessionName(name: string, options: { prefix: string }): void {
  if (!isToken(name)) {
    throw invalidConfigError(
      `${options.prefix} Session "name" must be a valid cookie name (got ${quoteTokenValue(name)}).`,
    );
  }
  if (CHUNK_SUFFIX.test(name)) {
    throw invalidConfigError(
      `${options.prefix} Session "name" ${quoteTokenValue(name)} cannot end in a dot and digits.`,
    );
  }
}

export function isToken(value: unknown): value is string {
  return typeof value === "string" && TOKEN.test(value);
}

/** A `__Host-` cookie must be Secure, with `Path=/` and no `Domain`. A `__Secure-` cookie must be Secure (RFC 6265bis §4.1.3). */
export function assertCookiePrefix(
  name: string,
  attrs: { secure?: unknown; domain?: unknown; path?: unknown },
  options: { prefix: string },
): void {
  const lower = name.toLowerCase();
  const host = lower.startsWith("__host-");
  if (!host && !lower.startsWith("__secure-")) return;
  const rule = host
    ? '"__Host-" cookie must be Secure, with Path=/ and no Domain'
    : '"__Secure-" cookie must be Secure';
  const broken =
    attrs.secure === false ||
    (host && (attrs.domain !== undefined || (attrs.path !== undefined && attrs.path !== "/")));
  if (broken) {
    throw invalidConfigError(`${options.prefix} Session ${quoteTokenValue(name)}: a ${rule}.`);
  }
}

/** `rolling` requires a `maxAge`, and is `true` or a duration shorter than `maxAge`. */
export function assertRolling(
  config: { rolling?: unknown; maxAge?: ExpiresIn },
  options: { prefix: string },
): void {
  const { rolling } = config;
  if (rolling === undefined) return;
  if (config.maxAge === undefined) {
    throw invalidConfigError(`${options.prefix} "rolling" needs a "maxAge" to extend.`);
  }
  if (rolling === true) return;
  if (!isExpiresIn(rolling)) {
    throw new JWTError(
      `${options.prefix} "rolling" must be true or a duration.`,
      "ERR_INVALID_OPTION",
    );
  }
  if (computeDurationInSeconds(rolling) >= computeDurationInSeconds(config.maxAge)) {
    throw invalidConfigError(`${options.prefix} "rolling" must be shorter than "maxAge".`);
  }
}

export function assertKeyMaterial(key: unknown, options: { prefix: string }): void {
  if (typeof key === "string") {
    throw invalidKeyError(
      `${options.prefix} Session "key" cannot be a string, use deriveJWKFromPassword().`,
    );
  }
  if (!key) {
    throw invalidKeyError(`${options.prefix} Session "key" is required.`);
  }
}

/**
 * Imports a configured JWK before first use, so unusable key material throws `ERR_SESSION_KEY_INVALID`.
 * A successful import is remembered per JWK object and `alg`. A failed one is retried.
 */
export async function assertImportableKey(
  key: unknown,
  options: { alg: JWKAlgorithm | undefined; prefix: string },
): Promise<void> {
  if (!isJWK(key)) return;
  const alg = key.alg ?? options.alg;
  if (key.kty !== "oct" && !alg) return;
  let imports = importedKeys.get(key);
  if (!imports) {
    imports = new Map();
    importedKeys.set(key, imports);
  }
  const slot = alg ?? "";
  let pending = imports.get(slot);
  if (!pending) {
    pending = importKey(key, { alg }).then(() => undefined);
    imports.set(slot, pending);
  }
  try {
    await pending;
  } catch (error) {
    if (imports.get(slot) === pending) imports.delete(slot);
    throw invalidKeyError(`${options.prefix} Invalid session key: ${messageOf(error)}`, error);
  }
}

/** The configured `typ`, else `"session+jwt"` (RFC 8725 §3.11 explicit typing). */
export function sessionTyp(configured: unknown): string {
  return typeof configured === "string" && configured ? configured : SESSION_TYP;
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

/** Always `jti` and `iat`, plus `exp` when the session has a `maxAge`. */
export function sessionRequiredClaims(
  configured: string[] | undefined,
  options: { maxAge: ExpiresIn | undefined },
): string[] {
  const required = new Set([...(configured || []), "jti", "iat"]);
  if (options.maxAge !== undefined) required.add("exp");
  return [...required];
}

/** Strips the claims the session sets, and refuses a `__proto__`, `constructor` or `prototype` key with `ERR_INVALID_OPTION`. */
export function sanitizeSessionUpdate(
  update: object,
  options: { prefix: string },
): Record<string, unknown> {
  if (!isPlainObject(update)) {
    throw new JWTError(
      `${options.prefix} Session data must be a plain object.`,
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
  return sanitized;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isExpiresIn(value: unknown): value is ExpiresIn {
  return typeof value === "number" || typeof value === "string";
}
