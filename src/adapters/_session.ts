import { JWTError, isJWTError } from "../core/error";
import { importKey } from "../core/jwk";
import { computeDurationInSeconds, expiredClaimMessage } from "../core/utils/jwt";
import { isJWK, isPlainObject } from "../core/utils/guards";
import { quoteTokenValue } from "../core/utils/_text";
import type { ExpiresIn, JWKAlgorithm } from "../core/types";

/** Adapter-owned claims: minted on every issue, stripped from `update()` payloads and `session.data`. */
export const RESERVED_CLAIMS: readonly string[] = ["jti", "iat", "exp", "nbf"];

const SESSION_TYP = "session+jwt";

const FORBIDDEN_KEYS: readonly string[] = ["__proto__", "constructor", "prototype"];

const importedKeys = /* @__PURE__ */ new WeakMap<object, Map<string, Promise<void>>>();

/** Per-issue overrides for a single `update()` call. */
export interface SessionIssueOptions {
  /** Lifetime for this issue only, overriding the config's `maxAge`. */
  maxAge?: ExpiresIn;
}

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

/** Shaped like the core claim failure so `onExpire` gets the same error on both expiry paths. */
export function expiredSessionError(options: {
  id: string | undefined;
  expiresAt: number;
}): JWTError<"ERR_JWT_EXPIRED"> {
  const { id, expiresAt } = options;
  const exp = Math.floor(expiresAt / 1000);
  return new JWTError(expiredClaimMessage(exp), "ERR_JWT_EXPIRED", { jti: id, exp });
}

/** Passes `ERR_JWT_EXPIRED` through; anything else becomes `ERR_SESSION_TOKEN_INVALID`. */
export function rethrowAsInvalidToken(error: unknown, options: { prefix: string }): never {
  if (isJWTError(error, "ERR_JWT_EXPIRED")) throw error;
  throw invalidTokenError(`${options.prefix} Invalid session token: ${messageOf(error)}`, error);
}

/** RFC 7230 token: required of a cookie name (RFC 6265 §4.1.1) and of a header name. */
const TOKEN = /^[!#$%&'*+\-.^_`|~\w]+$/;

/** `<name>.<n>` is the cookie holding chunk `n` of the session called `<name>`. */
const CHUNK_SUFFIX = /\.\d+$/;

export function assertSessionName(name: string, options: { prefix: string }): void {
  if (typeof name !== "string" || !TOKEN.test(name)) {
    throw invalidConfigError(
      `${options.prefix} Session "name" must be a cookie name (RFC 6265 §4.1.1): letters, digits and !#$%&'*+-.^_\`|~ only. Got ${quoteTokenValue(name)}.`,
    );
  }
  if (CHUNK_SUFFIX.test(name)) {
    throw invalidConfigError(
      `${options.prefix} Session "name" cannot end in a dot and digits: ${quoteTokenValue(name)} is the cookie holding a chunk of the session named ${quoteTokenValue(name.replace(CHUNK_SUFFIX, ""))}.`,
    );
  }
}

/** A `__Host-` cookie must be Secure, carry `Path=/` and no `Domain`; a `__Secure-` cookie must be Secure (RFC 6265bis §4.1.3). */
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
    throw invalidConfigError(
      `${options.prefix} Session ${quoteTokenValue(name)}: a ${rule} (RFC 6265bis §4.1.3).`,
    );
  }
}

/** Reject a `sessionHeader` that is not a header name (RFC 7230 §3.2). */
export function assertSessionHeader(header: unknown, options: { prefix: string }): void {
  if (header === undefined || header === false) return;
  if (typeof header === "string" && TOKEN.test(header)) return;
  throw invalidConfigError(
    `${options.prefix} Session "sessionHeader" must be false or a header name: letters, digits and !#$%&'*+-.^_\`|~ only. Got ${quoteTokenValue(header)}.`,
  );
}

/** `rolling` extends a session's `exp` on read, so it needs a `maxAge`: `true`, or the age a token must reach first, shorter than `maxAge`. */
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
    throw invalidConfigError(
      `${options.prefix} "rolling" must be shorter than "maxAge": the session would expire before it rolls.`,
    );
  }
}

export function hasTokenSource(source: SessionTokenSource): boolean {
  return source.cookie !== false || source.sessionHeader !== false;
}

export function assertTokenSource(source: SessionTokenSource, options: { prefix: string }): void {
  if (!hasTokenSource(source)) {
    throw invalidConfigError(
      `${options.prefix} Session has no token source: "cookie" and "sessionHeader" are both disabled.`,
    );
  }
}

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
 * Imports a configured JWK up front, so unusable key material throws `ERR_SESSION_KEY_INVALID`.
 * A successful import is remembered per JWK object and `alg`; a failed one is retried.
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

/** The configured header, else `x-<name>-session` without a `__Host-`/`__Secure-` prefix. */
export function sessionHeaderName(
  sessionName: string,
  configured: false | string | undefined,
): string {
  if (typeof configured === "string") return configured.toLowerCase();
  // RFC 6265bis §4.1.3 — cookie prefixes are matched case-insensitively.
  const bare = sessionName.replace(/^__(?:host|secure)-/i, "");
  return `x-${bare.toLowerCase()}-session`;
}

/** A bare token or `Bearer <token>` (RFC 7235 §2.1, case-insensitive); anything else is `undefined`. */
export function headerToken(value: string | null | undefined): string | undefined {
  if (typeof value !== "string") return undefined;
  const words = value.trim().split(/\s+/);
  const [first = "", second] = words;
  if (/^bearer$/i.test(first)) return words.length === 2 ? second : undefined;
  return words.length === 1 && first ? first : undefined;
}

/** Cookie first (this response's own write wins; a written deletion means no token), then the header. */
export function resolveSessionToken(
  source: SessionTokenSource,
  sessionName: string,
  read: {
    written?: (name: string) => string | undefined;
    cookie: (name: string) => string | undefined;
    header: (name: string) => string | null | undefined;
  },
): string | undefined {
  let cookieValue: string | undefined;
  if (source.cookie !== false) {
    const written = read.written?.(sessionName);
    if (written === "") return undefined;
    cookieValue = written ?? read.cookie(sessionName);
  }

  const headerValue =
    source.sessionHeader === false
      ? undefined
      : headerToken(read.header(sessionHeaderName(sessionName, source.sessionHeader)));

  return cookieValue || headerValue || undefined;
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

/** Strips adapter-owned claims and rejects prototype-polluting keys. */
export function sanitizeSessionUpdate(
  update: object,
  options: { prefix: string },
): Record<string, unknown> {
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
  return sanitized;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isExpiresIn(value: unknown): value is ExpiresIn {
  return typeof value === "number" || typeof value === "string";
}
