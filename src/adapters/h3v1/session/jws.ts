/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { CookieSerializeOptions } from "cookie-esv1";
import type { H3Event } from "h3v1";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import type {
  ExpiresIn,
  JWKSet,
  JWK_HMAC,
  JWK_oct,
  JWSSignJWK,
  JWSVerifyJWK,
  JWSAsymmetricPrivateJWK,
  JWSAsymmetricPublicJWK,
  JWSSignOptions,
  JWKLookupFunctionHeader,
  JWTClaimValidationOptions,
} from "../../../core/types";
import { sign, verify, isJWTError } from "../../../core/jws";
import { isCryptoKey, isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../../../core/utils";
import {
  type SessionIssueOptions,
  assertKeyMaterial,
  assertSessionContentType,
  expiredSessionError,
  invalidConfigError,
  invalidKeyError,
  readOnlyEventError,
  resolveExpiresAt,
  rethrowAsInvalidToken,
  sanitizeSessionUpdate,
  sessionRequiredClaims,
  sessionTyp,
  splitSessionClaims,
} from "../../_session";
import { setChunkedCookie, deleteChunkedCookie } from "../_cookie";
import type { SessionClaims, SessionData, SessionUpdate, SessionManager } from "./types";
import {
  type CompatEvent,
  PREFIX,
  getSessionsContext,
  hasWritableResponse,
  readSessionToken,
  sessionSlot,
} from "./_shared";

const kGetSessionPromise: unique symbol = Symbol("h3_jws_getSession");

/**
 * In-memory session state for the current request, mirroring the claims of
 * the underlying compact JWS token.
 */
export interface SessionJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  /** Session ID — mirrors the JWT `jti` claim. `undefined` until the session is persisted. */
  id: string | undefined;
  /** Session creation time in ms — mirrors the JWT `iat` claim (seconds). */
  createdAt: number;
  /** Session expiry time in ms — mirrors the JWT `exp` claim (seconds). */
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
  /** Session data — carried in the token payload, spread at the top level. */
  data: SessionData<T>;
  /** The current compact JWS token. `undefined` until the session is persisted. */
  token: string | undefined;
  [kGetSessionPromise]?: Promise<SessionJWS<T, MaxAge>>;
}

/**
 * Lifecycle hooks for JWS sessions. `onRead`, `onExpire`, and `onError` are
 * mutually exclusive per incoming token — `onRead` fires only when a session
 * was successfully established from it.
 */
export interface SessionHooksJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> {
  /**
   * Fires when an incoming token was verified and the session established.
   * May fire more than once per request when `useJWSSession` is called
   * concurrently in the same handler — dedupe via `session.id` if needed.
   */
  onRead?: (args: {
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Fires after a new token was signed — including pure token refreshes (update with no data). */
  onUpdate?: (args: {
    /** Session after the update. */
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    /** Deep-copied snapshot of the session before the update. */
    oldSession: SessionJWS<T, MaxAge>;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Fires when the session is cleared. */
  onClear?: (args: {
    /** Last known session before clearing, if any. */
    oldSession: SessionJWS<T, MaxAge> | undefined;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Fires when the incoming token is expired. Receives the expired token's decoded claims. */
  onExpire?: (args: {
    session: {
      id: string | undefined;
      createdAt: number | undefined;
      expiresAt: number | undefined;
      token: string;
    };
    event: TEvent;
    error: Error;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Fires on read-path failures other than expiry, and on write-path sign failures. */
  onError?: (args: {
    /**
     * The session involved in the error.
     */
    session: SessionJWS<T, MaxAge>;
    event: TEvent;
    error: any;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Resolve the verification key(s) for the incoming token from its protected header (e.g. by `kid`). */
  onVerifyKeyLookup?: (args: {
    header: JWKLookupFunctionHeader;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
}

/**
 * Configuration for a JWS-backed (signed, not encrypted) session.
 */
export interface SessionConfigJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> {
  /**
   * Key used for signing — a symmetric `oct` (HS*) JWK, a `CryptoKey`, or an
   * asymmetric pair: the private key signs, the public side verifies (single
   * JWK, array, or JWKSet for rotation). A `CryptoKey` carries no algorithm, so
   * it additionally requires `jws.signOptions.alg`.
   */
  key:
    | CryptoKey
    | JWK_oct<JWK_HMAC>
    | {
        privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
        publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
      };
  /**
   * Session lifetime — sets `exp = iat + maxAge` in the token, bounds the age
   * of an incoming token, and drives the cookie expiry. Without it the session
   * writes no `exp` and never expires on its own.
   */
  maxAge?: MaxAge;
  /** Session name — drives the cookie name and the default session header. Default `"h3-jws"`. */
  name?: string;
  /** Cookie options (`false` to disable). Defaults: `path="/"`, `secure`, `sameSite: "lax"`, `httpOnly: false` — the JWS payload is client-readable by design. */
  cookie?: false | (CookieSerializeOptions & { chunkMaxLength?: number });
  /** Request header to read the token from (`false` to disable). Default `x-<name>-session`. */
  sessionHeader?: false | string;
  /** Session ID (`jti`) generator. Default `crypto.randomUUID`. */
  generateId?: () => string;
  /** JWS sign/verify overrides. Set `signOptions.alg` to pin the session algorithm — verification then accepts only it. */
  jws?: {
    signOptions?: Omit<JWSSignOptions, "expiresIn">;
    verifyOptions?: JWTClaimValidationOptions;
  };
  /** Lifecycle hooks — see {@link SessionHooksJWS}. */
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}

const DEFAULT_NAME = "h3-jws";
const DEFAULT_COOKIE: SessionConfigJWS["cookie"] = {
  path: "/",
  secure: true,
  httpOnly: false,
  sameSite: "lax",
};

/**
 * Create a session manager for the current request using JWS (signed only, not encrypted).
 * NOTE: Contents are visible to clients (Base64URL-decoded JSON). Do not store secrets in session data.
 */
export async function useJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  const slot = sessionSlot("jws", config.name || DEFAULT_NAME);
  await getJWSSession(event, config);

  const sessionManager: SessionManager<T, MaxAge> = {
    get id() {
      return (event.context.sessions?.[slot] as SessionJWS<T, MaxAge> | undefined)?.id;
    },
    get createdAt() {
      return (
        (event.context.sessions?.[slot] as SessionJWS<T, MaxAge> | undefined)?.createdAt ??
        Date.now()
      );
    },
    get expiresAt() {
      return (event.context.sessions?.[slot] as SessionJWS<T, MaxAge> | undefined)
        ?.expiresAt as SessionManager<T, MaxAge>["expiresAt"];
    },
    get data() {
      return ((event.context.sessions?.[slot] as SessionJWS<T, MaxAge> | undefined)?.data ||
        {}) as T;
    },
    get token() {
      const session = event.context.sessions?.[slot] as SessionJWS<T, MaxAge> | undefined;
      return session ? session.token : getJWSSessionToken(event, config);
    },
    update: async (update?: SessionUpdate<T>, options?: SessionIssueOptions) => {
      await updateJWSSession(event, config, update, options);
      return sessionManager as Awaited<ReturnType<SessionManager<T, MaxAge>["update"]>>;
    },
    clear: async () => {
      await clearJWSSession(event, config);
      return sessionManager as Awaited<ReturnType<SessionManager<T, MaxAge>["clear"]>>;
    },
  };
  return sessionManager;
}

/**
 * Get (and lazily initialize) the session for the current request.
 */
export async function getJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionJWS<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  const slot = sessionSlot("jws", sessionName);
  const sessions = getSessionsContext(event);

  const existingSession = sessions[slot] as SessionJWS<T, MaxAge> | undefined;
  if (existingSession) {
    const session = existingSession[kGetSessionPromise]
      ? await existingSession[kGetSessionPromise]
      : existingSession;

    /**
     * We check if a session is expired before returning it. If it is expired we clear it and create a new one,
     * unless we have a read-only event in which case we just return it as it was valid at the time of reading
     * the cookie/header (like in a websocket upgrade)
     */
    if (session.expiresAt !== undefined && session.expiresAt < Date.now()) {
      await config.hooks?.onExpire?.({
        session: {
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          token: session.token!,
        },
        event,
        error: expiredSessionError({ id: session.id, expiresAt: session.expiresAt }),
        config,
      });
      dropSessionCookie(event, sessionName, config);
      const freshSession = emptySession<T, MaxAge>(config);
      sessions[slot] = freshSession;
      return freshSession;
    }

    if (session.id !== undefined && session.token !== undefined) {
      await config.hooks?.onRead?.({
        session: session as SessionJWS<T, MaxAge> & { id: string; token: string },
        event,
        config,
      });
    }
    return session;
  }

  const session = emptySession<T, MaxAge>(config);
  sessions[slot] = session;

  const token = getJWSSessionToken(event, config);

  let exclusiveHookFired = false;
  if (token) {
    session.token = token;
    const promise = verifyJWSSession(event, config, token)
      .catch(async (error_) => {
        exclusiveHookFired = true;
        if (isJWTError(error_, "ERR_JWT_EXPIRED")) {
          session.token = undefined;
          dropSessionCookie(event, sessionName, config);
          await config.hooks?.onExpire?.({
            session: {
              id: error_.cause.jti,
              createdAt: error_.cause.iat ? error_.cause.iat * 1000 : undefined,
              expiresAt: error_.cause.exp ? error_.cause.exp * 1000 : undefined,
              token,
            },
            error: error_,
            event,
            config,
          });
        } else {
          await config.hooks?.onError?.({
            session,
            error: error_,
            event,
            config,
          });
        }
        return undefined;
      })
      .then((unsealed) => {
        if (unsealed) {
          Object.assign(session, unsealed);
        }
        delete session[kGetSessionPromise];
        return session;
      });
    session[kGetSessionPromise] = promise;
    await promise;
  }

  if (!exclusiveHookFired && session.id !== undefined && session.token !== undefined) {
    await config.hooks?.onRead?.({
      session: session as SessionJWS<T, MaxAge> & { id: string; token: string },
      event,
      config,
    });
  }
  return session;
}

/**
 * Read the raw session token for the request. The cookie is consulted first,
 * and the session header (default `x-<name>-session`, optional case-insensitive
 * `Bearer` prefix) only when the cookie carries none.
 */
export function getJWSSessionToken<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): string | undefined {
  return readSessionToken(event, config.name || DEFAULT_NAME, config);
}

/**
 * Update the session data (if provided) and reissue the JWS token.
 * Pass `options.maxAge` to give this one token a lifetime of its own.
 */
export async function updateJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWS<T, MaxAge, TEvent>,
  update?: SessionUpdate<T>,
  options?: SessionIssueOptions,
): Promise<SessionJWS<T, MaxAge> & { id: string; token: string }> {
  const canWriteCookie = hasWritableResponse(event);
  if (config.cookie !== false && !canWriteCookie) {
    throw readOnlyEventError(`${PREFIX} Cannot update session on read-only event.`);
  }

  const sessionName = config.name || DEFAULT_NAME;
  const slot = sessionSlot("jws", sessionName);

  const session: SessionJWS<T, MaxAge> & { id: string; token: string } =
    (event.context.sessions?.[slot] as SessionJWS<T, MaxAge> & {
      id: string;
      token: string;
    }) || (await getJWSSession(event, config));

  // Snapshot before the updater runs, with a deep copy of `data`, so
  // `oldSession` is a true "before" state for hook diffing and rollback.
  const oldSession = { ...session, data: sanitizeObjectCopy(session.data) };

  const resolved = typeof update === "function" ? update(session.data) : update;
  if (resolved) {
    Object.assign(session.data, sanitizeSessionUpdate(resolved, { prefix: PREFIX }));
  }

  const maxAge = options?.maxAge ?? config.maxAge;
  const now = config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  Object.assign(session, {
    id: config.generateId?.() || crypto.randomUUID(),
    createdAt,
    expiresAt: resolveExpiresAt(createdAt, { maxAge }),
  });

  let token: string;
  try {
    token = await signJWSSession(event, config);
  } catch (error_) {
    Object.assign(session, {
      id: oldSession.id,
      createdAt: oldSession.createdAt,
      expiresAt: oldSession.expiresAt,
      data: oldSession.data,
    });
    session.token = oldSession.token;
    await config.hooks?.onError?.({ session, event, error: error_, config });
    throw error_;
  }
  session.token = token;
  if (config.cookie !== false && canWriteCookie) {
    setChunkedCookie(event as H3Event, sessionName, token, {
      ...DEFAULT_COOKIE,
      ...config.cookie,
      expires: session.expiresAt === undefined ? undefined : new Date(session.expiresAt),
    });
  }

  // Fires after signing so the hook receives the definitive new token, jti, and
  // timestamps. Also fires on pure token refresh (update is undefined).
  await config.hooks?.onUpdate?.({
    session,
    oldSession,
    event,
    config,
  });

  return session;
}

/**
 * Sign the current session as a compact JWS.
 * Payload: `session.data` spread at the top level, plus the reserved claims
 * `jti`, `iat`, and `exp` (when the session has a lifetime).
 */
export async function signJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<string> {
  const key = getSignKey(config);
  const slot = sessionSlot("jws", config.name || DEFAULT_NAME);

  const session: SessionJWS<T, MaxAge> =
    (event.context.sessions?.[slot] as SessionJWS<T, MaxAge>) ||
    (await getJWSSession(event, config));

  const iat = Math.floor(session.createdAt / 1000);
  const exp = session.expiresAt ? Math.floor(session.expiresAt / 1000) : undefined;

  const payload: Record<string, any> = {
    ...session.data,
    jti: session.id,
    iat,
  };
  if (exp) {
    payload.exp = exp;
  }

  return sign(payload as Record<string, unknown>, key as JWSSignJWK, {
    ...config.jws?.signOptions,
    // `exp` is computed from the session lifetime and carried via the claim above.
    expiresIn: undefined,
    protectedHeader: {
      ...config.jws?.signOptions?.protectedHeader,
      kid: "kid" in key ? key.kid : undefined,
      typ: sessionTyp(config.jws?.signOptions?.protectedHeader?.typ),
      cty: "application/json",
    },
  });
}

/**
 * Verify and parse a compact JWS into a Session structure.
 * Performs:
 *  - cryptographic signature verification
 *  - claim validation (always on): `jti` & `iat` required, `exp` honoured
 *  - `typ` and `cty` header checks, and algorithm pinning when configured
 *  - `maxAge` enforced as `maxTokenAge`, and `exp` required alongside it
 */
export async function verifyJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWS<T, MaxAge, TEvent>,
  token: string,
): Promise<Partial<SessionJWS<T, MaxAge>>> {
  const alg = config.jws?.signOptions?.alg;
  const jwk = config.hooks?.onVerifyKeyLookup
    ? (header: JWKLookupFunctionHeader) =>
        config.hooks!.onVerifyKeyLookup!({
          header,
          event,
          config,
        })
    : getVerifyKey(config);

  const { payload, protectedHeader } = await verify<T & { jti: string; iat: number }>(
    token,
    jwk as JWSVerifyJWK,
    {
      ...config.jws?.verifyOptions,
      requiredClaims: sessionRequiredClaims(config.jws?.verifyOptions?.requiredClaims, {
        maxAge: config.maxAge,
      }),
      typ: sessionTyp(config.jws?.signOptions?.protectedHeader?.typ),
      maxTokenAge: config.maxAge,
      algorithms: alg ? [alg] : undefined,
      forceUint8Array: false,
      validateClaims: true,
    },
  ).catch((error_: unknown) => rethrowAsInvalidToken(error_, { prefix: PREFIX }));

  assertSessionContentType(protectedHeader.cty, { prefix: PREFIX });

  const { jti, iat, exp, data } = splitSessionClaims(payload);

  return {
    id: jti,
    createdAt: iat * 1000,
    expiresAt: (exp ? exp * 1000 : undefined) as SessionJWS<T, MaxAge>["expiresAt"],
    data: data as SessionData<T>,
  };
}

/**
 * Clear the session: drop the cookie and leave an empty session behind, so a
 * later read in the same request sees no session rather than the request cookie.
 */
export async function clearJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<void> {
  const canWriteCookie = hasWritableResponse(event);
  if (config.cookie !== false && !canWriteCookie) {
    throw readOnlyEventError(`${PREFIX} Cannot clear session on read-only event.`);
  }

  const sessionName = config.name || DEFAULT_NAME;
  const slot = sessionSlot("jws", sessionName);
  const sessions = getSessionsContext(event);

  let session = sessions[slot] as SessionJWS<T, MaxAge> | undefined;
  if (session && session[kGetSessionPromise]) {
    session = await session[kGetSessionPromise];
  }
  const oldSession =
    session && (session.id !== undefined || session.token !== undefined)
      ? { ...session, data: sanitizeObjectCopy(session.data) }
      : undefined;

  sessions[slot] = emptySession<T, MaxAge>(config);

  if (config.cookie !== false && canWriteCookie) {
    deleteChunkedCookie(event as H3Event, sessionName, { ...DEFAULT_COOKIE, ...config.cookie });
  }

  await config.hooks?.onClear?.({
    oldSession,
    event,
    config,
  });
}

function emptySession<T extends Record<string, any>, MaxAge extends ExpiresIn | undefined>(
  config: SessionConfigJWS<T, MaxAge, any>,
): SessionJWS<T, MaxAge> {
  const now = config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  return {
    id: undefined,
    createdAt,
    expiresAt: resolveExpiresAt(createdAt, { maxAge: config.maxAge }) as SessionJWS<
      T,
      MaxAge
    >["expiresAt"],
    data: Object.create(null),
    token: undefined,
  };
}

function dropSessionCookie(
  event: CompatEvent | H3Event,
  sessionName: string,
  config: SessionConfigJWS<any, any, any>,
): void {
  if (config.cookie === false) return;
  if (!hasWritableResponse(event)) {
    console.warn(`${PREFIX} Session expired but cookie cannot be cleared on a read-only event.`);
    return;
  }
  deleteChunkedCookie(event, sessionName, { ...DEFAULT_COOKIE, ...config.cookie });
}

function getSignKey(config: SessionConfigJWS<any, any, any>): JWSSignJWK | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix: PREFIX });

  let _key: JWSSignJWK | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("privateKey" in key) {
    const privateKey = key.privateKey;
    if (isCryptoKey(privateKey) || isPrivateJWK(privateKey)) _key = privateKey;
  }

  if (!_key) {
    throw invalidKeyError(
      `${PREFIX} Invalid JWS key. It must be a symmetric JWK, a private JWK, or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlg(_key, config);
  return _key;
}

function getVerifyKey(config: SessionConfigJWS<any, any, any>): JWSVerifyJWK | JWKSet | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix: PREFIX });

  let _key: JWSVerifyJWK | JWKSet | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("publicKey" in key) {
    const publicKey = key.publicKey;
    if (isCryptoKey(publicKey)) {
      _key = publicKey;
    } else if (isPublicJWK(publicKey)) {
      _key = publicKey;
    } else if (Array.isArray(publicKey)) {
      const keys = publicKey.filter((candidate) => isPublicJWK(candidate));
      if (keys.length > 0) {
        _key = { keys };
      }
    } else if (
      publicKey &&
      typeof publicKey === "object" &&
      Array.isArray((publicKey as JWKSet).keys)
    ) {
      const keys = (publicKey as JWKSet).keys.filter((candidate) => isPublicJWK(candidate));
      if (keys.length > 0) {
        _key = { keys };
      }
    }
  }

  if (!_key) {
    throw invalidKeyError(
      `${PREFIX} Invalid JWS key. It must be a symmetric JWK, a public JWK/set, or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlg(_key, config);
  return _key;
}

function assertPinnedAlg(key: unknown, config: SessionConfigJWS<any, any, any>): void {
  if (isCryptoKey(key) && !config.jws?.signOptions?.alg) {
    throw invalidConfigError(
      `${PREFIX} A CryptoKey session key carries no algorithm: set "jws.signOptions.alg".`,
    );
  }
}
