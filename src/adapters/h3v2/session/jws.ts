import {
  type H3Event,
  type HTTPEvent,
  type H3EventContext,
  getEventContext,
  getChunkedCookie,
  setChunkedCookie,
} from "h3v2";

import type { CookieSerializeOptions } from "cookie-esv3";

import { NullProtoObj } from "rou3";
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
import { sign, verify, JWTError, isJWTError } from "../../../core/jws";
import {
  isSymmetricJWK,
  isPrivateJWK,
  isPublicJWK,
  computeDurationInSeconds,
} from "../../../core/utils";
import type { SessionClaims, SessionData, SessionUpdate, SessionManager } from "./types";

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
  expiresAt: MaxAge extends ExpiresIn ? number : T["exp"];
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
  TEvent extends HTTPEvent = HTTPEvent,
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
  TEvent extends HTTPEvent = HTTPEvent,
> {
  /**
   * JWK used for signing — a symmetric `oct` (HS*) key, or an asymmetric pair:
   * the private key signs, the public side verifies (single JWK, array, or
   * JWKSet for rotation).
   */
  key:
    | JWK_oct<JWK_HMAC>
    | {
        privateKey: JWSAsymmetricPrivateJWK;
        publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet;
      };
  /**
   * Session lifetime in seconds — sets `exp = iat + maxAge` in the token and
   * drives the cookie expiry. Without it the library writes no `exp` — though
   * an `exp` key in the session data is then carried into the token as its
   * actual expiry claim.
   */
  maxAge?: MaxAge;
  /** Session name — drives the cookie name and the default session header. Default `"h3-jws"`. */
  name?: string;
  /** Cookie options (`false` to disable). Defaults: `path="/"`, `secure`, `httpOnly: false` — the JWS payload is client-readable by design. */
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
};

/**
 * Create a session manager for the current request using JWS (signed only, not encrypted).
 * NOTE: Contents are visible to clients (Base64URL-decoded JSON). Do not store secrets in session data.
 */
export async function useJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  await getJWSSession(event, config);

  const sessionManager: SessionManager<T, MaxAge> = {
    get id() {
      return getSessionFromContext<T, MaxAge>(event, sessionName)?.id;
    },
    get createdAt() {
      return getSessionFromContext<T, MaxAge>(event, sessionName)?.createdAt ?? Date.now();
    },
    get expiresAt() {
      return getSessionFromContext<T, MaxAge>(event, sessionName)
        ?.expiresAt as MaxAge extends ExpiresIn ? number : T["exp"];
    },
    get data() {
      return (getSessionFromContext<T, MaxAge>(event, sessionName)?.data || {}) as T;
    },
    get token() {
      return (
        getSessionFromContext<T, MaxAge>(event, sessionName)?.token ??
        getJWSSessionToken(event, config)
      );
    },
    update: async (update?: SessionUpdate<T>) => {
      await updateJWSSession(event, config, update);
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
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<SessionJWS<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  const context = getEventContext<H3EventContext>(event);

  if (!context.sessions) {
    context.sessions = new NullProtoObj();
  }

  const existingSession = context.sessions![sessionName] as SessionJWS<T, MaxAge> | undefined;
  if (existingSession) {
    const session = existingSession[kGetSessionPromise]
      ? await existingSession[kGetSessionPromise]
      : existingSession;

    if (session.expiresAt !== undefined && session.expiresAt < Date.now()) {
      await config.hooks?.onExpire?.({
        session: {
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          token: session.token!,
        },
        event,
        error: new JWTError(
          `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(session.expiresAt * 1000).toISOString()})`,
          "ERR_JWT_EXPIRED",
          { jti: session.id, exp: session.expiresAt / 1000 },
        ),
        config,
      });
      delete context.sessions![sessionName];
      if (config.cookie !== false) {
        if (hasWritableResponse(event)) {
          setChunkedCookie(event, sessionName, "", {
            ...DEFAULT_COOKIE,
            ...config.cookie,
            expires: new Date(0),
            maxAge: undefined,
          });
        } else {
          console.warn(
            "[unjwt/h3] Session expired but cookie cannot be cleared on a read-only event.",
          );
        }
      }
      const freshNow = config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
      const freshCreatedAt = freshNow - (freshNow % 1000);
      const freshSession: SessionJWS<T, MaxAge> = {
        id: undefined,
        createdAt: freshCreatedAt,
        expiresAt: (config.maxAge === undefined
          ? undefined
          : freshCreatedAt +
            computeDurationInSeconds(config.maxAge) * 1000) as MaxAge extends ExpiresIn
          ? number
          : T["exp"],
        data: new NullProtoObj(),
        token: undefined,
      };
      // @ts-expect-error upstream types expect an empty id string
      context.sessions![sessionName] = freshSession;
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

  const now = config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  const session: SessionJWS<T, MaxAge> = {
    id: undefined,
    createdAt,
    expiresAt: (config.maxAge === undefined
      ? undefined
      : createdAt + computeDurationInSeconds(config.maxAge) * 1000) as MaxAge extends ExpiresIn
      ? number
      : T["exp"],
    data: new NullProtoObj(),
    token: undefined,
  };
  // @ts-expect-error upstream types expect an empty id string
  context.sessions![sessionName] = session;

  const token = getJWSSessionToken(event, config);

  let exclusiveHookFired = false;
  if (token) {
    session.token = token;
    const promise = verifyJWSSession(event, config, token)
      .catch(async (error_) => {
        exclusiveHookFired = true;
        if (isJWTError(error_, "ERR_JWT_EXPIRED")) {
          await config.hooks?.onExpire?.({
            session: {
              id: error_.cause.jti,
              createdAt: error_.cause.iat ? error_.cause.iat * 1000 : undefined,
              expiresAt: error_.cause.exp ? error_.cause.exp * 1000 : undefined,
              token,
            },
            event,
            error: error_,
            config,
          });
        } else {
          await config.hooks?.onError?.({
            session,
            event,
            error: error_,
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
        return session as SessionJWS<T, MaxAge>;
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
 * Read the raw session token for the request. The session header (default
 * `x-<name>-session`, `Bearer ` prefix stripped) takes precedence, then a
 * freshly-minted token on the response's `Set-Cookie`, then the session cookie.
 */
export function getJWSSessionToken<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): string | undefined {
  const sessionName = config.name || DEFAULT_NAME;

  let token: string | undefined;

  if (config.sessionHeader !== false) {
    const headerName =
      typeof config.sessionHeader === "string"
        ? config.sessionHeader.toLowerCase()
        : `x-${sessionName.toLowerCase()}-session`;
    const headerValue = event.req.headers.get(headerName);
    if (typeof headerValue === "string") {
      token = headerValue.startsWith("Bearer ") ? headerValue.slice(7).trim() : headerValue;
    }
  }

  // Set-Cookie header may carry a freshly-minted session on redirect responses.
  if (config.cookie !== false && hasWritableResponse(event)) {
    const setCookie = event.res.headers.get("set-cookie");
    if (typeof setCookie === "string") {
      token = findSetCookie(setCookie, sessionName);
    }
  }

  if (!token) {
    token = getChunkedCookie(event, sessionName);
  }

  return token;
}

/**
 * Update the session data (if provided) and reissue the JWS token.
 */
export async function updateJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(
  event: TEvent,
  config: SessionConfigJWS<T, MaxAge, TEvent>,
  update?: SessionUpdate<T>,
): Promise<SessionJWS<T, MaxAge>> {
  const canWriteCookie = hasWritableResponse(event);
  if (config.cookie !== false && !canWriteCookie) {
    throw new Error("[unjwt/h3] Cannot update session on read-only event.");
  }

  const sessionName = config.name || DEFAULT_NAME;
  const context = getEventContext<H3EventContext>(event);

  const session: SessionJWS<T, MaxAge> & { id: string; token: string } =
    (context.sessions?.[sessionName] as SessionJWS<T, MaxAge> & { id: string; token: string }) ||
    (await getJWSSession(event, config));

  // Snapshot before the updater runs, with a deep copy of `data`, so
  // `oldSession` is a true "before" state for hook diffing and rollback.
  const oldSession = { ...session, data: sanitizeObjectCopy(session.data) };

  if (typeof update === "function") {
    update = update(session.data);
  }

  if (update) {
    Object.assign(session.data, update);
  }

  const now = config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000); // round to seconds
  Object.assign(session, {
    id: config.generateId?.() || crypto.randomUUID(),
    createdAt,
    expiresAt:
      config.maxAge === undefined
        ? undefined
        : createdAt + computeDurationInSeconds(config.maxAge) * 1000,
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
    setChunkedCookie(event, sessionName, token, {
      ...DEFAULT_COOKIE,
      expires:
        config.maxAge === undefined
          ? undefined
          : new Date(session.createdAt + computeDurationInSeconds(config.maxAge) * 1000),
      ...config.cookie,
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
 * `jti`, `iat`, and `exp` (when `maxAge` is set), which overwrite any
 * same-named keys in the session data.
 */
export async function signJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<string> {
  const key = getSignKey(config.key);
  const sessionName = config.name || DEFAULT_NAME;
  const context = getEventContext<H3EventContext>(event);

  const session: SessionJWS<T, MaxAge> =
    (context.sessions?.[sessionName] as SessionJWS<T, MaxAge>) ||
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

  let typ: string | undefined;
  if (
    config.jws?.signOptions?.protectedHeader?.typ &&
    typeof config.jws.signOptions.protectedHeader.typ === "string" &&
    config.jws.signOptions.protectedHeader.typ.toLowerCase().includes("jwt")
  ) {
    typ = config.jws.signOptions.protectedHeader.typ;
  }

  const token = await sign(payload, key, {
    ...config.jws?.signOptions,
    // `exp` is computed from `maxAge` and carried via the `exp` claim above.
    expiresIn: undefined,
    protectedHeader: {
      ...config.jws?.signOptions?.protectedHeader,
      kid: "kid" in key ? key.kid : undefined,
      typ: typ || "JWT",
      cty: "application/json",
    },
  });

  return token;
}

/**
 * Verify and parse a compact JWS into a Session structure.
 * Performs:
 *  - cryptographic signature verification
 *  - claim validation (always on): `jti` & `iat` required, `exp` honoured
 *  - `typ` header check and algorithm pinning when configured
 *  - `maxAge` enforced as `maxTokenAge` when provided
 */
export async function verifyJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
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
    : getVerifyKey(config.key);

  let typ: string | undefined;
  if (
    config.jws?.signOptions?.protectedHeader?.typ &&
    typeof config.jws.signOptions.protectedHeader.typ === "string" &&
    config.jws.signOptions.protectedHeader.typ.toLowerCase().includes("jwt")
  ) {
    typ = config.jws.signOptions.protectedHeader.typ;
  }

  const { payload } = await verify<T & { iat: number }>(token, jwk, {
    ...config.jws?.verifyOptions,
    requiredClaims: [
      ...new Set([...(config.jws?.verifyOptions?.requiredClaims || []), "jti", "iat"]),
    ],
    typ: typ || "JWT",
    algorithms: alg ? [alg] : undefined,
    forceUint8Array: false,
    validateClaims: true,
  }).catch((error_: unknown) => {
    if (isJWTError(error_, "ERR_JWT_EXPIRED")) throw error_;
    const message = error_ instanceof Error ? error_.message : String(error_);
    throw new Error(`Invalid session token: ${message}`);
  });

  const { jti, iat, exp, ...data } = payload;

  return {
    id: jti,
    createdAt: iat * 1000,
    expiresAt: (exp ? exp * 1000 : undefined) as MaxAge extends ExpiresIn ? number : T["exp"],
    data: (data && typeof data === "object" ? data : new NullProtoObj()) as SessionData<T>,
  };
}

/**
 * Clear the session (delete from context and drop cookie).
 */
export async function clearJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
>(event: TEvent, config: SessionConfigJWS<T, MaxAge, TEvent>): Promise<void> {
  const canWriteCookie = hasWritableResponse(event);
  if (config.cookie !== false && !canWriteCookie) {
    throw new Error("[unjwt/h3] Cannot clear session on read-only event.");
  }

  const context = getEventContext<H3EventContext>(event);
  const sessionName = config.name || DEFAULT_NAME;

  let session = context.sessions?.[sessionName] as SessionJWS<T, MaxAge> | undefined;
  if (session && session[kGetSessionPromise]) {
    session = await session[kGetSessionPromise];
  }
  const oldSession = session ? { ...session, data: sanitizeObjectCopy(session.data) } : undefined;

  if (context.sessions?.[sessionName]) {
    delete context.sessions![sessionName];
  }

  if (config.cookie !== false && canWriteCookie) {
    setChunkedCookie(event, sessionName, "", {
      ...DEFAULT_COOKIE,
      ...config.cookie,
      expires: new Date(0),
      maxAge: undefined,
    });
  }

  await config.hooks?.onClear?.({
    oldSession,
    event,
    config,
  });
}

function getSessionFromContext<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(event: HTTPEvent, sessionName: string): SessionJWS<T, MaxAge> | undefined {
  const context = getEventContext<H3EventContext>(event);
  return context.sessions?.[sessionName] as SessionJWS<T, MaxAge> | undefined;
}

function hasWritableResponse(event: HTTPEvent): event is H3Event {
  return Boolean((event as H3Event).res);
}

function getSignKey(key: SessionConfigJWS["key"] | undefined): JWSSignJWK {
  if (!key) {
    throw new Error("Session: JWS key is required.");
  }

  let _key: JWSSignJWK | undefined;
  if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("privateKey" in key && isPrivateJWK(key.privateKey)) {
    _key = key.privateKey;
  }

  if (!_key) {
    throw new Error("Session: Invalid JWS key. It must be a symmetric JWK or a private JWK.", {
      cause: key,
    });
  }

  return _key;
}

function getVerifyKey(key: SessionConfigJWS["key"] | undefined): JWSVerifyJWK | JWKSet {
  if (!key) {
    throw new Error("Session: JWS key is required.");
  }

  let _key: JWSVerifyJWK | JWKSet | undefined;
  if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("publicKey" in key) {
    const publicKey = key.publicKey;
    if (isPublicJWK(publicKey)) {
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
    throw new Error("Session: Invalid JWS key. It must be a symmetric JWK or a public JWK/set.", {
      cause: key,
    });
  }

  return _key;
}
function findSetCookie(setCookie: string, name: string): string | undefined {
  const regex = new RegExp(`(?:^|,\\s*)${name}=([^;]+)`);
  const match = setCookie.match(regex);

  return match ? match[1] : undefined;
}
