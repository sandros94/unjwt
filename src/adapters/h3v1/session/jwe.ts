/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { CookieSerializeOptions } from "cookie-esv1";
import { type H3Event, isEvent, setCookie } from "h3v1";
import { parse as parseCookies } from "cookie-esv1";
import type {
  ExpiresIn,
  JWK,
  JWK_oct,
  JWK_Symmetric,
  JWK_Public,
  JWK_Private,
  JWEEncryptOptions,
  JWEHeaderParameters,
  JWTClaimValidationOptions,
} from "../../../core/types";
import { encrypt, decrypt, JWTError, isJWTError } from "../../../core/jwe";
import {
  isSymmetricJWK,
  isPrivateJWK,
  isPublicJWK,
  computeExpiresInSeconds,
} from "../../../core/utils";
import type { SessionClaims, SessionData, SessionUpdate, SessionManager } from "./types";

const kGetSessionPromise: unique symbol = Symbol("h3_jwe_getSession");

export interface SessionJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  /** Session ID — mirrors the JWT `jti` claim. `undefined` until the session is persisted. */
  id: string | undefined;
  /** Session creation time in ms — mirrors the JWT `iat` claim (seconds). */
  createdAt: number;
  /** Session expiry time in ms — mirrors the JWT `exp` claim (seconds). */
  expiresAt: MaxAge extends ExpiresIn ? number : T["exp"];
  data: SessionData<T>;
  token: string | undefined;
  [kGetSessionPromise]?: Promise<SessionJWE<T, MaxAge>>;
}

export interface SessionHooksJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> {
  onRead?: (args: {
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  onUpdate?: (args: {
    /** Session after it has been updated.. */
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    /** Snapshot of the session before was updated. */
    oldSession: SessionJWE<T, MaxAge>;
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  onClear?: (args: {
    oldSession: SessionJWE<T, MaxAge> | undefined;
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  onExpire?: (args: {
    session: {
      id: string | undefined;
      createdAt: number | undefined;
      expiresAt: number | undefined;
      token: string;
    };
    event: TEvent;
    error: Error;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  onError?: (args: {
    /**
     * The session involved in the error.
     */
    session: SessionJWE<T, MaxAge>;
    event: TEvent;
    error: any;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  onUnsealKeyLookup?: (args: {
    header: JWEHeaderParameters;
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => JWK_Symmetric | JWK_Private | Promise<JWK_Symmetric | JWK_Private>;
}

export interface SessionConfigJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> {
  /** Shared key used, string for PBES2 or Json Web Key (JWK) */
  key:
    | string
    | JWK_Symmetric
    | JWK_Private
    | {
        privateKey: JWK_Private | JWK_Symmetric;
        publicKey?: JWK_Public;
      };
  /** Session lifetime in seconds (used to derive exp from iat) */
  maxAge?: MaxAge;
  /** Default is "h3" */
  name?: string;
  /** Default is secure, httpOnly, path="/" */
  cookie?: false | CookieSerializeOptions;
  /** Default is x-h3-session / x-{name}-session */
  sessionHeader?: false | string;
  /** Default is crypto.randomUUID */
  generateId?: () => string;
  /** JWE configuration overrides */
  jwe?: {
    encryptOptions?: Omit<JWEEncryptOptions, "expiresIn">;
    decryptOptions?: JWTClaimValidationOptions;
  };
  hooks?: SessionHooksJWE<T, MaxAge, TEvent>;
}

const DEFAULT_NAME = "h3-jwe";
const DEFAULT_COOKIE: SessionConfigJWE["cookie"] = {
  path: "/",
  secure: true,
  httpOnly: true,
};

// Compatible type with h3 v2 and external usage
type CompatEvent =
  | { request: { headers: Headers }; context: any }
  | { headers: Headers; context: any };

/**
 * Create a session manager for the current request.
 */
export async function useJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  await getJWESession(event, config);

  const sessionManager: SessionManager<T, MaxAge> = {
    get id() {
      return event.context.sessions?.[sessionName]?.id;
    },
    get createdAt() {
      return event.context.sessions?.[sessionName]?.createdAt || Date.now();
    },
    get expiresAt() {
      return event.context.sessions?.[sessionName]?.expiresAt;
    },
    get data() {
      return (event.context.sessions?.[sessionName]?.data || {}) as T;
    },
    get token() {
      return (
        (event.context.sessions?.[sessionName] as SessionJWE<T, MaxAge>)?.token ??
        getJWESessionToken(event, config)
      );
    },
    update: async (update?: SessionUpdate<T>) => {
      await updateJWESession(event, config, update);
      return sessionManager as Awaited<ReturnType<SessionManager<T, MaxAge>["update"]>>;
    },
    clear: async () => {
      await clearJWESession(event, config);
      return sessionManager as Awaited<ReturnType<SessionManager<T, MaxAge>["clear"]>>;
    },
  };

  return sessionManager;
}

/**
 * Get (and lazily initialize) the session for the current request.
 */
export async function getJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionJWE<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;

  if (!event.context.sessions) {
    event.context.sessions = Object.create(null);
  }

  const existingSession = event.context.sessions![sessionName] as SessionJWE<T, MaxAge>;
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
        error: new JWTError(
          `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(session.expiresAt * 1000).toISOString()})`,
          "ERR_JWT_EXPIRED",
          { jti: session.id, exp: session.expiresAt / 1000 },
        ),
        config,
      });
      delete event.context.sessions![sessionName];
      if (config.cookie !== false) {
        if (isEvent(event)) {
          setCookie(event, sessionName, "", {
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
      const freshNow = config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
      const freshCreatedAt = freshNow - (freshNow % 1000);
      const freshSession: SessionJWE<T, MaxAge> = {
        id: undefined,
        createdAt: freshCreatedAt,
        expiresAt: (config.maxAge === undefined
          ? undefined
          : freshCreatedAt +
            computeExpiresInSeconds(config.maxAge) * 1000) as MaxAge extends ExpiresIn
          ? number
          : T["exp"],
        data: Object.create(null),
        token: undefined,
      };
      event.context.sessions![sessionName] = freshSession;
      return freshSession;
    }

    if (session.id !== undefined && session.token !== undefined) {
      await config.hooks?.onRead?.({
        session: session as SessionJWE<T, MaxAge> & { id: string; token: string },
        event,
        config,
      });
    }
    return session;
  }

  const now = config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  const session: SessionJWE<T, MaxAge> = {
    id: undefined,
    createdAt,
    expiresAt: (config.maxAge === undefined
      ? undefined
      : createdAt + computeExpiresInSeconds(config.maxAge) * 1000) as MaxAge extends ExpiresIn
      ? number
      : T["exp"],
    data: Object.create(null),
    token: undefined,
  };
  event.context.sessions![sessionName] = session;

  const token = getJWESessionToken(event, config);

  let exclusiveHookFired = false;
  if (token) {
    session.token = token;
    const promise = unsealJWESession(event, config, token)
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
        delete event.context.sessions![sessionName][kGetSessionPromise];
        return session as SessionJWE<T, MaxAge>;
      });
    event.context.sessions![sessionName][kGetSessionPromise] = promise;
    await promise;
  }

  if (!exclusiveHookFired && session.id !== undefined && session.token !== undefined) {
    await config.hooks?.onRead?.({
      session: session as SessionJWE<T, MaxAge> & { id: string; token: string },
      event,
      config,
    });
  }
  return session;
}

export function getJWESessionToken<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): string | undefined {
  const sessionName = config.name || DEFAULT_NAME;
  let token: string | undefined;

  if (config.sessionHeader !== false) {
    const headerName =
      typeof config.sessionHeader === "string"
        ? config.sessionHeader.toLowerCase()
        : `x-${sessionName.toLowerCase()}-session`;
    const headerValue = _getReqHeader(event, headerName);
    if (typeof headerValue === "string") {
      token = headerValue.startsWith("Bearer ") ? headerValue.slice(7).trim() : headerValue;
    }
  }

  // Set-Cookie header may carry a freshly-minted session on redirect responses.
  if (config.cookie !== false) {
    const setCookie = _getResHeader(event, "set-cookie");
    if (typeof setCookie === "string") {
      token = findSetCookie(setCookie, sessionName);
    } else if (Array.isArray(setCookie)) {
      for (const sc of setCookie) {
        token = findSetCookie(sc, sessionName);
        if (token) {
          break;
        }
      }
    }
  }

  if (!token) {
    const cookieHeader = _getReqHeader(event, "cookie");
    if (cookieHeader) {
      token = parseCookies(String(cookieHeader))[sessionName];
    }
  }

  return token;
}

function _getReqHeader(event: H3Event | CompatEvent, name: string) {
  if ((event as H3Event).node) {
    return (event as H3Event).node?.req.headers[name];
  }
  if ((event as { request?: Request }).request) {
    return (event as { request?: Request }).request!.headers?.get(name);
  }
  if ((event as { headers?: Headers }).headers) {
    return (event as { headers?: Headers }).headers!.get(name);
  }
}

function _getResHeader(event: H3Event | CompatEvent, name: string) {
  if ((event as H3Event).node) {
    return (event as H3Event).node?.res.getHeader(name);
  }
  if ((event as { response?: Response }).response) {
    return (event as { response?: Response }).response!.headers?.get(name);
  }
}

/**
 * Update the session (optionally mutating the session data) and re-issue the JWE token.
 */
export async function updateJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
  update?: SessionUpdate<T>,
): Promise<SessionJWE<T, MaxAge> & { id: string; token: string }> {
  const canWriteCookie = isEvent(event);
  if (config.cookie !== false && !canWriteCookie) {
    throw new Error("[unjwt/h3] Cannot update session on read-only event.");
  }

  const sessionName = config.name || DEFAULT_NAME;

  const session: SessionJWE<T, MaxAge> & { id: string; token: string } =
    (event.context.sessions?.[sessionName] as SessionJWE<T, MaxAge> & {
      id: string;
      token: string;
    }) || (await getJWESession(event, config));

  if (typeof update === "function") {
    update = update(session.data);
  }

  const oldSession = { ...session, data: { ...session.data } };

  if (update) {
    Object.assign(session.data, update);
  }

  const now = config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  Object.assign(session, {
    id: config.generateId?.() || crypto.randomUUID(),
    createdAt,
    expiresAt:
      config.maxAge === undefined
        ? undefined
        : createdAt + computeExpiresInSeconds(config.maxAge) * 1000,
  });

  let sealed: string;
  try {
    sealed = await sealJWESession(event, config);
  } catch (error_) {
    Object.assign(session, {
      id: oldSession.id,
      createdAt: oldSession.createdAt,
      expiresAt: oldSession.expiresAt,
    });
    session.token = oldSession.token;
    await config.hooks?.onError?.({ session, event, error: error_, config });
    throw error_;
  }
  session.token = sealed;
  if (config.cookie !== false && canWriteCookie) {
    setCookie(event, sessionName, sealed, {
      ...DEFAULT_COOKIE,
      ...config.cookie,
      expires:
        config.maxAge === undefined
          ? undefined
          : new Date(session.createdAt + computeExpiresInSeconds(config.maxAge) * 1000),
    });
  }

  // Fires after sealing so the hook receives the definitive new token, jti, and
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
 * Produce a JWE for the current session.
 * Payload structure:
 * {
 *   jti: string;
 *   iat: number; (seconds)
 *   exp?: number; (seconds)
 *   data: Record<string, any>;
 * }
 */
export async function sealJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<string> {
  const key = getEncryptKey(config.key);

  const sessionName = config.name || DEFAULT_NAME;

  const session: SessionJWE<T, MaxAge> =
    (event.context.sessions?.[sessionName] as SessionJWE<T, MaxAge>) ||
    (await getJWESession(event, config));

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

  let typ: string | undefined = undefined;
  if (
    config.jwe?.encryptOptions?.protectedHeader?.typ &&
    typeof config.jwe.encryptOptions.protectedHeader.typ === "string" &&
    config.jwe.encryptOptions.protectedHeader.typ.toLowerCase().includes("jwt")
  ) {
    typ = config.jwe.encryptOptions.protectedHeader.typ;
  }
  const token = await encrypt(payload, key, {
    ...config.jwe?.encryptOptions,
    // `exp` is computed from `maxAge` and carried via the `exp` claim above.
    expiresIn: undefined,
    protectedHeader: {
      ...config.jwe?.encryptOptions?.protectedHeader,
      kid: typeof key === "string" ? undefined : key.kid,
      typ: typ || "JWT",
      cty: "application/json",
    },
  });

  return token;
}

/**
 * Decrypt the JWE and return a Session-compatible object.
 */
export async function unsealJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
  sealed: string,
): Promise<Partial<SessionJWE<T, MaxAge>>> {
  const key = config.hooks?.onUnsealKeyLookup
    ? (header: JWEHeaderParameters) =>
        config.hooks!.onUnsealKeyLookup!({
          header,
          event,
          config,
        })
    : getDecryptKey(config.key);

  const alg = config.jwe?.encryptOptions?.alg;
  const enc = config.jwe?.encryptOptions?.enc;

  let typ: string | undefined = undefined;
  if (
    config.jwe?.encryptOptions?.protectedHeader?.typ &&
    typeof config.jwe.encryptOptions.protectedHeader.typ === "string" &&
    config.jwe.encryptOptions.protectedHeader.typ.toLowerCase().includes("jwt")
  ) {
    typ = config.jwe.encryptOptions.protectedHeader.typ;
  }
  const { payload } = await decrypt<T & { jti: string; iat: number; exp?: number }>(sealed, key, {
    ...config.jwe?.decryptOptions,
    requiredClaims: [
      ...new Set([...(config.jwe?.decryptOptions?.requiredClaims || []), "jti", "iat"]),
    ],
    typ: typ || "JWT",
    maxTokenAge: config.maxAge,
    algorithms: alg ? [alg] : undefined,
    encryptionAlgorithms: enc ? [enc] : undefined,
    unwrappedKeyAlgorithm: undefined,
    keyUsage: undefined,
    forceUint8Array: false,
    validateClaims: true,
  }).catch((error_) => {
    if (isJWTError(error_, "ERR_JWT_EXPIRED")) throw error_;
    const message = error_ instanceof Error ? error_.message : String(error_);
    throw new Error(`Invalid session token: ${message}`);
  });

  const { jti, iat, exp, ...data } = payload;

  return {
    id: jti,
    createdAt: iat * 1000,
    expiresAt: (exp ? exp * 1000 : undefined) as MaxAge extends ExpiresIn ? number : T["exp"],
    data: (data && typeof data === "object" ? data : Object.create(null)) as any,
  };
}

/**
 * Clear the session (delete from context and drop cookie).
 */
export async function clearJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<void> {
  const canWriteCookie = isEvent(event);
  if (config.cookie !== false && !canWriteCookie) {
    throw new Error("[unjwt/h3] Cannot clear session on read-only event.");
  }

  const sessionName = config.name || DEFAULT_NAME;

  let session = event.context.sessions?.[sessionName] as SessionJWE<T, MaxAge> | undefined;
  if (session && session[kGetSessionPromise]) {
    session = await session[kGetSessionPromise];
  }
  const oldSession = session ? { ...session, data: { ...session.data } } : undefined;

  if (event.context.sessions?.[sessionName]) {
    delete event.context.sessions[sessionName];
  }

  if (config.cookie !== false && canWriteCookie) {
    setCookie(event, sessionName, "", {
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

function getEncryptKey(key: SessionConfigJWE["key"] | undefined): string | JWK {
  if (!key) {
    throw new Error("Session: JWE key is required.");
  }

  let _key: string | JWK | undefined;
  if (typeof key === "string") {
    _key = key;
  } else if (isSymmetricJWK(key) || isPrivateJWK(key)) {
    _key = key;
  } else if ("publicKey" in key && isPublicJWK(key.publicKey)) {
    _key = key.publicKey;
  } else if ("privateKey" in key && isPrivateJWK(key.privateKey)) {
    _key = key.privateKey;
  }

  if (!_key) {
    throw new Error("Session: Invalid JWE key. It must be a password string or valid JWK.", {
      cause: key,
    });
  }

  return _key;
}
function getDecryptKey(key: SessionConfigJWE["key"] | undefined): string | JWK_oct | JWK_Private {
  if (!key) {
    throw new Error("Session: JWE key is required.");
  }

  let _key: string | JWK_oct | JWK_Private | undefined = undefined;
  if (typeof key === "string") {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("privateKey" in key) {
    _key = key.privateKey;
  }

  if (!_key) {
    throw new Error(
      "Session: Invalid JWE key. It must be a password string or a valid private JWK.",
      { cause: key },
    );
  }

  return _key;
}
function findSetCookie(setCookie: string, name: string): string | undefined {
  const regex = new RegExp(`(?:^|,\\s*)${name}=([^;]+)`);
  const match = setCookie.match(regex);

  return match ? match[1] : undefined;
}
