import {
  type H3Event,
  type HTTPEvent,
  type H3EventContext,
  getEventContext,
  getChunkedCookie,
  setChunkedCookie,
} from "h3v2";

import type { CookieSerializeOptions } from "cookie-esv2";
import { NullProtoObj } from "rou3";

import type {
  ExpiresIn,
  JWKSet,
  JWK_Public,
  JWK_Private,
  JWK_Symmetric,
  JWSSignOptions,
  JWSProtectedHeader,
  JWTClaimValidationOptions,
} from "../../../core/types";
import { sign, verify, JWTError, isJWTError } from "../../../core/jws";
import {
  isSymmetricJWK,
  isPrivateJWK,
  isPublicJWK,
  computeExpiresInSeconds,
} from "../../../core/utils";
import type { SessionClaims, SessionData, SessionUpdate, SessionManager } from "./types";

const kGetSessionPromise: unique symbol = Symbol("h3_jws_getSession");

export interface SessionJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  // Mapped from payload.jti
  id: string | undefined;
  // Mapped from payload.iat (in ms)
  createdAt: number;
  // Mapped from payload.exp (in ms)
  expiresAt: MaxAge extends ExpiresIn ? number : T["exp"];
  data: SessionData<T>;
  token: string | undefined;
  [kGetSessionPromise]?: Promise<SessionJWS<T, MaxAge>>;
}

export interface SessionHooksJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> {
  onRead?: (args: {
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  onUpdate?: (args: {
    /** Session after it has been updated.. */
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    /** Snapshot of the session before was updated. */
    oldSession: SessionJWS<T, MaxAge>;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  onClear?: (args: {
    oldSession: SessionJWS<T, MaxAge> | undefined;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
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
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  onError?: (args: {
    /**
     * The session involved in the error.
     */
    session: SessionJWS<T, MaxAge>;
    event: TEvent;
    error: any;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  onVerifyKeyLookup?: (args: {
    header: JWSProtectedHeader;
    event: TEvent;
    config: SessionConfigJWS<T, MaxAge, TEvent>;
  }) => JWKSet | JWK_Symmetric | JWK_Public | Promise<JWKSet | JWK_Symmetric | JWK_Public>;
}

export interface SessionConfigJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends HTTPEvent = HTTPEvent,
> {
  key:
    | JWK_Symmetric
    | {
        privateKey: JWK_Private;
        publicKey: JWK_Public | JWK_Public[] | JWKSet;
      };
  maxAge?: MaxAge;
  name?: string;
  cookie?: false | (CookieSerializeOptions & { chunkMaxLength?: number });
  sessionHeader?: false | string;
  generateId?: () => string;
  jws?: {
    signOptions?: Omit<JWSSignOptions, "expiresIn">;
    verifyOptions?: JWTClaimValidationOptions;
  };
  hooks?: SessionHooksJWS<T, MaxAge, TEvent>;
}

const DEFAULT_NAME = "h3-jws";
const DEFAULT_COOKIE: SessionConfigJWS["cookie"] = {
  path: "/",
  secure: true,
  httpOnly: false,
};

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
            computeExpiresInSeconds(config.maxAge) * 1000) as MaxAge extends ExpiresIn
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

  // Placeholder session object
  const now = config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000); // round to seconds
  const session: SessionJWS<T, MaxAge> = {
    id: undefined,
    createdAt,
    expiresAt: (config.maxAge === undefined
      ? undefined
      : createdAt + computeExpiresInSeconds(config.maxAge) * 1000) as MaxAge extends ExpiresIn
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

  // Check Set-Cookie (eg. in case of redirects)
  if (config.cookie !== false && hasWritableResponse(event)) {
    const setCookie = event.res.headers.get("set-cookie");
    if (typeof setCookie === "string") {
      token = findSetCookie(setCookie, sessionName);
    }
  }

  // Fallback to cookie if not found earlier
  if (!token) {
    token = getChunkedCookie(event, sessionName);
  }

  return token;
}

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

  if (typeof update === "function") {
    update = update(session.data);
  }

  const oldSession = { ...session, data: { ...session.data } };

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
        : createdAt + computeExpiresInSeconds(config.maxAge) * 1000,
  });

  let token: string;
  try {
    token = await signJWSSession(event, config);
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
  session.token = token;

  if (config.cookie !== false && canWriteCookie) {
    setChunkedCookie(event, sessionName, token, {
      ...DEFAULT_COOKIE,
      expires:
        config.maxAge === undefined
          ? undefined
          : new Date(session.createdAt + computeExpiresInSeconds(config.maxAge) * 1000),
      ...config.cookie,
    });
  }

  // Fire after signing so the hook receives the definitive new token, jti, and timestamps.
  // Also fires when update is undefined (pure token refresh with no payload change).
  await config.hooks?.onUpdate?.({
    session,
    oldSession,
    event,
    config,
  });

  return session;
}

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
    expiresIn: undefined, // controlled via 'exp' claim
    protectedHeader: {
      ...config.jws?.signOptions?.protectedHeader,
      kid: "kid" in key ? key.kid : undefined,
      typ: typ || "JWT",
      cty: "application/json",
    },
  });

  return token;
}

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
    ? (header: JWSProtectedHeader) =>
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
    validateJWT: true,
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

  // If session exists in context store for hook and delete it
  let session = context.sessions?.[sessionName] as SessionJWS<T, MaxAge> | undefined;
  if (session && session[kGetSessionPromise]) {
    session = await session[kGetSessionPromise];
  }
  const oldSession = session ? { ...session, data: { ...session.data } } : undefined;

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

function getSignKey(key: SessionConfigJWS["key"] | undefined): JWK_Symmetric | JWK_Private {
  if (!key) {
    throw new Error("Session: JWS key is required.");
  }

  let _key: JWK_Symmetric | JWK_Private | undefined;
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

function getVerifyKey(
  key: SessionConfigJWS["key"] | undefined,
): JWK_Symmetric | JWK_Public | JWKSet {
  if (!key) {
    throw new Error("Session: JWS key is required.");
  }

  let _key: JWK_Symmetric | JWK_Public | JWKSet | undefined;
  if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("publicKey" in key) {
    const publicKey = key.publicKey;
    if (isPublicJWK(publicKey)) {
      _key = publicKey;
    } else if (Array.isArray(publicKey)) {
      const keys = publicKey.filter((candidate): candidate is JWK_Public => isPublicJWK(candidate));
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
