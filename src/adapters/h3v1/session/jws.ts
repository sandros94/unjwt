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
  JWKSet,
  JWK_Public,
  JWK_Private,
  JWK_Symmetric,
  JWSSignOptions,
  JWSProtectedHeader,
  JWTClaimValidationOptions,
} from "../../../core/types";
import { sign, verify } from "../../../core/jws";
import {
  isSymmetricJWK,
  isPrivateJWK,
  isPublicJWK,
  computeExpiresInSeconds,
} from "../../../core/utils";
import type {
  SessionClaims,
  SessionData,
  SessionUpdate,
  SessionManager,
} from "./types";

const kGetSessionPromise = Symbol("h3_jws_getSession");

export interface SessionJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  // Mapped from payload.jti
  id: string;
  // Mapped from payload.iat (in ms)
  createdAt: number;
  // Mapped from payload.exp (in ms)
  expiresAt: MaxAge extends ExpiresIn ? number : T["exp"];
  data: SessionData<T>;
  [kGetSessionPromise]?: Promise<SessionJWS<T, MaxAge>>;
}

export interface SessionHooksJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  onRead?: (args: {
    session: SessionJWS<T, MaxAge>;
    event: H3Event;
    config: SessionConfigJWS<T, MaxAge>;
  }) => void | Promise<void>;
  onUpdate?: (args: {
    session: SessionJWS<T, MaxAge>;
    oldSession: SessionJWS<T, MaxAge>;
    event: H3Event;
    config: SessionConfigJWS<T, MaxAge>;
  }) => void | Promise<void>;
  onClear?: (args: {
    session: SessionJWS<T, MaxAge> | undefined;
    event: H3Event;
    config: Partial<SessionConfigJWS<T, MaxAge>>;
  }) => void | Promise<void>;
  onExpire?: (args: {
    event: H3Event;
    error: Error;
    config: SessionConfigJWS<T, MaxAge>;
  }) => void | Promise<void>;
  onError?: (args: {
    event: H3Event;
    error: any;
    config: SessionConfigJWS<T, MaxAge>;
  }) => void | Promise<void>;
  onVerifyKeyLookup?: (args: {
    header: JWSProtectedHeader;
    event: H3Event;
    config: SessionConfigJWS<T, MaxAge>;
  }) =>
    | JWKSet
    | JWK_Symmetric
    | JWK_Public
    | Promise<JWKSet | JWK_Symmetric | JWK_Public>;
}

export interface SessionConfigJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  /**
   * JWK (private for signing with RS/ES/PS, or symmetric oct) used for signing.
   */
  key:
    | JWK_Symmetric
    | {
        privateKey: JWK_Private;
        publicKey: JWK_Public | JWK_Public[] | JWKSet;
      };
  /** Session lifetime in seconds (sets exp = iat + maxAge) */
  maxAge?: MaxAge;
  /** Default cookie / header name base */
  name?: string;
  /** Cookie options (false to disable cookies) */
  cookie?: false | CookieSerializeOptions;
  /** Custom header (false to disable header lookup) */
  sessionHeader?: false | string;
  /** Custom ID generator (defaults to crypto.randomUUID) */
  generateId?: () => string;
  /** JWS customization */
  jws?: {
    signOptions?: Omit<JWSSignOptions, "expiresIn">;
    verifyOptions?: JWTClaimValidationOptions;
  };
  hooks?: SessionHooksJWS<T, MaxAge>;
}

/**
 * @deprecated use `SessionConfigJWS` instead
 */
export type SessionJWSConfig = SessionConfigJWS;

const DEFAULT_NAME = "h3-jws";
const DEFAULT_COOKIE: SessionConfigJWS["cookie"] = {
  path: "/",
  secure: true,
  httpOnly: false,
};

// Compatible type with h3 v2 and external usage
type CompatEvent =
  | { request: { headers: Headers }; context: any }
  | { headers: Headers; context: any };

/**
 * Create a session manager for the current request using JWS (signed only, not encrypted).
 * NOTE: Contents are visible to clients (Base64URL-decoded JSON). Do not store secrets in session data.
 */
export async function useJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWS<T, MaxAge>,
): Promise<SessionManager<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  await getJWSSession<T, MaxAge>(event, config);

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
      return getJWSSessionToken<T, MaxAge>(event, config);
    },
    update: async (update: SessionUpdate<T>) => {
      if (!isEvent(event)) {
        throw new Error("[h3] Cannot update read-only session.");
      }
      await updateJWSSession<T, MaxAge>(event as H3Event, config, update);
      return sessionManager;
    },
    clear: () => {
      if (!isEvent(event)) {
        throw new Error("[h3] Cannot clear read-only session.");
      }
      clearJWSSession<T, MaxAge>(event as H3Event, config);
      return Promise.resolve(sessionManager);
    },
  };
  return sessionManager;
}

/**
 * Retrieve (and lazily initialize) the session.
 */
export async function getJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWS<T, MaxAge>,
): Promise<SessionJWS<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;

  if (!event.context.sessions) {
    event.context.sessions = Object.create(null);
  }

  const existingSession = event.context.sessions[sessionName] as SessionJWS<
    T,
    MaxAge
  >;
  if (existingSession) {
    const session = existingSession[kGetSessionPromise]
      ? await existingSession[kGetSessionPromise]
      : existingSession;

    /**
     * We check if a session is expired before returning it. If it is expired we clear it and create a new one,
     * unless we have a read-only event in which case we just return it as it was valid at the time of reading
     * the cookie/header (like in a websocket upgrade)
     */
    if (
      session.expiresAt !== undefined &&
      session.expiresAt < Date.now() &&
      isEvent(event)
    ) {
      await config.hooks?.onExpire?.({
        event,
        error: new Error(
          `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(session.expiresAt * 1000).toISOString()})`,
        ),
        config,
      });
      return clearJWSSession<T, MaxAge>(event as H3Event, config).then(() =>
        getJWSSession<T, MaxAge>(event, config),
      );
    }

    await config.hooks?.onRead?.({
      event: event as H3Event,
      session,
      config,
    });
    return session;
  }

  const session: SessionJWS<T, MaxAge> = {
    id: "",
    createdAt: 0,
    expiresAt: undefined as MaxAge extends ExpiresIn ? number : T["exp"],
    data: Object.create(null),
  };
  event.context.sessions[sessionName] = session;

  const token = getJWSSessionToken<T, MaxAge>(event, config);

  if (token) {
    const promise = verifyJWSSession<T, MaxAge>(event, config, token)
      .catch(async (error_) => {
        // Silently ignore invalid/expired tokens -> new session will be created
        // Check if error_ is about expiration
        if (
          error_ instanceof Error &&
          (error_.message.includes("Token has expired") ||
            error_.message.includes("Token is too old"))
        ) {
          await config.hooks?.onExpire?.({
            event: event as H3Event,
            error: error_,
            config,
          });
          return undefined;
        }
        await config.hooks?.onError?.({
          event: event as H3Event,
          error: error_,
          config,
        });
        return undefined;
      })
      .then((unsealed) => {
        if (unsealed) {
          Object.assign(session, unsealed);
        }
        delete event.context.sessions[sessionName][kGetSessionPromise];
        return session;
      });
    session[kGetSessionPromise] = promise;
    await promise;
  }

  // Initialize new session if none
  if (!session.id) {
    if (!isEvent(event)) {
      throw new Error(
        "Cannot initialize a new session outside main handler. Use `useJWSSession(event)` properly.",
      );
    }
    session.id = config.generateId?.() ?? crypto.randomUUID();
    session.createdAt =
      config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
    (session.expiresAt as any) =
      config.maxAge === undefined
        ? undefined
        : session.createdAt + computeExpiresInSeconds(config.maxAge) * 1000;
    await updateJWSSession<T, MaxAge>(event as H3Event, config);
  }

  await config.hooks?.onRead?.({
    event: event as H3Event,
    session,
    config,
  });
  return session;
}

function getJWSSessionToken<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWS<T, MaxAge>,
): string | undefined {
  const sessionName = config.name || DEFAULT_NAME;
  let token: string | undefined;

  if (config.sessionHeader !== false) {
    const headerName =
      typeof config.sessionHeader === "string"
        ? config.sessionHeader.toLowerCase()
        : `x-${sessionName.toLowerCase()}-session`;
    const headerValue = _getReqHeader(event, headerName);
    if (typeof headerValue === "string") {
      token = headerValue.startsWith("Bearer ")
        ? headerValue.slice(7).trim()
        : headerValue;
    }
  }

  // Check Set-Cookie (eg. in case of redirects)
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

  // Fallback to cookie if not found earlier
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
    return (event as H3Event).node!.req.headers[name];
  }
  if ((event as { request?: Request }).request) {
    return (event as { request?: Request }).request!.headers.get(name);
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
 * Update session data (if provided) and reissue JWS.
 */
export async function updateJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(
  event: H3Event,
  config: SessionConfigJWS<T, MaxAge>,
  update?: SessionUpdate<T>,
): Promise<SessionJWS<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;

  const session: SessionJWS<T, MaxAge> =
    (event.context.sessions?.[sessionName] as SessionJWS<T, MaxAge>) ||
    (await getJWSSession<T, MaxAge>(event, config));

  if (typeof update === "function") {
    update = update(session.data);
  }
  if (update) {
    const oldSession = { ...session, data: { ...session.data } };

    Object.assign(session.data, update);

    await config.hooks?.onUpdate?.({
      session,
      oldSession,
      event,
      config,
    });
  }

  if (config.cookie !== false) {
    const token = await signJWSSession<T, MaxAge>(event, config);
    setCookie(event, sessionName, token, {
      ...DEFAULT_COOKIE,
      ...config.cookie,
      expires:
        config.maxAge === undefined
          ? undefined
          : new Date(
              session.createdAt + computeExpiresInSeconds(config.maxAge) * 1000,
            ),
    });
  }

  return session;
}

/**
 * Sign current session as a compact JWS.
 * Payload claims:
 *  jti, iat, exp?, data, plus optional extraClaims (cannot override reserved)
 */
export async function signJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWS<T, MaxAge>,
): Promise<string> {
  const key = getSignKey(config.key);

  const sessionName = config.name || DEFAULT_NAME;

  const session: SessionJWS<T, MaxAge> =
    (event.context.sessions?.[sessionName] as SessionJWS<T, MaxAge>) ||
    (await getJWSSession<T, MaxAge>(event, config));

  const iatSeconds = Math.floor(session.createdAt / 1000);
  const expSeconds =
    config.maxAge === undefined
      ? undefined
      : iatSeconds + computeExpiresInSeconds(config.maxAge);

  const payload: Record<string, any> = {
    ...session.data,
    jti: session.id,
    iat: iatSeconds,
  };
  if (expSeconds) {
    payload.exp = expSeconds;
  }

  let typ: string | undefined = undefined;
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
      kid: key.kid,
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
 *  - (optional) standard claim checks if validateJWT true
 *  - ensures jti & iat presence
 *  - enforces maxAge if provided
 */
export async function verifyJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWS<T, MaxAge>,
  token: string,
): Promise<Partial<SessionJWS<T, MaxAge>>> {
  const alg = config.jws?.signOptions?.alg;
  const jwk = config.hooks?.onVerifyKeyLookup
    ? (header: JWSProtectedHeader) =>
        config.hooks!.onVerifyKeyLookup!({
          header,
          event: event as H3Event,
          config,
        })
    : getVerifyKey(config.key);

  let typ: string | undefined = undefined;
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
      ...new Set([
        ...(config.jws?.verifyOptions?.requiredClaims || []),
        "jti",
        "iat",
      ]),
    ],
    typ: typ || "JWT",
    algorithms: alg ? [alg] : undefined,
    forceUint8Array: false,
    validateJWT: true,
  }).catch((error_: unknown) => {
    const message = error_ instanceof Error ? error_.message : String(error_);
    throw new Error(`Invalid session token: ${message}`);
  });

  const { jti, iat, exp, ...data } = payload;

  return {
    id: jti,
    createdAt: iat * 1000, // Convert back to ms
    expiresAt: (exp ? exp * 1000 : undefined) as MaxAge extends ExpiresIn
      ? number
      : T["exp"],
    data: (data && typeof data === "object"
      ? data
      : Object.create(null)) as any,
  };
}

/**
 * Destroy the session (context + cookie).
 */
export async function clearJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
>(event: H3Event, config: Partial<SessionConfigJWS<T, MaxAge>>): Promise<void> {
  const sessionName = config.name || DEFAULT_NAME;

  // If session exists in context store for hook and delete it
  let session = event.context.sessions?.[sessionName] as
    | SessionJWS<T, MaxAge>
    | undefined;
  if (session && session[kGetSessionPromise]) {
    session = await session[kGetSessionPromise];
  }

  if (event.context.sessions?.[sessionName]) {
    delete event.context.sessions[sessionName];
  }

  setCookie(event, sessionName, "", {
    ...DEFAULT_COOKIE,
    ...config.cookie,
    expires: new Date(0),
    maxAge: undefined,
  });

  await config.hooks?.onClear?.({
    session,
    event,
    config,
  });
}

function getSignKey(
  key: SessionConfigJWS["key"] | undefined,
): JWK_Symmetric | JWK_Private {
  if (!key) {
    throw new Error("Session: JWS key is required.");
  }

  let _key: JWK_Symmetric | JWK_Private | undefined = undefined;
  if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("privateKey" in key && isPrivateJWK(key.privateKey)) {
    _key = key.privateKey;
  }

  if (!_key) {
    throw new Error(
      "Session: Invalid JWS key. It must be a symmetric JWK or a private JWK.",
      { cause: key },
    );
  }

  return _key;
}
function getVerifyKey(
  key: SessionConfigJWS["key"] | undefined,
): JWK_Symmetric | JWK_Public | JWKSet {
  if (!key) {
    throw new Error("Session: JWS key is required.");
  }

  let _key: JWK_Symmetric | JWK_Public | JWKSet | undefined = undefined;
  if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("publicKey" in key && isPublicJWK(key.publicKey)) {
    _key = key.publicKey;
  } else if ("publicKey" in key && Array.isArray(key.publicKey)) {
    const keys = key.publicKey.filter((k) => isPublicJWK(k));

    if (keys && keys.length > 0) {
      _key = { keys };
    }
  }

  if (!_key) {
    throw new Error(
      "Session: Invalid JWS key. It must be a symmetric JWK or a public JWK/set.",
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
