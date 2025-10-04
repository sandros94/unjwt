/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/test/session.test.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { CookieSerializeOptions } from "cookie-es";
import { type H3Event, isEvent, setCookie } from "h3";
import { parse as parseCookies } from "cookie-es";
import {
  type JWK_Symmetric,
  type JWK_Public,
  type JWK_Private,
  type JWKSet,
  type JWTClaims,
  type JWSSignOptions,
  type JWTClaimValidationOptions,
  sign,
  verify,
} from "../../../core/jws";
import { isAsymmetricJWK, isPrivateJWK } from "../../../core/utils";
import type { SessionData, SessionManager } from "./jwe";

type SessionDataT = Omit<JWTClaims, "jti" | "iat" | "exp">;

const kGetSessionPromise = Symbol("h3_jws_getSession");

export interface SessionJWS<T extends SessionDataT = SessionDataT> {
  // Mapped from payload.jti
  id: string;
  // Mapped from payload.iat (in ms)
  createdAt: number;
  // Mapped from payload.exp (in ms)
  expiresAt?: number;
  data: SessionData<T>;
  [kGetSessionPromise]?: Promise<SessionJWS<T>>;
}

export interface SessionConfigJWS {
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
  maxAge?: number;
  /** Default cookie / header name base */
  name?: string;
  /** Cookie options (false to disable cookies) */
  cookie?: false | CookieSerializeOptions;
  /** Custom header (false to disable header lookup) */
  sessionHeader?: false | string;
  /** Provide a custom WebCrypto (if needed for algorithm operations) */
  crypto?: Crypto;
  /** Custom ID generator (defaults to crypto.randomUUID) */
  generateId?: () => string;
  /** JWS customization */
  jws?: {
    signOptions?: Omit<JWSSignOptions, "expiresIn">;
    verifyOptions?: JWTClaimValidationOptions;
  };
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

type SessionUpdate<T extends SessionDataT = SessionDataT> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

/**
 * Create a session manager for the current request using JWS (signed only, not encrypted).
 * NOTE: Contents are visible to clients (Base64URL-decoded JSON). Do not store secrets in session data.
 */
export async function useJWSSession<T extends SessionDataT = SessionDataT>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWS,
): Promise<SessionManager<T>> {
  const sessionName = config.name || DEFAULT_NAME;
  await getJWSSession<T>(event, config);

  const sessionManager: SessionManager<T> = {
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
    update: async (update: SessionUpdate<T>) => {
      if (!isEvent(event)) {
        throw new Error("[h3] Cannot update read-only session.");
      }
      await updateJWSSession<T>(event as H3Event, config, update);
      return sessionManager;
    },
    clear: () => {
      if (!isEvent(event)) {
        throw new Error("[h3] Cannot clear read-only session.");
      }
      clearJWSSession(event as H3Event, config);
      return Promise.resolve(sessionManager);
    },
  };
  return sessionManager;
}

/**
 * Retrieve (and lazily initialize) the session.
 */
export async function getJWSSession<T extends SessionDataT = SessionDataT>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWS,
): Promise<SessionJWS<T>> {
  const sessionName = config.name || DEFAULT_NAME;

  if (!event.context.sessions) {
    event.context.sessions = Object.create(null);
  }

  const existingSession = event.context.sessions[sessionName] as SessionJWS<T>;
  if (existingSession) {
    /**
     * We check if a session is expired before returning it. If it is expired we clear it and create a new one,
     * unless we have a read-only event in which case we just return it as it was valid at the time of reading
     * the cookie/header (like in a websocket upgrade)
     */
    return existingSession.expiresAt === undefined
      ? existingSession[kGetSessionPromise] || existingSession
      : existingSession.expiresAt < Date.now() && isEvent(event)
        ? clearJWSSession(event, config).then(() =>
            getJWSSession<T>(event, config),
          )
        : existingSession[kGetSessionPromise] || existingSession;
  }

  const session: SessionJWS<T> = {
    id: "",
    createdAt: 0,
    expiresAt: undefined,
    data: Object.create(null),
  };
  event.context.sessions[sessionName] = session;

  let token: string | undefined;

  if (config.sessionHeader !== false) {
    const headerName =
      typeof config.sessionHeader === "string"
        ? config.sessionHeader.toLowerCase()
        : `x-${sessionName.toLowerCase()}-session`;
    const headerValue = _getReqHeader(event, headerName);
    if (typeof headerValue === "string") {
      token = headerValue;
    }
  }

  if (!token) {
    const cookieHeader = _getReqHeader(event, "cookie");
    if (cookieHeader) {
      token = parseCookies(String(cookieHeader))[sessionName];
    }
  }

  if (token) {
    const promise = verifyJWSSession(event, config, token)
      .catch(() => {
        // ignore -> new session
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
    session.id =
      config.generateId?.() ??
      (config.crypto || globalThis.crypto).randomUUID();
    session.createdAt =
      config.jws?.signOptions?.currentDate === undefined
        ? Date.now()
        : config.jws.signOptions.currentDate.getTime();
    session.expiresAt = config.maxAge
      ? session.createdAt + config.maxAge * 1000
      : undefined;
    session.data = Object.create(null);
    await updateJWSSession<T>(event as H3Event, config);
  }

  return session;
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

/**
 * Update session data (if provided) and reissue JWS.
 */
export async function updateJWSSession<T extends SessionDataT = SessionDataT>(
  event: H3Event,
  config: SessionConfigJWS,
  update?: SessionUpdate<T>,
): Promise<SessionJWS<T>> {
  const sessionName = config.name || DEFAULT_NAME;

  const session: SessionJWS<T> =
    (event.context.sessions?.[sessionName] as SessionJWS<T>) ||
    (await getJWSSession<T>(event, config));

  if (typeof update === "function") {
    update = update(session.data);
  }
  if (update) {
    Object.assign(session.data, update);
  }

  if (config.cookie !== false) {
    const token = await signJWSSession<T>(event, config);
    setCookie(event, sessionName, token, {
      ...DEFAULT_COOKIE,
      ...config.cookie,
      expires: config.maxAge
        ? new Date(session.createdAt + config.maxAge * 1000)
        : undefined,
    });
  }

  return session;
}

/**
 * Sign current session as a compact JWS.
 * Payload claims:
 *  jti, iat, exp?, data, plus optional extraClaims (cannot override reserved)
 */
export async function signJWSSession<T extends SessionDataT = SessionDataT>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWS,
): Promise<string> {
  const key = getSignKey(config.key);
  if (isAsymmetricJWK(key) && !isPrivateJWK(key)) {
    throw new Error("Session: JWS key cannot be a public asymmetric JWK.");
  }

  const sessionName = config.name || DEFAULT_NAME;

  const session: SessionJWS<T> =
    (event.context.sessions?.[sessionName] as SessionJWS<T>) ||
    (await getJWSSession<T>(event, config));

  const iatSeconds = Math.floor(session.createdAt / 1000);
  const expSeconds =
    config.maxAge == null ? undefined : iatSeconds + config.maxAge;

  const payload: Record<string, any> = {
    ...session.data,
    jti: session.id,
    iat: iatSeconds,
  };
  if (expSeconds) {
    payload.exp = expSeconds;
  }

  const token = await sign(payload, key, {
    ...config.jws?.signOptions,
    protectedHeader: {
      ...config.jws?.signOptions?.protectedHeader,
      typ: "JWT",
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
export async function verifyJWSSession(
  _event: H3Event | CompatEvent,
  config: SessionConfigJWS,
  token: string,
): Promise<Partial<SessionJWS>> {
  const alg = config.jws?.signOptions?.alg;
  const jwk = getVerifyKey(config.key);
  if (isAsymmetricJWK(jwk) && isPrivateJWK(jwk)) {
    throw new Error("Session: JWS key cannot be a private asymmetric JWK.");
  }

  const { payload } = await verify<
    JWTClaims & { jti: string; iat: number; exp?: number }
  >(token, jwk, {
    ...config.jws?.verifyOptions,
    requiredClaims: [
      ...(config.jws?.verifyOptions?.requiredClaims?.filter(
        (claim) => claim !== "jti" && claim !== "iat",
      ) || []),
      "jti",
      "iat",
    ],
    typ: "JWT",
    algorithms: alg ? [alg] : undefined,
    forceUint8Array: false,
    validateJWT: true,
  }).catch((error_: unknown) => {
    const message = error_ instanceof Error ? error_.message : String(error_);
    throw new Error(`Invalid session token: ${message}`);
  });

  const { jti, iat, ...data } = payload;

  return {
    id: jti,
    createdAt: iat * 1000, // Convert back to ms
    expiresAt: payload.exp ? payload.exp * 1000 : undefined,
    data: (data && typeof data === "object"
      ? data
      : Object.create(null)) as any,
  };
}

/**
 * Destroy the session (context + cookie).
 */
export function clearJWSSession(
  event: H3Event,
  config: Partial<SessionConfigJWS>,
): Promise<void> {
  const sessionName = config.name || DEFAULT_NAME;
  if (event.context.sessions?.[sessionName]) {
    delete event.context.sessions[sessionName];
  }
  setCookie(event, sessionName, "", {
    ...DEFAULT_COOKIE,
    ...config.cookie,
    expires: new Date(0),
  });
  return Promise.resolve();
}

function getSignKey(key: SessionConfigJWS["key"]) {
  if ("privateKey" in key) {
    return key.privateKey;
  }
  return key;
}
function getVerifyKey(key: SessionConfigJWS["key"]) {
  if ("publicKey" in key) {
    return Array.isArray(key.publicKey)
      ? { keys: key.publicKey }
      : key.publicKey;
  }
  return key;
}
