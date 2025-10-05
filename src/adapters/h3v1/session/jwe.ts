/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { CookieSerializeOptions } from "cookie-esv1";
import { type H3Event, isEvent, setCookie } from "h3v1";
import { parse as parseCookies } from "cookie-esv1";
import {
  type JWK,
  type JWK_oct,
  type JWK_Symmetric,
  type JWK_Public,
  type JWK_Private,
  type JWTClaims,
  type JWEEncryptOptions,
  type JWTClaimValidationOptions,
  encrypt,
  decrypt,
} from "../../../core/jwe";
import { isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../../../core/utils";

type SessionDataT = Omit<JWTClaims, "jti" | "iat" | "exp">;
export type SessionData<T extends SessionDataT = SessionDataT> = T;

const kGetSessionPromise = Symbol("h3_jwe_getSession");

export interface SessionJWE<T extends SessionDataT = SessionDataT> {
  // Mapped from payload.jti
  id: string;
  // Mapped from payload.iat (in ms)
  createdAt: number;
  // Mapped from payload.exp (in ms)
  expiresAt?: number;
  data: SessionData<T>;
  [kGetSessionPromise]?: Promise<SessionJWE<T>>;
}

export interface SessionHooksJWE {
  onRead?: (
    session: SessionJWE,
    event: H3Event,
    config: SessionConfigJWE,
  ) => void | Promise<void>;
  onUpdate?: (
    session: SessionJWE,
    event: H3Event,
    config: SessionConfigJWE,
  ) => void | Promise<void>;
  onClear?: (
    event: H3Event,
    config: Partial<SessionConfigJWE>,
  ) => void | Promise<void>;
  onExpire?: (
    event: H3Event,
    error: any | undefined,
    config: SessionConfigJWE,
  ) => void | Promise<void>;
  onError?: (
    event: H3Event,
    error: any,
    config: SessionConfigJWE,
  ) => void | Promise<void>;
}

export interface SessionManager<T extends SessionDataT = SessionDataT> {
  readonly id: string | undefined;
  readonly createdAt: number;
  readonly expiresAt: number | undefined;
  readonly data: SessionData<T>;
  update: (update: SessionUpdate<T>) => Promise<SessionManager<T>>;
  clear: () => Promise<SessionManager<T>>;
}

export interface SessionConfigJWE {
  /** @deprecated use `key` instead */
  secret?:
    | string
    | JWK_Symmetric
    | {
        privateKey: JWK_Private | JWK_Symmetric;
        publicKey?: JWK_Public;
      };
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
  maxAge?: number;
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
  hooks?: SessionHooksJWE;
}

/**
 * @deprecated use `SessionConfigJWE` instead
 */
export type SessionJWEConfig = SessionConfigJWE;

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

type SessionUpdate<T extends SessionDataT = SessionDataT> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

/**
 * Create a session manager for the current request.
 */
export async function useJWESession<T extends SessionDataT = SessionDataT>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWE,
): Promise<SessionManager<T>> {
  const sessionName = config.name || DEFAULT_NAME;
  await getJWESession<T>(event, config); // Ensure initialization/loading

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
      await updateJWESession<T>(event as H3Event, config, update);
      return sessionManager;
    },
    clear: () => {
      if (!isEvent(event)) {
        throw new Error("[h3] Cannot clear read-only session.");
      }
      clearJWESession(event as H3Event, config);
      return Promise.resolve(sessionManager);
    },
  };

  return sessionManager;
}

/**
 * Get (and lazily initialize) the session for the current request.
 */
export async function getJWESession<T extends SessionDataT = SessionDataT>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWE,
): Promise<SessionJWE<T>> {
  const sessionName = config.name || DEFAULT_NAME;

  if (!event.context.sessions) {
    event.context.sessions = Object.create(null);
  }

  const existingSession = event.context.sessions![sessionName] as SessionJWE<T>;
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
      await config.hooks?.onExpire?.(event as H3Event, undefined, config);
      return clearJWESession(event as H3Event, config).then(() =>
        getJWESession<T>(event, config),
      );
    }

    await config.hooks?.onRead?.(session, event as H3Event, config);
    return session;
  }

  // Placeholder session object
  const session: SessionJWE<T> = {
    id: "",
    createdAt: 0,
    expiresAt: undefined,
    data: Object.create(null),
  };
  event.context.sessions![sessionName] = session;

  // Attempt to read existing token from headers/cookies
  let jweToken: string | undefined;

  if (config.sessionHeader !== false) {
    const headerName =
      typeof config.sessionHeader === "string"
        ? config.sessionHeader.toLowerCase()
        : `x-${sessionName.toLowerCase()}-session`;
    const headerValue = _getReqHeader(event, headerName);
    if (typeof headerValue === "string") {
      jweToken = headerValue;
    }
  }

  if (!jweToken) {
    const cookieHeader = _getReqHeader(event, "cookie");
    if (cookieHeader) {
      jweToken = parseCookies(String(cookieHeader))[sessionName];
    }
  }

  if (jweToken) {
    const promise = unsealJWESession(event, config, jweToken)
      .catch(async (error_) => {
        // Silently ignore invalid/expired tokens -> new session will be created
        // Check if error_ is about expiration
        if (
          error_ instanceof Error &&
          (error_.message.includes("Token has expired") ||
            error_.message.includes("Token is too old"))
        ) {
          await config.hooks?.onExpire?.(event as H3Event, error_, config);
          return undefined;
        }
        await config.hooks?.onError?.(event as H3Event, error_, config);
        return undefined;
      })
      .then((unsealed) => {
        if (unsealed) {
          Object.assign(session, unsealed);
        }
        delete event.context.sessions![sessionName][kGetSessionPromise];
        return session as SessionJWE<T>;
      });
    event.context.sessions![sessionName][kGetSessionPromise] = promise;
    await promise;
  }

  // If no valid session loaded, create a new one
  if (!session.id) {
    if (!isEvent(event)) {
      throw new Error(
        "Cannot initialize a new session. Use `useSession(event)` within the main handler.",
      );
    }
    session.id = config.generateId?.() ?? crypto.randomUUID();
    session.createdAt =
      config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
    session.expiresAt = config.maxAge
      ? session.createdAt + config.maxAge * 1000
      : undefined;
    await updateJWESession<T>(event as H3Event, config);
  }

  await config.hooks?.onRead?.(session, event as H3Event, config);
  return session;
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

/**
 * Update the session (optionally mutating the session data) and re-issue the JWE token.
 */
export async function updateJWESession<T extends SessionDataT = SessionDataT>(
  event: H3Event,
  config: SessionConfigJWE,
  update?: SessionUpdate<T>,
): Promise<SessionJWE<T>> {
  const sessionName = config.name || DEFAULT_NAME;

  const session: SessionJWE<T> =
    (event.context.sessions?.[sessionName] as SessionJWE<T>) ||
    (await getJWESession<T>(event, config));

  if (typeof update === "function") {
    update = update(session.data);
  }
  if (update) {
    Object.assign(session.data, update);
    await config.hooks?.onUpdate?.(session, event, config);
  }

  if (config.cookie !== false) {
    const sealed = await sealJWESession<T>(event, config);
    setCookie(event, sessionName, sealed, {
      ...DEFAULT_COOKIE,
      ...config.cookie,
      expires: config.maxAge
        ? new Date(
            // createdAt is ms, maxAge is seconds
            session.createdAt + config.maxAge * 1000,
          )
        : undefined,
    });
  }

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
export async function sealJWESession<T extends SessionDataT = SessionDataT>(
  event: H3Event | CompatEvent,
  config: SessionConfigJWE,
): Promise<string> {
  const key = getEncryptKey(config.key || config.secret);

  const sessionName = config.name || DEFAULT_NAME;

  const session: SessionJWE<T> =
    (event.context.sessions?.[sessionName] as SessionJWE<T>) ||
    (await getJWESession<T>(event, config));

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
    expiresIn: undefined, // controlled via 'exp' claim
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
export async function unsealJWESession(
  _event: H3Event | CompatEvent,
  config: SessionConfigJWE,
  sealed: string,
): Promise<Partial<SessionJWE>> {
  const key = getDecryptKey(config.key || config.secret);

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
  const { payload } = await decrypt<
    JWTClaims & { jti: string; iat: number; exp?: number }
  >(sealed, key, {
    ...config.jwe?.decryptOptions,
    requiredClaims: [
      ...(config.jwe?.decryptOptions?.requiredClaims?.filter(
        (claim) => claim !== "jti" && claim !== "iat",
      ) || []),
      "jti",
      "iat",
    ],
    typ: typ || "JWT",
    maxTokenAge: config.maxAge,
    algorithms: alg ? [alg] : undefined,
    encryptionAlgorithms: enc ? [enc] : undefined,
    unwrappedKeyAlgorithm: undefined,
    keyUsage: undefined,
    forceUint8Array: false,
    validateJWT: true,
  }).catch((error_) => {
    if (error_ instanceof Error) {
      const message = error_.message;
      throw new Error(`Invalid session token: ${message}`);
    }
    throw new Error(error_);
  });

  const { jti, iat, exp, ...data } = payload;

  return {
    id: jti,
    createdAt: iat * 1000, // Convert back to ms
    expiresAt: exp ? exp * 1000 : undefined,
    data: (data && typeof data === "object"
      ? data
      : Object.create(null)) as any,
  };
}

/**
 * Clear the session (delete from context and drop cookie).
 */
export async function clearJWESession(
  event: H3Event,
  config: Partial<SessionConfigJWE>,
): Promise<void> {
  const sessionName = config.name || DEFAULT_NAME;
  if (event.context.sessions?.[sessionName]) {
    delete event.context.sessions![sessionName];
  }

  setCookie(event, sessionName, "", {
    ...DEFAULT_COOKIE,
    ...config.cookie,
    expires: new Date(0),
    maxAge: undefined,
  });

  await config.hooks?.onClear?.(event, config);
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
    throw new Error(
      "Session: Invalid JWE key. It must be a password string or valid JWK.",
      { cause: key },
    );
  }

  return _key;
}
function getDecryptKey(
  key: SessionConfigJWE["key"] | undefined,
): string | JWK_oct | JWK_Private {
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
