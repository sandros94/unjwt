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
  JWK,
  JWK_oct,
  JWK_Symmetric,
  JWK_Public,
  JWK_Private,
  JWTClaims,
  JWEEncryptOptions,
  JWTClaimValidationOptions,
} from "../../../core/types";
import { encrypt, decrypt } from "../../../core/jwe";
import { isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../../../core/utils";
import type { SessionData, SessionUpdate, SessionManager } from "./types";

const kGetSessionPromise = Symbol("h3_jwe_getSession");

export interface SessionJWE<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
> {
  // Mapped from payload.jti
  id: string;
  // Mapped from payload.iat (in ms)
  createdAt: number;
  // Mapped from payload.exp (in ms)
  expiresAt: MaxAge extends number ? number : T['exp'];
  data: SessionData<T>;
  [kGetSessionPromise]?: Promise<SessionJWE<T, MaxAge>>;
}

export interface SessionHooksJWE<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
> {
  onRead?: (args: {
    session: SessionJWE<T, MaxAge>;
    event: HTTPEvent;
    config: SessionConfigJWE<T, MaxAge>;
  }) => void | Promise<void>;
  onUpdate?: (args: {
    session: SessionJWE<T, MaxAge>;
    event: HTTPEvent;
    config: SessionConfigJWE<T, MaxAge>;
  }) => void | Promise<void>;
  onClear?: (args: {
    event: HTTPEvent;
    config: Partial<SessionConfigJWE<T, MaxAge>>;
  }) => void | Promise<void>;
  onExpire?: (args: {
    event: HTTPEvent;
    error: Error;
    config: SessionConfigJWE<T, MaxAge>;
  }) => void | Promise<void>;
  onError?: (args: {
    event: HTTPEvent;
    error: any;
    config: SessionConfigJWE<T, MaxAge>;
  }) => void | Promise<void>;
}

export interface SessionConfigJWE<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
> {
  /** Shared secret used, string for PBES2 or Json Web Key (JWK) */
  key:
    | string
    | JWK_Symmetric
    | {
        privateKey: JWK_Private | JWK_Symmetric;
        publicKey?: JWK_Public;
      };
  /** Session lifetime in seconds (used to derive exp from iat) */
  maxAge?: MaxAge;
  /** Default is "h3" */
  name?: string;
  /** Default is secure, httpOnly, path="/" */
  cookie?: false | (CookieSerializeOptions & { chunkMaxLength?: number });
  /** Default is x-h3-session / x-{name}-session */
  sessionHeader?: false | string;
  /** Default is crypto.randomUUID */
  generateId?: () => string;
  /** JWE configuration overrides */
  jwe?: {
    encryptOptions?: Omit<JWEEncryptOptions, "expiresIn">;
    decryptOptions?: JWTClaimValidationOptions;
  };
  hooks?: SessionHooksJWE<T, MaxAge>;
}

const DEFAULT_NAME = "h3-jwe";
const DEFAULT_COOKIE: SessionConfigJWE["cookie"] = {
  path: "/",
  secure: true,
  httpOnly: true,
};

/**
 * Create a session manager for the current request.
 */
export async function useJWESession<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
>(
  event: HTTPEvent,
  config: SessionConfigJWE<T, MaxAge>,
): Promise<SessionManager<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  await getJWESession<T, MaxAge>(event, config);

  const sessionManager: SessionManager<T, MaxAge> = {
    get id() {
      return getSessionFromContext(event, sessionName)?.id;
    },
    get createdAt() {
      return getSessionFromContext(event, sessionName)?.createdAt ?? Date.now();
    },
    get expiresAt() {
      return getSessionFromContext(event, sessionName)?.expiresAt as T extends {
        exp: number;
      }
        ? number
        : MaxAge;
    },
    get data() {
      return (getSessionFromContext(event, sessionName)?.data || {}) as T;
    },
    update: async (update: SessionUpdate<T>) => {
      await updateJWESession<T, MaxAge>(event, config, update);
      return sessionManager;
    },
    clear: async () => {
      await clearJWESession<T, MaxAge>(event, config);
      return sessionManager;
    },
  };

  return sessionManager;
}

/**
 * Get the session for the current request.
 */
export async function getJWESession<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
>(
  event: HTTPEvent,
  config: SessionConfigJWE<T, MaxAge>,
): Promise<SessionJWE<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;

  const context = getEventContext<H3EventContext>(event);

  // Initialize sessions container if not present
  if (!context.sessions) {
    context.sessions = new NullProtoObj();
  }
  // Return existing session if available and valid
  const existingSession = context.sessions![sessionName] as
    | SessionJWE<T, MaxAge>
    | undefined;
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
      hasWritableResponse(event)
    ) {
      await config.hooks?.onExpire?.({
        event,
        error: new Error(
          `JWT "exp" (Expiration Time) Claim validation failed: Token has expired (exp: ${new Date(session.expiresAt * 1000).toISOString()})`,
        ),
        config,
      });
      return clearJWESession(event, config).then(() =>
        getJWESession(event, config),
      );
    }

    await config.hooks?.onRead?.({
      event,
      session,
      config,
    });
    return session;
  }

  // Prepare an empty session object and store in context
  const session: SessionJWE<T, MaxAge> = {
    id: "",
    createdAt: 0,
    expiresAt: undefined as MaxAge extends number ? number : T['exp'],
    data: new NullProtoObj(),
  };
  context.sessions![sessionName] = session;

  // Load session from cookie or header
  let token: string | undefined;

  // Check header first
  if (config.sessionHeader !== false) {
    const headerName =
      typeof config.sessionHeader === "string"
        ? config.sessionHeader.toLowerCase()
        : `x-${sessionName.toLowerCase()}-session`;
    const headerValue = event.req.headers.get(headerName);
    if (typeof headerValue === "string") {
      token = headerValue.startsWith("Bearer ")
        ? headerValue.slice(7).trim()
        : headerValue;
    }
  }

  // Fallback to cookie if not found in header
  if (!token) {
    token = getChunkedCookie(event, sessionName);
  }

  // If we have a token, try to unseal and load into session context
  if (token) {
    const promise = unsealJWESession(event, config, token)
      .catch(async (error_) => {
        if (error_ instanceof Error) {
          const message = error_.message;
          if (
            message.includes("Token has expired") ||
            message.includes("Token is too old")
          ) {
            await config.hooks?.onExpire?.({
              event,
              error: error_,
              config,
            });
            return undefined;
          }
        }
        await config.hooks?.onError?.({
          event,
          error: error_,
          config,
        });
        return undefined;
      })
      .then((unsealed) => {
        if (unsealed) {
          Object.assign(session, unsealed);
        }
        delete session[kGetSessionPromise];
        return session as SessionJWE<T, MaxAge>;
      });
    session[kGetSessionPromise] = promise;
    await promise;
  }

  // New session store in response cookies
  if (!session.id) {
    session.id = config.generateId?.() ?? crypto.randomUUID();
    session.createdAt =
      config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
    (session.expiresAt as any) = config.maxAge
      ? session.createdAt + config.maxAge * 1000
      : undefined;
    await updateJWESession(event, config);
  }

  await config.hooks?.onRead?.({
    event,
    session,
    config,
  });
  return session;
}

/**
 * Update the session data for the current request.
 */
export async function updateJWESession<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
>(
  event: HTTPEvent,
  config: SessionConfigJWE<T, MaxAge>,
  update?: SessionUpdate<T>,
): Promise<SessionJWE<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;

  // Access current session
  const context = getEventContext<H3EventContext>(event);
  const session: SessionJWE<T, MaxAge> =
    (context.sessions?.[sessionName] as SessionJWE<T, MaxAge>) ||
    (await getJWESession(event, config));

  // Update session data if provided
  if (typeof update === "function") {
    update = update(session.data);
  }
  if (update) {
    Object.assign(session.data, update);
    await config.hooks?.onUpdate?.({
      event,
      session,
      config,
    });
  }

  // Seal and store in cookie
  if (config.cookie !== false && hasWritableResponse(event)) {
    const sealed = await sealJWESession(event, config);
    setChunkedCookie(event, sessionName, sealed, {
      ...DEFAULT_COOKIE,
      expires: config.maxAge
        ? new Date(session.createdAt + config.maxAge * 1000)
        : undefined,
      ...config.cookie,
    });
  }

  return session;
}

/**
 * Produce a JWE for the current session.
 */
export async function sealJWESession<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
>(event: HTTPEvent, config: SessionConfigJWE<T, MaxAge>): Promise<string> {
  const key = getEncryptKey(config.key);
  const sessionName = config.name || DEFAULT_NAME;

  // Access current session
  const context = getEventContext<H3EventContext>(event);
  const session: SessionJWE<T, MaxAge> =
    (context.sessions?.[sessionName] as SessionJWE<T, MaxAge>) ||
    (await getJWESession<T, MaxAge>(event, config));

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
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
>(
  _event: HTTPEvent,
  config: SessionConfigJWE<T, MaxAge>,
  sealed: string,
): Promise<Partial<SessionJWE<T, MaxAge>>> {
  const key = getDecryptKey(config.key);

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
  const { payload } = await decrypt<T & { iat: number }>(sealed, key, {
    ...config.jwe?.decryptOptions,
    requiredClaims: [
      ...new Set([
        ...(config.jwe?.decryptOptions?.requiredClaims || []),
        "jti",
        "iat",
      ]),
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
      throw error_;
    }
    throw new Error(String(error_));
  });

  const { jti, iat, exp, ...data } = payload;

  return {
    id: jti,
    createdAt: iat * 1000,
    expiresAt: (exp ? exp * 1000 : undefined) as T extends { exp: number }
      ? number
      : MaxAge,
    data: (data && typeof data === "object"
      ? data
      : new NullProtoObj()) as SessionData<T>,
  };
}

/**
 * Clear the session (delete from context and drop cookie).
 */
export async function clearJWESession<
  T extends JWTClaims,
  MaxAge extends number | undefined,
>(
  event: HTTPEvent,
  config: Partial<SessionConfigJWE<T, MaxAge>>,
): Promise<void> {
  const context = getEventContext<H3EventContext>(event);
  const sessionName = config.name || DEFAULT_NAME;

  if (context.sessions?.[sessionName]) {
    delete context.sessions![sessionName];
  }

  if (config.cookie !== false && hasWritableResponse(event)) {
    setChunkedCookie(event, sessionName, "", {
      ...DEFAULT_COOKIE,
      ...config.cookie,
      expires: new Date(0),
      maxAge: undefined,
    });

    await config.hooks?.onClear?.({
      event,
      config,
    });
  }
}

function getSessionFromContext<
  T extends JWTClaims,
  MaxAge extends number | undefined,
>(event: HTTPEvent, sessionName: string): SessionJWE<T, MaxAge> | undefined {
  const context = getEventContext<H3EventContext>(event);
  return context.sessions?.[sessionName] as SessionJWE<T, MaxAge> | undefined;
}

function hasWritableResponse(event: HTTPEvent): event is H3Event {
  return Boolean((event as H3Event).res);
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
