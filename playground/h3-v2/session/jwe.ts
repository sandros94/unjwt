import {
  type H3Event,
  type HTTPEvent,
  H3EventContext,
  getEventContext,
} from "h3v2";
// TODO: replace with h3v2 export when available
import { getChunkedCookie, setChunkedCookie } from "./cookie.ts";

import type { CookieSerializeOptions } from "cookie-esv2";
import { NullProtoObj } from "rou3";

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
} from "../../../src/core/jwe";
import { isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../../../src/core/utils";

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
    event: HTTPEvent,
    config: SessionConfigJWE,
  ) => void | Promise<void>;
  onUpdate?: (
    session: SessionJWE,
    event: HTTPEvent,
    config: SessionConfigJWE,
  ) => void | Promise<void>;
  onClear?: (
    event: HTTPEvent,
    config: Partial<SessionConfigJWE>,
  ) => void | Promise<void>;
  onExpire?: (
    event: HTTPEvent,
    error: any | undefined,
    config: SessionConfigJWE,
  ) => void | Promise<void>;
  onError?: (
    event: HTTPEvent,
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
  /** Shared secret used, string for PBES2 or Json Web Key (JWK) */
  key:
    | string
    | JWK_Symmetric
    | {
        privateKey: JWK_Private | JWK_Symmetric;
        publicKey?: JWK_Public;
      };
  /** Session lifetime in seconds (used to derive exp from iat) */
  maxAge?: number;
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
  hooks?: SessionHooksJWE;
}

const DEFAULT_NAME = "h3-jwe";
const DEFAULT_COOKIE: SessionConfigJWE["cookie"] = {
  path: "/",
  secure: true,
  httpOnly: true,
};

type SessionUpdate<T extends SessionDataT = SessionDataT> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

/**
 * Create a session manager for the current request.
 */
export async function useJWESession<T extends SessionDataT = SessionDataT>(
  event: HTTPEvent,
  config: SessionConfigJWE,
): Promise<SessionManager<T>> {
  const sessionName = config.name || DEFAULT_NAME;
  await getJWESession<T>(event, config);

  const sessionManager: SessionManager<T> = {
    get id() {
      return getSessionFromContext<T>(event, sessionName)?.id;
    },
    get createdAt() {
      return (
        getSessionFromContext<T>(event, sessionName)?.createdAt ?? Date.now()
      );
    },
    get expiresAt() {
      return getSessionFromContext<T>(event, sessionName)?.expiresAt;
    },
    get data() {
      return (getSessionFromContext<T>(event, sessionName)?.data || {}) as T;
    },
    update: async (update: SessionUpdate<T>) => {
      await updateJWESession<T>(event, config, update);
      return sessionManager;
    },
    clear: async () => {
      await clearJWESession(event, config);
      return sessionManager;
    },
  };

  return sessionManager;
}

/**
 * Get the session for the current request.
 */
export async function getJWESession<T extends SessionDataT = SessionDataT>(
  event: HTTPEvent,
  config: SessionConfigJWE,
): Promise<SessionJWE<T>> {
  const sessionName = config.name || DEFAULT_NAME;

  const context = getEventContext<H3EventContext>(event);

  // Initialize sessions container if not present
  if (!context.sessions) {
    context.sessions = new NullProtoObj();
  }
  // Return existing session if available and valid
  const existingSession = context.sessions![sessionName] as
    | SessionJWE<T>
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
      await config.hooks?.onExpire?.(event, undefined, config);
      return clearJWESession(event, config).then(() =>
        getJWESession<T>(event, config),
      );
    }

    await config.hooks?.onRead?.(session, event, config);
    return session;
  }

  // Prepare an empty session object and store in context
  const session: SessionJWE<T> = {
    id: "",
    createdAt: 0,
    expiresAt: undefined,
    data: new NullProtoObj(),
  };
  context.sessions![sessionName] = session;

  // Load session from cookie or header
  let jweToken: string | undefined;

  // Check header first
  if (config.sessionHeader !== false) {
    const headerName =
      typeof config.sessionHeader === "string"
        ? config.sessionHeader.toLowerCase()
        : `x-${sessionName.toLowerCase()}-session`;
    const headerValue = event.req.headers.get(headerName);
    if (typeof headerValue === "string") {
      jweToken = headerValue;
    }
  }

  // Fallback to cookie if not found in header
  if (!jweToken) {
    jweToken = getChunkedCookie(event, sessionName);
  }

  // If we have a token, try to unseal and load into session context
  if (jweToken) {
    const promise = unsealJWESession(event, config, jweToken)
      .catch(async (error_) => {
        if (error_ instanceof Error) {
          const message = error_.message;
          if (
            message.includes("Token has expired") ||
            message.includes("Token is too old")
          ) {
            await config.hooks?.onExpire?.(event, error_, config);
            return undefined;
          }
        }
        await config.hooks?.onError?.(event, error_, config);
        return undefined;
      })
      .then((unsealed) => {
        if (unsealed) {
          Object.assign(session, unsealed);
        }
        delete session[kGetSessionPromise];
        return session as SessionJWE<T>;
      });
    session[kGetSessionPromise] = promise;
    await promise;
  }

  // New session store in response cookies
  if (!session.id) {
    session.id = config.generateId?.() ?? crypto.randomUUID();
    session.createdAt =
      config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
    session.expiresAt = config.maxAge
      ? session.createdAt + config.maxAge * 1000
      : undefined;
    await updateJWESession<T>(event, config);
  }

  await config.hooks?.onRead?.(session, event, config);
  return session;
}

/**
 * Update the session data for the current request.
 */
export async function updateJWESession<T extends SessionDataT = SessionDataT>(
  event: HTTPEvent,
  config: SessionConfigJWE,
  update?: SessionUpdate<T>,
): Promise<SessionJWE<T>> {
  const sessionName = config.name || DEFAULT_NAME;

  // Access current session
  const context = getEventContext<H3EventContext>(event);
  const session: SessionJWE<T> =
    (context.sessions?.[sessionName] as SessionJWE<T>) ||
    (await getJWESession<T>(event, config));

  // Update session data if provided
  if (typeof update === "function") {
    update = update(session.data);
  }
  if (update) {
    Object.assign(session.data, update);
    await config.hooks?.onUpdate?.(session, event, config);
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
export async function sealJWESession<T extends SessionDataT = SessionDataT>(
  event: HTTPEvent,
  config: SessionConfigJWE,
): Promise<string> {
  const key = getEncryptKey(config.key);
  const sessionName = config.name || DEFAULT_NAME;

  // Access current session
  const context = getEventContext<H3EventContext>(event);
  const session: SessionJWE<T> =
    (context.sessions?.[sessionName] as SessionJWE<T>) ||
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
  _event: HTTPEvent,
  config: SessionConfigJWE,
  sealed: string,
): Promise<Partial<SessionJWE>> {
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
      throw error_;
    }
    throw new Error(String(error_));
  });

  const { jti, iat, ...data } = payload;

  return {
    id: jti,
    createdAt: iat * 1000,
    expiresAt: payload.exp ? payload.exp * 1000 : undefined,
    data: (data && typeof data === "object" ? data : new NullProtoObj()) as any,
  };
}

/**
 * Clear the session (delete from context and drop cookie).
 */
export async function clearJWESession(
  event: HTTPEvent,
  config: Partial<SessionConfigJWE>,
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

    await config.hooks?.onClear?.(event, config);
  }
}

function getSessionFromContext<T extends SessionDataT>(
  event: HTTPEvent,
  sessionName: string,
): SessionJWE<T> | undefined {
  const context = getEventContext<H3EventContext>(event);
  return context.sessions?.[sessionName] as SessionJWE<T> | undefined;
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
