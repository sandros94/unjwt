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
  JWK_Symmetric,
  JWK_Public,
  JWK_Private,
  JWKSet,
  JWTClaims,
  JWSSignOptions,
  JWTClaimValidationOptions,
} from "../../../core/types";
import { sign, verify } from "../../../core/jws";
import { isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../../../core/utils";
import type { SessionData, SessionUpdate, SessionManager } from "./types";

const kGetSessionPromise = Symbol("h3_jws_getSession");

export interface SessionJWS<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
> {
  // Mapped from payload.jti
  id: string;
  // Mapped from payload.iat (in ms)
  createdAt: number;
  // Mapped from payload.exp (in ms)
  expiresAt: T extends { exp: number } ? number : MaxAge;
  data: SessionData<T>;
  [kGetSessionPromise]?: Promise<SessionJWS<T, MaxAge>>;
}

export interface SessionHooksJWS<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
> {
  onRead?: (args: {
    session: SessionJWS<T, MaxAge>;
    event: HTTPEvent;
    config: SessionConfigJWS<T, MaxAge>;
  }) => void | Promise<void>;
  onUpdate?: (args: {
    session: SessionJWS<T, MaxAge>;
    event: HTTPEvent;
    config: SessionConfigJWS<T, MaxAge>;
  }) => void | Promise<void>;
  onClear?: (args: {
    event: HTTPEvent;
    config: Partial<SessionConfigJWS<T, MaxAge>>;
  }) => void | Promise<void>;
  onExpire?: (args: {
    event: HTTPEvent;
    error: Error;
    config: SessionConfigJWS<T, MaxAge>;
  }) => void | Promise<void>;
  onError?: (args: {
    event: HTTPEvent;
    error: any;
    config: SessionConfigJWS<T, MaxAge>;
  }) => void | Promise<void>;
}

export interface SessionConfigJWS<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
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
  hooks?: SessionHooksJWS<T, MaxAge>;
}

const DEFAULT_NAME = "h3-jws";
const DEFAULT_COOKIE: SessionConfigJWS["cookie"] = {
  path: "/",
  secure: true,
  httpOnly: false,
};

export async function useJWSSession<
  T extends JWTClaims,
  MaxAge extends number | undefined,
>(
  event: HTTPEvent,
  config: SessionConfigJWS<T, MaxAge>,
): Promise<SessionManager<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  await getJWSSession<T, MaxAge>(event, config);

  const sessionManager: SessionManager<T, MaxAge> = {
    get id() {
      return getSessionFromContext<T, MaxAge>(event, sessionName)?.id;
    },
    get createdAt() {
      return (
        getSessionFromContext<T, MaxAge>(event, sessionName)?.createdAt ??
        Date.now()
      );
    },
    get expiresAt() {
      return getSessionFromContext<T, MaxAge>(event, sessionName)
        ?.expiresAt as T extends { exp: number } ? number : MaxAge;
    },
    get data() {
      return (getSessionFromContext<T, MaxAge>(event, sessionName)?.data ||
        {}) as T;
    },
    update: async (update: SessionUpdate<T>) => {
      await updateJWSSession<T, MaxAge>(event, config, update);
      return sessionManager;
    },
    clear: async () => {
      await clearJWSSession<T, MaxAge>(event, config);
      return sessionManager;
    },
  };

  return sessionManager;
}

export async function getJWSSession<
  T extends JWTClaims,
  MaxAge extends number | undefined,
>(
  event: HTTPEvent,
  config: SessionConfigJWS<T, MaxAge>,
): Promise<SessionJWS<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  const context = getEventContext<H3EventContext>(event);

  if (!context.sessions) {
    context.sessions = new NullProtoObj();
  }

  const existingSession = context.sessions![sessionName] as
    | SessionJWS<T, MaxAge>
    | undefined;
  if (existingSession) {
    const session = existingSession[kGetSessionPromise]
      ? await existingSession[kGetSessionPromise]
      : existingSession;

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
      return clearJWSSession(event, config).then(() =>
        getJWSSession<T, MaxAge>(event, config),
      );
    }

    await config.hooks?.onRead?.({
      event,
      session,
      config,
    });
    return session;
  }

  const session: SessionJWS<T, MaxAge> = {
    id: "",
    createdAt: 0,
    expiresAt: undefined as T extends { exp: number } ? number : MaxAge,
    data: new NullProtoObj(),
  };
  context.sessions![sessionName] = session;

  let token: string | undefined;

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

  if (!token) {
    token = getChunkedCookie(event, sessionName);
  }

  if (token) {
    const promise = verifyJWSSession(event, config, token)
      .catch(async (error_) => {
        if (
          error_ instanceof Error &&
          (error_.message.includes("Token has expired") ||
            error_.message.includes("Token is too old"))
        ) {
          await config.hooks?.onExpire?.({
            event,
            error: error_,
            config,
          });
          return undefined;
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
        return session as SessionJWS<T, MaxAge>;
      });
    session[kGetSessionPromise] = promise;
    await promise;
  }

  if (!session.id) {
    session.id = config.generateId?.() ?? crypto.randomUUID();
    session.createdAt =
      config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
    (session.expiresAt as any) = config.maxAge
      ? session.createdAt + config.maxAge * 1000
      : undefined;
    await updateJWSSession<T, MaxAge>(event, config);
  }

  await config.hooks?.onRead?.({
    event,
    session,
    config,
  });
  return session;
}

export async function updateJWSSession<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
>(
  event: HTTPEvent,
  config: SessionConfigJWS<T, MaxAge>,
  update?: SessionUpdate<T>,
): Promise<SessionJWS<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  const context = getEventContext<H3EventContext>(event);

  const session: SessionJWS<T, MaxAge> =
    (context.sessions?.[sessionName] as SessionJWS<T, MaxAge>) ||
    (await getJWSSession<T, MaxAge>(event, config));

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

  if (config.cookie !== false && hasWritableResponse(event)) {
    const token = await signJWSSession(event, config);
    setChunkedCookie(event, sessionName, token, {
      ...DEFAULT_COOKIE,
      expires: config.maxAge
        ? new Date(session.createdAt + config.maxAge * 1000)
        : undefined,
      ...config.cookie,
    });
  }

  return session;
}

export async function signJWSSession<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
>(event: HTTPEvent, config: SessionConfigJWS<T, MaxAge>): Promise<string> {
  const key = getSignKey(config.key);
  const sessionName = config.name || DEFAULT_NAME;
  const context = getEventContext<H3EventContext>(event);

  const session: SessionJWS<T, MaxAge> =
    (context.sessions?.[sessionName] as SessionJWS<T, MaxAge>) ||
    (await getJWSSession<T, MaxAge>(event, config));

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
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
>(
  _event: HTTPEvent,
  config: SessionConfigJWS<T, MaxAge>,
  token: string,
): Promise<Partial<SessionJWS<T, MaxAge>>> {
  const jwk = getVerifyKey(config.key);
  const alg = config.jws?.signOptions?.alg;

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
    createdAt: iat * 1000,
    expiresAt: (exp ? exp * 1000 : undefined) as T extends { exp: number }
      ? number
      : MaxAge,
    data: (data && typeof data === "object"
      ? data
      : new NullProtoObj()) as SessionData<T>,
  };
}

export async function clearJWSSession<
  T extends JWTClaims = JWTClaims,
  MaxAge extends number | undefined = number | undefined,
>(
  event: HTTPEvent,
  config: Partial<SessionConfigJWS<T, MaxAge>>,
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
>(event: HTTPEvent, sessionName: string): SessionJWS<T, MaxAge> | undefined {
  const context = getEventContext<H3EventContext>(event);
  return context.sessions?.[sessionName] as SessionJWS<T, MaxAge> | undefined;
}

function hasWritableResponse(event: HTTPEvent): event is H3Event {
  return Boolean((event as H3Event).res);
}

function getSignKey(
  key: SessionConfigJWS["key"] | undefined,
): JWK_Symmetric | JWK_Private {
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

  let _key: JWK_Symmetric | JWK_Public | JWKSet | undefined;
  if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("publicKey" in key) {
    const publicKey = key.publicKey;
    if (isPublicJWK(publicKey)) {
      _key = publicKey;
    } else if (Array.isArray(publicKey)) {
      const keys = publicKey.filter((candidate): candidate is JWK_Public =>
        isPublicJWK(candidate),
      );
      if (keys.length > 0) {
        _key = { keys };
      }
    } else if (
      publicKey &&
      typeof publicKey === "object" &&
      Array.isArray((publicKey as JWKSet).keys)
    ) {
      const keys = (publicKey as JWKSet).keys.filter((candidate) =>
        isPublicJWK(candidate),
      );
      if (keys.length > 0) {
        _key = { keys };
      }
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
