import {
  type H3Event,
  type HTTPEvent,
  type H3EventContext,
  getEventContext,
} from "h3v2";
// TODO: replace with h3v2 export when available
import { getChunkedCookie, setChunkedCookie } from "./cookie";

import type { CookieSerializeOptions } from "cookie-esv2";
import { NullProtoObj } from "rou3";

import type { SessionData, SessionManager } from "./jwe.ts";
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
import { isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../../../core/utils";

type SessionDataT = Omit<JWTClaims, "jti" | "iat" | "exp">;

const kGetSessionPromise = Symbol("h3_jws_getSession");

export interface SessionJWS<T extends SessionDataT = SessionDataT> {
  id: string;
  createdAt: number;
  expiresAt?: number;
  data: SessionData<T>;
  [kGetSessionPromise]?: Promise<SessionJWS<T>>;
}

export interface SessionHooksJWS {
  onRead?: (
    session: SessionJWS,
    event: HTTPEvent,
    config: SessionConfigJWS,
  ) => void | Promise<void>;
  onUpdate?: (
    session: SessionJWS,
    event: HTTPEvent,
    config: SessionConfigJWS,
  ) => void | Promise<void>;
  onClear?: (
    event: HTTPEvent,
    config: Partial<SessionConfigJWS>,
  ) => void | Promise<void>;
  onExpire?: (
    event: HTTPEvent,
    error: any | undefined,
    config: SessionConfigJWS,
  ) => void | Promise<void>;
  onError?: (
    event: HTTPEvent,
    error: any,
    config: SessionConfigJWS,
  ) => void | Promise<void>;
}

export interface SessionConfigJWS {
  key:
    | JWK_Symmetric
    | {
        privateKey: JWK_Private;
        publicKey: JWK_Public | JWK_Public[] | JWKSet;
      };
  maxAge?: number;
  name?: string;
  cookie?: false | (CookieSerializeOptions & { chunkMaxLength?: number });
  sessionHeader?: false | string;
  generateId?: () => string;
  jws?: {
    signOptions?: Omit<JWSSignOptions, "expiresIn">;
    verifyOptions?: JWTClaimValidationOptions;
  };
  hooks?: SessionHooksJWS;
}

const DEFAULT_NAME = "h3-jws";
const DEFAULT_COOKIE: SessionConfigJWS["cookie"] = {
  path: "/",
  secure: true,
  httpOnly: false,
};

type SessionUpdate<T extends SessionDataT = SessionDataT> =
  | Partial<SessionData<T>>
  | ((oldData: SessionData<T>) => Partial<SessionData<T>> | undefined);

export async function useJWSSession<T extends SessionDataT = SessionDataT>(
  event: HTTPEvent,
  config: SessionConfigJWS,
): Promise<SessionManager<T>> {
  const sessionName = config.name || DEFAULT_NAME;
  await getJWSSession<T>(event, config);

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
      await updateJWSSession<T>(event, config, update);
      return sessionManager;
    },
    clear: async () => {
      await clearJWSSession(event, config);
      return sessionManager;
    },
  };

  return sessionManager;
}

export async function getJWSSession<T extends SessionDataT = SessionDataT>(
  event: HTTPEvent,
  config: SessionConfigJWS,
): Promise<SessionJWS<T>> {
  const sessionName = config.name || DEFAULT_NAME;
  const context = getEventContext<H3EventContext>(event);

  if (!context.sessions) {
    context.sessions = new NullProtoObj();
  }

  const existingSession = context.sessions![sessionName] as
    | SessionJWS<T>
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
      await config.hooks?.onExpire?.(event, undefined, config);
      return clearJWSSession(event, config).then(() =>
        getJWSSession<T>(event, config),
      );
    }

    await config.hooks?.onRead?.(session, event, config);
    return session;
  }

  const session: SessionJWS<T> = {
    id: "",
    createdAt: 0,
    expiresAt: undefined,
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
      token = headerValue;
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
          await config.hooks?.onExpire?.(event, error_, config);
          return undefined;
        }
        await config.hooks?.onError?.(event, error_, config);
        return undefined;
      })
      .then((unsealed) => {
        if (unsealed) {
          Object.assign(session, unsealed);
        }
        delete session[kGetSessionPromise];
        return session as SessionJWS<T>;
      });
    session[kGetSessionPromise] = promise;
    await promise;
  }

  if (!session.id) {
    session.id = config.generateId?.() ?? crypto.randomUUID();
    session.createdAt =
      config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
    session.expiresAt = config.maxAge
      ? session.createdAt + config.maxAge * 1000
      : undefined;
    await updateJWSSession<T>(event, config);
  }

  await config.hooks?.onRead?.(session, event, config);
  return session;
}

export async function updateJWSSession<T extends SessionDataT = SessionDataT>(
  event: HTTPEvent,
  config: SessionConfigJWS,
  update?: SessionUpdate<T>,
): Promise<SessionJWS<T>> {
  const sessionName = config.name || DEFAULT_NAME;
  const context = getEventContext<H3EventContext>(event);

  const session: SessionJWS<T> =
    (context.sessions?.[sessionName] as SessionJWS<T>) ||
    (await getJWSSession<T>(event, config));

  if (typeof update === "function") {
    update = update(session.data);
  }
  if (update) {
    Object.assign(session.data, update);
    await config.hooks?.onUpdate?.(session, event, config);
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

export async function signJWSSession<T extends SessionDataT = SessionDataT>(
  event: HTTPEvent,
  config: SessionConfigJWS,
): Promise<string> {
  const key = getSignKey(config.key);
  const sessionName = config.name || DEFAULT_NAME;
  const context = getEventContext<H3EventContext>(event);

  const session: SessionJWS<T> =
    (context.sessions?.[sessionName] as SessionJWS<T>) ||
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

export async function verifyJWSSession(
  _event: HTTPEvent,
  config: SessionConfigJWS,
  token: string,
): Promise<Partial<SessionJWS>> {
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
    typ: typ || "JWT",
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
    createdAt: iat * 1000,
    expiresAt: payload.exp ? payload.exp * 1000 : undefined,
    data: (data && typeof data === "object"
      ? data
      : new NullProtoObj()) as SessionData,
  };
}

export async function clearJWSSession(
  event: HTTPEvent,
  config: Partial<SessionConfigJWS>,
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
): SessionJWS<T> | undefined {
  const context = getEventContext<H3EventContext>(event);
  return context.sessions?.[sessionName] as SessionJWS<T> | undefined;
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
