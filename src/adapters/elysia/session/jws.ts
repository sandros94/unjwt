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
import { sign, verify, isJWTError } from "../../../core/jws";
import {
  isSymmetricJWK,
  isPrivateJWK,
  isPublicJWK,
  computeDurationInSeconds,
} from "../../../core/utils";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import {
  readChunkedCookie,
  writeChunkedCookie,
  removeChunkedCookie,
  type CookieAttributes,
} from "../_cookie";
import type {
  SessionClaims,
  SessionData,
  SessionUpdate,
  SessionManager,
  SessionContext,
} from "./types";

export type { SessionContext };

export interface SessionJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  id: string | undefined;
  createdAt: number;
  expiresAt: MaxAge extends ExpiresIn ? number : T["exp"];
  data: SessionData<T>;
  token: string | undefined;
}

export interface SessionHooksJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> {
  onRead?: (args: {
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    context: TContext;
    config: SessionConfigJWS<T, MaxAge, TContext>;
  }) => void | Promise<void>;
  onUpdate?: (args: {
    session: SessionJWS<T, MaxAge> & { id: string; token: string };
    oldSession: SessionJWS<T, MaxAge>;
    context: TContext;
    config: SessionConfigJWS<T, MaxAge, TContext>;
  }) => void | Promise<void>;
  onClear?: (args: {
    oldSession: SessionJWS<T, MaxAge> | undefined;
    context: TContext;
    config: SessionConfigJWS<T, MaxAge, TContext>;
  }) => void | Promise<void>;
  onExpire?: (args: {
    session: {
      id: string | undefined;
      createdAt: number | undefined;
      expiresAt: number | undefined;
      token: string;
    };
    context: TContext;
    error: Error;
    config: SessionConfigJWS<T, MaxAge, TContext>;
  }) => void | Promise<void>;
  onError?: (args: {
    session: SessionJWS<T, MaxAge>;
    context: TContext;
    error: any;
    config: SessionConfigJWS<T, MaxAge, TContext>;
  }) => void | Promise<void>;
  onVerifyKeyLookup?: (args: {
    header: JWKLookupFunctionHeader;
    context: TContext;
    config: SessionConfigJWS<T, MaxAge, TContext>;
  }) => JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
}

export interface SessionConfigJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> {
  key:
    | JWK_oct<JWK_HMAC>
    | {
        privateKey: JWSAsymmetricPrivateJWK;
        publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet;
      };
  maxAge?: MaxAge;
  name?: string;
  /** Context property the session is exposed under. Default `"session"`. */
  contextKey?: string;
  cookie?: false | (CookieAttributes & { chunkMaxLength?: number });
  sessionHeader?: false | string;
  generateId?: () => string;
  jws?: {
    signOptions?: Omit<JWSSignOptions, "expiresIn">;
    verifyOptions?: JWTClaimValidationOptions;
  };
  hooks?: SessionHooksJWS<T, MaxAge, TContext>;
}

const DEFAULT_NAME = "elysia-jws";
const DEFAULT_COOKIE: CookieAttributes = {
  path: "/",
  secure: true,
  httpOnly: false,
};

export async function createJWSSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
): Promise<SessionManager<T, MaxAge>> {
  const state = emptySession<T, MaxAge>(config);
  await initFromToken(context, config, state);
  return buildManager(context, config, state);
}

function buildManager<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
  state: SessionJWS<T, MaxAge>,
): SessionManager<T, MaxAge> {
  const manager: SessionManager<T, MaxAge> = {
    get id() {
      return state.id;
    },
    get createdAt() {
      return state.createdAt;
    },
    get expiresAt() {
      return state.expiresAt as SessionManager<T, MaxAge>["expiresAt"];
    },
    get data() {
      return state.data;
    },
    get token() {
      return state.token;
    },
    update: async (update?: SessionUpdate<T>) => {
      await updateSession(context, config, state, update);
      return manager;
    },
    clear: async () => {
      await clearSession(context, config, state);
      return manager;
    },
  };
  return manager;
}

async function initFromToken<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
  state: SessionJWS<T, MaxAge>,
): Promise<void> {
  const token = readToken(context, config);
  if (!token) return;

  state.token = token;

  let exclusiveHookFired = false;
  try {
    const unsealed = await verifySession(context, config, token);
    Object.assign(state, unsealed);
  } catch (error_) {
    exclusiveHookFired = true;
    if (isJWTError(error_, "ERR_JWT_EXPIRED")) {
      await config.hooks?.onExpire?.({
        session: {
          id: error_.cause.jti,
          createdAt: error_.cause.iat ? error_.cause.iat * 1000 : undefined,
          expiresAt: error_.cause.exp ? error_.cause.exp * 1000 : undefined,
          token,
        },
        context,
        error: error_,
        config,
      });
    } else {
      await config.hooks?.onError?.({ session: state, context, error: error_, config });
    }
  }

  if (!exclusiveHookFired && state.id !== undefined && state.token !== undefined) {
    await config.hooks?.onRead?.({
      session: state as SessionJWS<T, MaxAge> & { id: string; token: string },
      context,
      config,
    });
  }
}

async function updateSession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
  state: SessionJWS<T, MaxAge>,
  update?: SessionUpdate<T>,
): Promise<void> {
  const oldSession: SessionJWS<T, MaxAge> = { ...state, data: sanitizeObjectCopy(state.data) };

  const resolvedUpdate = typeof update === "function" ? update(state.data) : update;
  if (resolvedUpdate) {
    Object.assign(state.data, resolvedUpdate);
  }

  const now = config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  state.id = config.generateId?.() || crypto.randomUUID();
  state.createdAt = createdAt;
  state.expiresAt = (
    config.maxAge === undefined
      ? undefined
      : createdAt + computeDurationInSeconds(config.maxAge) * 1000
  ) as SessionJWS<T, MaxAge>["expiresAt"];

  let token: string;
  try {
    token = await signSession(config, state);
  } catch (error_) {
    state.id = oldSession.id;
    state.createdAt = oldSession.createdAt;
    state.expiresAt = oldSession.expiresAt;
    state.data = oldSession.data;
    state.token = oldSession.token;
    await config.hooks?.onError?.({ session: state, context, error: error_, config });
    throw error_;
  }
  state.token = token;

  if (config.cookie !== false) {
    const { chunkMaxLength, ...attrs } = { ...DEFAULT_COOKIE, ...config.cookie };
    writeChunkedCookie(context.cookie, config.name || DEFAULT_NAME, token, {
      ...attrs,
      chunkMaxLength,
      expires:
        config.maxAge === undefined
          ? undefined
          : new Date(createdAt + computeDurationInSeconds(config.maxAge) * 1000),
    });
  }

  await config.hooks?.onUpdate?.({
    session: state as SessionJWS<T, MaxAge> & { id: string; token: string },
    oldSession,
    context,
    config,
  });
}

async function clearSession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
  state: SessionJWS<T, MaxAge>,
): Promise<void> {
  const had = state.id !== undefined || state.token !== undefined;
  const oldSession: SessionJWS<T, MaxAge> | undefined = had
    ? { ...state, data: sanitizeObjectCopy(state.data) }
    : undefined;

  const fresh = emptySession<T, MaxAge>(config);
  state.id = fresh.id;
  state.createdAt = fresh.createdAt;
  state.expiresAt = fresh.expiresAt;
  state.data = fresh.data;
  state.token = fresh.token;

  if (config.cookie !== false) {
    const { chunkMaxLength: _chunkMaxLength, ...attrs } = { ...DEFAULT_COOKIE, ...config.cookie };
    removeChunkedCookie(context.cookie, config.name || DEFAULT_NAME, attrs);
  }

  await config.hooks?.onClear?.({ oldSession, context, config });
}

async function signSession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(config: SessionConfigJWS<T, MaxAge, TContext>, state: SessionJWS<T, MaxAge>): Promise<string> {
  const key = getSignKey(config.key);

  const iat = Math.floor(state.createdAt / 1000);
  const exp = state.expiresAt ? Math.floor(state.expiresAt / 1000) : undefined;

  const payload: Record<string, any> = { ...state.data, jti: state.id, iat };
  if (exp) {
    payload.exp = exp;
  }

  return sign(payload, key, {
    ...config.jws?.signOptions,
    expiresIn: undefined,
    protectedHeader: {
      ...config.jws?.signOptions?.protectedHeader,
      kid: "kid" in key ? key.kid : undefined,
      typ: resolveTyp(config) || "JWT",
      cty: "application/json",
    },
  });
}

async function verifySession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWS<T, MaxAge, TContext>,
  token: string,
): Promise<Partial<SessionJWS<T, MaxAge>>> {
  const alg = config.jws?.signOptions?.alg;
  const jwk = config.hooks?.onVerifyKeyLookup
    ? (header: JWKLookupFunctionHeader) =>
        config.hooks!.onVerifyKeyLookup!({ header, context, config })
    : getVerifyKey(config.key);

  const { payload } = await verify<T & { iat: number }>(token, jwk, {
    ...config.jws?.verifyOptions,
    requiredClaims: [
      ...new Set([...(config.jws?.verifyOptions?.requiredClaims || []), "jti", "iat"]),
    ],
    typ: resolveTyp(config) || "JWT",
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
    expiresAt: (exp ? exp * 1000 : undefined) as SessionJWS<T, MaxAge>["expiresAt"],
    data: (data && typeof data === "object" ? data : emptyData<T>()) as SessionData<T>,
  };
}

function emptySession<T extends Record<string, any>, MaxAge extends ExpiresIn | undefined>(
  config: SessionConfigJWS<T, MaxAge, any>,
): SessionJWS<T, MaxAge> {
  const now = config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  return {
    id: undefined,
    createdAt,
    expiresAt: (config.maxAge === undefined
      ? undefined
      : createdAt + computeDurationInSeconds(config.maxAge) * 1000) as SessionJWS<
      T,
      MaxAge
    >["expiresAt"],
    data: emptyData<T>(),
    token: undefined,
  };
}

function emptyData<T extends Record<string, any>>(): SessionData<T> {
  return Object.create(null) as SessionData<T>;
}

function readToken<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(context: TContext, config: SessionConfigJWS<T, MaxAge, TContext>): string | undefined {
  const sessionName = config.name || DEFAULT_NAME;

  if (config.sessionHeader !== false) {
    const headerName =
      typeof config.sessionHeader === "string"
        ? config.sessionHeader.toLowerCase()
        : `x-${sessionName.toLowerCase()}-session`;
    const headerValue = context.request.headers.get(headerName);
    if (typeof headerValue === "string") {
      return headerValue.startsWith("Bearer ") ? headerValue.slice(7).trim() : headerValue;
    }
  }

  if (config.cookie !== false) {
    return readChunkedCookie(context.cookie, sessionName);
  }

  return undefined;
}

function resolveTyp(config: SessionConfigJWS<any, any, any>): string | undefined {
  const typ = config.jws?.signOptions?.protectedHeader?.typ;
  if (typeof typ === "string" && typ.toLowerCase().includes("jwt")) {
    return typ;
  }
  return undefined;
}

function getSignKey(key: SessionConfigJWS["key"] | undefined): JWSSignJWK {
  if (!key) {
    throw new Error("[unjwt/elysia] JWS key is required.");
  }

  let _key: JWSSignJWK | undefined;
  if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("privateKey" in key && isPrivateJWK(key.privateKey)) {
    _key = key.privateKey;
  }

  if (!_key) {
    throw new Error(
      "[unjwt/elysia] Invalid JWS key. It must be a symmetric JWK or a private JWK.",
      {
        cause: key,
      },
    );
  }

  return _key;
}

function getVerifyKey(key: SessionConfigJWS["key"] | undefined): JWSVerifyJWK | JWKSet {
  if (!key) {
    throw new Error("[unjwt/elysia] JWS key is required.");
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
    throw new Error(
      "[unjwt/elysia] Invalid JWS key. It must be a symmetric JWK or a public JWK/set.",
      {
        cause: key,
      },
    );
  }

  return _key;
}
