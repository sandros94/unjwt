import type {
  ExpiresIn,
  JWEEncryptJWK,
  JWEDecryptJWK,
  JWEAsymmetricPublicJWK,
  JWEAsymmetricPrivateJWK,
  JWEEncryptOptions,
  JWEHeaderParameters,
  JWTClaimValidationOptions,
} from "../../../core/types";
import { Elysia } from "elysia";
import { encrypt, decrypt, isJWTError } from "../../../core/jwe";
import { guardName, type SessionPlugin } from "../_plugin";
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

export interface SessionJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  id: string | undefined;
  createdAt: number;
  expiresAt: MaxAge extends ExpiresIn ? number : T["exp"];
  data: SessionData<T>;
  token: string | undefined;
}

export interface SessionHooksJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> {
  onRead?: (args: {
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    context: TContext;
    config: SessionConfigJWE<T, MaxAge, TContext>;
  }) => void | Promise<void>;
  onUpdate?: (args: {
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    oldSession: SessionJWE<T, MaxAge>;
    context: TContext;
    config: SessionConfigJWE<T, MaxAge, TContext>;
  }) => void | Promise<void>;
  onClear?: (args: {
    oldSession: SessionJWE<T, MaxAge> | undefined;
    context: TContext;
    config: SessionConfigJWE<T, MaxAge, TContext>;
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
    config: SessionConfigJWE<T, MaxAge, TContext>;
  }) => void | Promise<void>;
  onError?: (args: {
    session: SessionJWE<T, MaxAge>;
    context: TContext;
    error: any;
    config: SessionConfigJWE<T, MaxAge, TContext>;
  }) => void | Promise<void>;
  onUnsealKeyLookup?: (args: {
    header: JWEHeaderParameters;
    context: TContext;
    config: SessionConfigJWE<T, MaxAge, TContext>;
  }) => JWEDecryptJWK | Promise<JWEDecryptJWK>;
}

export interface SessionConfigJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> {
  key:
    | string
    | JWEEncryptJWK
    | {
        privateKey: JWEAsymmetricPrivateJWK;
        publicKey?: JWEAsymmetricPublicJWK;
      };
  maxAge?: MaxAge;
  name?: string;
  /** Context property the session is exposed under. Default `"session"`. */
  contextKey?: string;
  cookie?: false | (CookieAttributes & { chunkMaxLength?: number });
  sessionHeader?: false | string;
  generateId?: () => string;
  jwe?: {
    encryptOptions?: Omit<JWEEncryptOptions, "expiresIn">;
    decryptOptions?: JWTClaimValidationOptions;
  };
  hooks?: SessionHooksJWE<T, MaxAge, TContext>;
}

const DEFAULT_NAME = "elysia-jwe";
const DEFAULT_COOKIE: CookieAttributes = {
  path: "/",
  secure: true,
  httpOnly: true,
};

export async function createJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
>(
  context: TContext,
  config: SessionConfigJWE<T, MaxAge, TContext>,
): Promise<SessionManager<T, MaxAge>> {
  const state = emptySession<T, MaxAge>(config);
  await initFromToken(context, config, state);
  return buildManager(context, config, state);
}

export function jweSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWE<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
): SessionPlugin<{ [P in K]: SessionManager<T, MaxAge> }, `require${Capitalize<K>}`> {
  const contextKey = (config.contextKey ?? "session") as K;
  return new Elysia({ name: "unjwt/elysia-jwe", seed: contextKey })
    .resolve({ as: "scoped" }, async ({ cookie, request }) => {
      const session = await createJWESession<T, MaxAge, SessionContext>(
        { cookie, request },
        config,
      );
      return { [contextKey]: session } as { [P in K]: SessionManager<T, MaxAge> };
    })
    .macro({
      [guardName(contextKey)]: {
        resolve(ctx) {
          const session = (ctx as Record<string, unknown>)[contextKey] as
            | SessionManager<T, MaxAge>
            | undefined;
          if (!session?.id) return ctx.status(401, "Unauthorized");
          return {};
        },
      },
    }) as unknown as SessionPlugin<
    { [P in K]: SessionManager<T, MaxAge> },
    `require${Capitalize<K>}`
  >;
}

function buildManager<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWE<T, MaxAge, TContext>,
  state: SessionJWE<T, MaxAge>,
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
  config: SessionConfigJWE<T, MaxAge, TContext>,
  state: SessionJWE<T, MaxAge>,
): Promise<void> {
  const token = readToken(context, config);
  if (!token) return;

  state.token = token;

  let exclusiveHookFired = false;
  try {
    const unsealed = await unsealSession(context, config, token);
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
      session: state as SessionJWE<T, MaxAge> & { id: string; token: string },
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
  config: SessionConfigJWE<T, MaxAge, TContext>,
  state: SessionJWE<T, MaxAge>,
  update?: SessionUpdate<T>,
): Promise<void> {
  const oldSession: SessionJWE<T, MaxAge> = { ...state, data: sanitizeObjectCopy(state.data) };

  const resolvedUpdate = typeof update === "function" ? update(state.data) : update;
  if (resolvedUpdate) {
    Object.assign(state.data, resolvedUpdate);
  }

  const now = config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  state.id = config.generateId?.() || crypto.randomUUID();
  state.createdAt = createdAt;
  state.expiresAt = (
    config.maxAge === undefined
      ? undefined
      : createdAt + computeDurationInSeconds(config.maxAge) * 1000
  ) as SessionJWE<T, MaxAge>["expiresAt"];

  let token: string;
  try {
    token = await sealSession(config, state);
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
    session: state as SessionJWE<T, MaxAge> & { id: string; token: string },
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
  config: SessionConfigJWE<T, MaxAge, TContext>,
  state: SessionJWE<T, MaxAge>,
): Promise<void> {
  const had = state.id !== undefined || state.token !== undefined;
  const oldSession: SessionJWE<T, MaxAge> | undefined = had
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

async function sealSession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(config: SessionConfigJWE<T, MaxAge, TContext>, state: SessionJWE<T, MaxAge>): Promise<string> {
  const key = getEncryptKey(config.key);

  const iat = Math.floor(state.createdAt / 1000);
  const exp = state.expiresAt ? Math.floor(state.expiresAt / 1000) : undefined;

  const payload: Record<string, any> = { ...state.data, jti: state.id, iat };
  if (exp) {
    payload.exp = exp;
  }

  return encrypt(payload, key, {
    ...config.jwe?.encryptOptions,
    expiresIn: undefined,
    protectedHeader: {
      ...config.jwe?.encryptOptions?.protectedHeader,
      typ: resolveTyp(config) || "JWT",
      cty: "application/json",
    },
  });
}

async function unsealSession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(
  context: TContext,
  config: SessionConfigJWE<T, MaxAge, TContext>,
  sealed: string,
): Promise<Partial<SessionJWE<T, MaxAge>>> {
  const key = config.hooks?.onUnsealKeyLookup
    ? (header: JWEHeaderParameters) => config.hooks!.onUnsealKeyLookup!({ header, context, config })
    : getDecryptKey(config.key);

  const alg = config.jwe?.encryptOptions?.alg;
  const enc = config.jwe?.encryptOptions?.enc;

  const { payload } = await decrypt<T & { iat: number }>(sealed, key, {
    ...config.jwe?.decryptOptions,
    requiredClaims: [
      ...new Set([...(config.jwe?.decryptOptions?.requiredClaims || []), "jti", "iat"]),
    ],
    typ: resolveTyp(config) || "JWT",
    maxTokenAge: config.maxAge,
    algorithms: alg ? [alg] : undefined,
    encryptionAlgorithms: enc ? [enc] : undefined,
    unwrappedKeyAlgorithm: undefined,
    keyUsage: undefined,
    forceUint8Array: false,
    validateClaims: true,
  }).catch((error_) => {
    if (error_ instanceof Error) throw error_;
    throw new Error(String(error_));
  });

  const { jti, iat, exp, ...data } = payload;
  return {
    id: jti,
    createdAt: iat * 1000,
    expiresAt: (exp ? exp * 1000 : undefined) as SessionJWE<T, MaxAge>["expiresAt"],
    data: (data && typeof data === "object" ? data : emptyData<T>()) as SessionData<T>,
  };
}

function emptySession<T extends Record<string, any>, MaxAge extends ExpiresIn | undefined>(
  config: SessionConfigJWE<T, MaxAge, any>,
): SessionJWE<T, MaxAge> {
  const now = config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  return {
    id: undefined,
    createdAt,
    expiresAt: (config.maxAge === undefined
      ? undefined
      : createdAt + computeDurationInSeconds(config.maxAge) * 1000) as SessionJWE<
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
>(context: TContext, config: SessionConfigJWE<T, MaxAge, TContext>): string | undefined {
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

function resolveTyp(config: SessionConfigJWE<any, any, any>): string | undefined {
  const typ = config.jwe?.encryptOptions?.protectedHeader?.typ;
  if (typeof typ === "string" && typ.toLowerCase().includes("jwt")) {
    return typ;
  }
  return undefined;
}

function getEncryptKey(key: SessionConfigJWE["key"] | undefined): string | JWEEncryptJWK {
  if (!key) {
    throw new Error("[unjwt/elysia] JWE key is required.");
  }

  let _key: string | JWEEncryptJWK | undefined;
  if (typeof key === "string") {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key as JWEEncryptJWK;
  } else if ("publicKey" in key && key.publicKey && isPublicJWK(key.publicKey)) {
    _key = key.publicKey as JWEAsymmetricPublicJWK;
  } else if ("privateKey" in key && isPrivateJWK(key.privateKey)) {
    _key = key.privateKey as unknown as JWEEncryptJWK;
  }

  if (!_key) {
    throw new Error("[unjwt/elysia] Invalid JWE key. It must be a password string or valid JWK.", {
      cause: key,
    });
  }

  return _key;
}

function getDecryptKey(key: SessionConfigJWE["key"] | undefined): string | JWEDecryptJWK {
  if (!key) {
    throw new Error("[unjwt/elysia] JWE key is required.");
  }

  let _key: string | JWEDecryptJWK | undefined;
  if (typeof key === "string") {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key as JWEDecryptJWK;
  } else if ("privateKey" in key) {
    _key = key.privateKey as JWEAsymmetricPrivateJWK;
  }

  if (!_key) {
    throw new Error(
      "[unjwt/elysia] Invalid JWE key. It must be a password string or a valid private JWK.",
      {
        cause: key,
      },
    );
  }

  return _key;
}
