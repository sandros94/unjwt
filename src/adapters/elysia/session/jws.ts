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
import { Elysia } from "elysia";
import { sign, verify, isJWTError } from "../../../core/jws";
import { guardName, type SessionPlugin } from "../_plugin";
import { isCryptoKey, isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../../../core/utils";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import {
  type SessionIssueOptions,
  assertKeyMaterial,
  assertSessionContentType,
  invalidConfigError,
  invalidKeyError,
  resolveExpiresAt,
  rethrowAsInvalidToken,
  sanitizeSessionUpdate,
  sessionRequiredClaims,
  sessionTyp,
  splitSessionClaims,
} from "../../_session";
import { writeChunkedCookie, removeChunkedCookie, type CookieAttributes } from "../_cookie";
import type {
  SessionClaims,
  SessionData,
  SessionUpdate,
  SessionManager,
  SessionContext,
} from "./types";
import { PREFIX, emptyData, readSessionToken } from "./_shared";

export type { SessionContext };

export interface SessionJWS<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  id: string | undefined;
  createdAt: number;
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
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
  /**
   * Key used for signing — a symmetric `oct` (HS*) JWK, a `CryptoKey`, or an
   * asymmetric pair. A `CryptoKey` carries no algorithm, so it additionally
   * requires `jws.signOptions.alg`.
   */
  key:
    | CryptoKey
    | JWK_oct<JWK_HMAC>
    | {
        privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
        publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
      };
  /**
   * Session lifetime — sets `exp = iat + maxAge` in the token, bounds the age
   * of an incoming token, and drives the cookie expiry.
   */
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
  sameSite: "lax",
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

export function jwsSession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  K extends string = "session",
>(
  config: SessionConfigJWS<T, MaxAge> &
    (K extends "session" ? { contextKey?: K } : { contextKey: K }),
): SessionPlugin<{ [P in K]: SessionManager<T, MaxAge> }, `require${Capitalize<K>}`> {
  const contextKey = (config.contextKey ?? "session") as K;
  // The seed carries the session name as well as the context key, so two
  // differently-named sessions register as two plugins rather than one.
  const seed = `${config.name || DEFAULT_NAME}:${contextKey}`;
  return new Elysia({ name: "unjwt/elysia-jws", seed })
    .resolve({ as: "scoped" }, async ({ cookie, request }) => {
      const session = await createJWSSession<T, MaxAge, SessionContext>(
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
    update: async (update?: SessionUpdate<T>, options?: SessionIssueOptions) => {
      await updateSession(context, config, state, update, options);
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
  const token = readSessionToken(context, config.name || DEFAULT_NAME, config);
  if (!token) return;

  state.token = token;

  let exclusiveHookFired = false;
  try {
    const unsealed = await verifySession(context, config, token);
    Object.assign(state, unsealed);
  } catch (error_) {
    exclusiveHookFired = true;
    if (isJWTError(error_, "ERR_JWT_EXPIRED")) {
      state.token = undefined;
      dropSessionCookie(context, config);
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
  options?: SessionIssueOptions,
): Promise<void> {
  const oldSession: SessionJWS<T, MaxAge> = { ...state, data: sanitizeObjectCopy(state.data) };

  const resolvedUpdate = typeof update === "function" ? update(state.data) : update;
  if (resolvedUpdate) {
    Object.assign(state.data, sanitizeSessionUpdate(resolvedUpdate, { prefix: PREFIX }));
  }

  const maxAge = options?.maxAge ?? config.maxAge;
  const now = config.jws?.signOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  state.id = config.generateId?.() || crypto.randomUUID();
  state.createdAt = createdAt;
  state.expiresAt = resolveExpiresAt(createdAt, { maxAge }) as SessionJWS<T, MaxAge>["expiresAt"];

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
      expires: state.expiresAt === undefined ? undefined : new Date(state.expiresAt),
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

  dropSessionCookie(context, config);

  await config.hooks?.onClear?.({ oldSession, context, config });
}

async function signSession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(config: SessionConfigJWS<T, MaxAge, TContext>, state: SessionJWS<T, MaxAge>): Promise<string> {
  const key = getSignKey(config);

  const iat = Math.floor(state.createdAt / 1000);
  const exp = state.expiresAt ? Math.floor(state.expiresAt / 1000) : undefined;

  const payload: Record<string, any> = { ...state.data, jti: state.id, iat };
  if (exp) {
    payload.exp = exp;
  }

  return sign(payload as Record<string, unknown>, key as JWSSignJWK, {
    ...config.jws?.signOptions,
    expiresIn: undefined,
    protectedHeader: {
      ...config.jws?.signOptions?.protectedHeader,
      kid: "kid" in key ? key.kid : undefined,
      typ: sessionTyp(config.jws?.signOptions?.protectedHeader?.typ),
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
    : getVerifyKey(config);

  const { payload, protectedHeader } = await verify<T & { jti: string; iat: number }>(
    token,
    jwk as JWSVerifyJWK,
    {
      ...config.jws?.verifyOptions,
      requiredClaims: sessionRequiredClaims(config.jws?.verifyOptions?.requiredClaims, {
        maxAge: config.maxAge,
      }),
      typ: sessionTyp(config.jws?.signOptions?.protectedHeader?.typ),
      maxTokenAge: config.maxAge,
      algorithms: alg ? [alg] : undefined,
      forceUint8Array: false,
      validateClaims: true,
    },
  ).catch((error_: unknown) => rethrowAsInvalidToken(error_, { prefix: PREFIX }));

  assertSessionContentType(protectedHeader.cty, { prefix: PREFIX });

  const { jti, iat, exp, data } = splitSessionClaims(payload);
  return {
    id: jti,
    createdAt: iat * 1000,
    expiresAt: (exp ? exp * 1000 : undefined) as SessionJWS<T, MaxAge>["expiresAt"],
    data: data as SessionData<T>,
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
    expiresAt: resolveExpiresAt(createdAt, { maxAge: config.maxAge }) as SessionJWS<
      T,
      MaxAge
    >["expiresAt"],
    data: emptyData<T>(),
    token: undefined,
  };
}

function dropSessionCookie(context: SessionContext, config: SessionConfigJWS<any, any, any>): void {
  if (config.cookie === false) return;
  const { chunkMaxLength: _chunkMaxLength, ...attrs } = { ...DEFAULT_COOKIE, ...config.cookie };
  removeChunkedCookie(context.cookie, config.name || DEFAULT_NAME, attrs);
}

function getSignKey(config: SessionConfigJWS<any, any, any>): JWSSignJWK | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix: PREFIX });

  let _key: JWSSignJWK | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("privateKey" in key) {
    const privateKey = key.privateKey;
    if (isCryptoKey(privateKey) || isPrivateJWK(privateKey)) _key = privateKey;
  }

  if (!_key) {
    throw invalidKeyError(
      `${PREFIX} Invalid JWS key. It must be a symmetric JWK, a private JWK, or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlg(_key, config);
  return _key;
}

function getVerifyKey(config: SessionConfigJWS<any, any, any>): JWSVerifyJWK | JWKSet | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix: PREFIX });

  let _key: JWSVerifyJWK | JWKSet | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("publicKey" in key) {
    const publicKey = key.publicKey;
    if (isCryptoKey(publicKey)) {
      _key = publicKey;
    } else if (isPublicJWK(publicKey)) {
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
    throw invalidKeyError(
      `${PREFIX} Invalid JWS key. It must be a symmetric JWK, a public JWK/set, or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlg(_key, config);
  return _key;
}

function assertPinnedAlg(key: unknown, config: SessionConfigJWS<any, any, any>): void {
  if (isCryptoKey(key) && !config.jws?.signOptions?.alg) {
    throw invalidConfigError(
      `${PREFIX} A CryptoKey session key carries no algorithm: set "jws.signOptions.alg".`,
    );
  }
}
