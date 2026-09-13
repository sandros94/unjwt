import type {
  ExpiresIn,
  JWEEncryptJWK,
  JWEDecryptJWK,
  JWEDecryptOptions,
  JWEAsymmetricPublicJWK,
  JWEAsymmetricPrivateJWK,
  JWEEncryptOptions,
  JWEHeaderParameters,
} from "../../../core/types";
import type { StrictOmit } from "../../../core/utils/types";
import { Elysia } from "elysia";
import { encrypt, decrypt, isJWTError } from "../../../core/jwe";
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

export interface SessionJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  id: string | undefined;
  createdAt: number;
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
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

/** JWE decrypt overrides a session accepts — everything the adapter does not own itself. */
export type SessionDecryptOptions = StrictOmit<
  JWEDecryptOptions,
  "algorithms" | "encryptionAlgorithms" | "typ" | "validateClaims" | "forceUint8Array"
>;

export interface SessionConfigJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TContext extends SessionContext = SessionContext,
> {
  /**
   * Key used for sealing — a symmetric JWK, a `CryptoKey`, or an asymmetric
   * pair. A `CryptoKey` carries no algorithm, so it additionally requires
   * `jwe.encryptOptions.alg` and `enc`. Passwords are not keys — derive one
   * once with `deriveJWKFromPassword()` and pass the JWK.
   */
  key:
    | CryptoKey
    | JWEEncryptJWK
    | {
        privateKey: JWEAsymmetricPrivateJWK | CryptoKey;
        publicKey?: JWEAsymmetricPublicJWK | CryptoKey;
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
  jwe?: {
    encryptOptions?: Omit<JWEEncryptOptions, "expiresIn">;
    decryptOptions?: SessionDecryptOptions;
  };
  hooks?: SessionHooksJWE<T, MaxAge, TContext>;
}

const DEFAULT_NAME = "elysia-jwe";
const DEFAULT_COOKIE: CookieAttributes = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
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
  // The seed carries the session name as well as the context key, so two
  // differently-named sessions register as two plugins rather than one.
  const seed = `${config.name || DEFAULT_NAME}:${contextKey}`;
  return new Elysia({ name: "unjwt/elysia-jwe", seed })
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
  config: SessionConfigJWE<T, MaxAge, TContext>,
  state: SessionJWE<T, MaxAge>,
): Promise<void> {
  const token = readSessionToken(context, config.name || DEFAULT_NAME, config);
  if (!token) return;

  state.token = token;

  let exclusiveHookFired = false;
  try {
    const unsealed = await unsealSession(context, config, token);
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
  options?: SessionIssueOptions,
): Promise<void> {
  const oldSession: SessionJWE<T, MaxAge> = { ...state, data: sanitizeObjectCopy(state.data) };

  const resolvedUpdate = typeof update === "function" ? update(state.data) : update;
  if (resolvedUpdate) {
    Object.assign(state.data, sanitizeSessionUpdate(resolvedUpdate, { prefix: PREFIX }));
  }

  const maxAge = options?.maxAge ?? config.maxAge;
  const now = config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  state.id = config.generateId?.() || crypto.randomUUID();
  state.createdAt = createdAt;
  state.expiresAt = resolveExpiresAt(createdAt, { maxAge }) as SessionJWE<T, MaxAge>["expiresAt"];

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
      expires: state.expiresAt === undefined ? undefined : new Date(state.expiresAt),
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

  dropSessionCookie(context, config);

  await config.hooks?.onClear?.({ oldSession, context, config });
}

async function sealSession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TContext extends SessionContext,
>(config: SessionConfigJWE<T, MaxAge, TContext>, state: SessionJWE<T, MaxAge>): Promise<string> {
  const key = getEncryptKey(config);

  const iat = Math.floor(state.createdAt / 1000);
  const exp = state.expiresAt ? Math.floor(state.expiresAt / 1000) : undefined;

  const payload: Record<string, any> = { ...state.data, jti: state.id, iat };
  if (exp) {
    payload.exp = exp;
  }

  return encrypt(payload as Record<string, unknown>, key as JWEEncryptJWK, {
    ...config.jwe?.encryptOptions,
    expiresIn: undefined,
    protectedHeader: {
      ...config.jwe?.encryptOptions?.protectedHeader,
      typ: sessionTyp(config.jwe?.encryptOptions?.protectedHeader?.typ),
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
    : getDecryptKey(config);

  const alg = config.jwe?.encryptOptions?.alg;
  const enc = config.jwe?.encryptOptions?.enc;

  const { payload, protectedHeader } = await decrypt<T & { jti: string; iat: number }>(
    sealed,
    key as JWEDecryptJWK,
    {
      ...config.jwe?.decryptOptions,
      maxIterations: sessionMaxIterations(config),
      requiredClaims: sessionRequiredClaims(config.jwe?.decryptOptions?.requiredClaims, {
        maxAge: config.maxAge,
      }),
      typ: sessionTyp(config.jwe?.encryptOptions?.protectedHeader?.typ),
      maxTokenAge: config.maxAge,
      algorithms: alg ? [alg] : undefined,
      encryptionAlgorithms: enc ? [enc] : undefined,
      forceUint8Array: false,
      validateClaims: true,
    },
  ).catch((error_: unknown) => rethrowAsInvalidToken(error_, { prefix: PREFIX }));

  assertSessionContentType(protectedHeader.cty, { prefix: PREFIX });

  const { jti, iat, exp, data } = splitSessionClaims(payload);
  return {
    id: jti,
    createdAt: iat * 1000,
    expiresAt: (exp ? exp * 1000 : undefined) as SessionJWE<T, MaxAge>["expiresAt"],
    data: data as SessionData<T>,
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
    expiresAt: resolveExpiresAt(createdAt, { maxAge: config.maxAge }) as SessionJWE<
      T,
      MaxAge
    >["expiresAt"],
    data: emptyData<T>(),
    token: undefined,
  };
}

function dropSessionCookie(context: SessionContext, config: SessionConfigJWE<any, any, any>): void {
  if (config.cookie === false) return;
  const { chunkMaxLength: _chunkMaxLength, ...attrs } = { ...DEFAULT_COOKIE, ...config.cookie };
  removeChunkedCookie(context.cookie, config.name || DEFAULT_NAME, attrs);
}

/**
 * PBES2 unwrap accepts at most the `p2c` the session itself mints, so a token
 * that pins a pinned-algorithm session to a costlier iteration count is refused.
 */
function sessionMaxIterations(config: SessionConfigJWE<any, any, any>): number | undefined {
  const configured = config.jwe?.decryptOptions?.maxIterations;
  if (configured !== undefined) return configured;
  const alg = config.jwe?.encryptOptions?.alg;
  return typeof alg === "string" && alg.startsWith("PBES2")
    ? config.jwe?.encryptOptions?.p2c
    : undefined;
}

function getEncryptKey(config: SessionConfigJWE<any, any, any>): JWEEncryptJWK | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix: PREFIX });

  let _key: JWEEncryptJWK | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key as JWEEncryptJWK;
  } else if ("publicKey" in key && key.publicKey) {
    const publicKey = key.publicKey;
    if (isCryptoKey(publicKey) || isPublicJWK(publicKey)) _key = publicKey as JWEEncryptJWK;
  }
  if (!_key && "privateKey" in key) {
    const privateKey = key.privateKey;
    if (isCryptoKey(privateKey) || isPrivateJWK(privateKey)) {
      _key = privateKey as unknown as JWEEncryptJWK;
    }
  }

  if (!_key) {
    throw invalidKeyError(`${PREFIX} Invalid JWE key. It must be a JWK or a CryptoKey.`, key);
  }

  assertPinnedAlgEnc(_key, config);
  return _key;
}

function getDecryptKey(config: SessionConfigJWE<any, any, any>): JWEDecryptJWK | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix: PREFIX });

  let _key: JWEDecryptJWK | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key as JWEDecryptJWK;
  } else if ("privateKey" in key) {
    _key = key.privateKey as JWEAsymmetricPrivateJWK;
  }

  if (!_key) {
    throw invalidKeyError(
      `${PREFIX} Invalid JWE key. It must be a JWK, a private JWK, or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlgEnc(_key, config);
  return _key;
}

function assertPinnedAlgEnc(key: unknown, config: SessionConfigJWE<any, any, any>): void {
  if (!isCryptoKey(key)) return;
  if (!config.jwe?.encryptOptions?.alg || !config.jwe?.encryptOptions?.enc) {
    throw invalidConfigError(
      `${PREFIX} A CryptoKey session key carries no algorithm: set "jwe.encryptOptions.alg" and "enc".`,
    );
  }
}
