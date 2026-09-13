/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { H3Event } from "h3v1";

import type { CookieSerializeOptions } from "cookie-esv1";

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
import { encrypt, decrypt, isJWTError } from "../../../core/jwe";
import { isCryptoKey, isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../../../core/utils";
import { sanitizeObjectCopy } from "unsecure/sanitize";
import {
  type SessionIssueOptions,
  assertKeyMaterial,
  assertSessionContentType,
  expiredSessionError,
  invalidConfigError,
  invalidKeyError,
  readOnlyEventError,
  resolveExpiresAt,
  rethrowAsInvalidToken,
  sanitizeSessionUpdate,
  sessionRequiredClaims,
  sessionTyp,
  splitSessionClaims,
} from "../../_session";
import { setChunkedCookie, deleteChunkedCookie } from "../_cookie";
import type { SessionClaims, SessionData, SessionUpdate, SessionManager } from "./types";
import {
  type CompatEvent,
  PREFIX,
  getSessionsContext,
  hasWritableResponse,
  readSessionToken,
  sessionSlot,
} from "./_shared";

const kGetSessionPromise: unique symbol = Symbol("h3_jwe_getSession");

/**
 * In-memory session state for the current request, mirroring the claims of
 * the underlying compact JWE token.
 */
export interface SessionJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> {
  /** Session ID — mirrors the JWT `jti` claim. `undefined` until the session is persisted. */
  id: string | undefined;
  /** Session creation time in ms — mirrors the JWT `iat` claim (seconds). */
  createdAt: number;
  /** Session expiry time in ms — mirrors the JWT `exp` claim (seconds). */
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
  /** Session data — carried in the token payload, spread at the top level. */
  data: SessionData<T>;
  /** The current compact JWE token. `undefined` until the session is persisted. */
  token: string | undefined;
  [kGetSessionPromise]?: Promise<SessionJWE<T, MaxAge>>;
}

/**
 * Lifecycle hooks for JWE sessions. `onRead`, `onExpire`, and `onError` are
 * mutually exclusive per incoming token — `onRead` fires only when a session
 * was successfully established from it.
 */
export interface SessionHooksJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> {
  /**
   * Fires when an incoming token was decrypted and the session established.
   * May fire more than once per request when `useJWESession` is called
   * concurrently in the same handler — dedupe via `session.id` if needed.
   */
  onRead?: (args: {
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Fires after a new token was sealed — including pure token refreshes (update with no data). */
  onUpdate?: (args: {
    /** Session after the update. */
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    /** Deep-copied snapshot of the session before the update. */
    oldSession: SessionJWE<T, MaxAge>;
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Fires when the session is cleared. */
  onClear?: (args: {
    /** Last known session before clearing, if any. */
    oldSession: SessionJWE<T, MaxAge> | undefined;
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Fires when the incoming token is expired. Receives the expired token's decoded claims. */
  onExpire?: (args: {
    session: {
      id: string | undefined;
      createdAt: number | undefined;
      expiresAt: number | undefined;
      token: string;
    };
    event: TEvent;
    error: Error;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Fires on read-path failures other than expiry, and on write-path seal failures. */
  onError?: (args: {
    /**
     * The session involved in the error.
     */
    session: SessionJWE<T, MaxAge>;
    event: TEvent;
    error: any;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => void | Promise<void>;
  /** Resolve the decryption key for the incoming token from its protected header (e.g. by `kid`). */
  onUnsealKeyLookup?: (args: {
    header: JWEHeaderParameters;
    event: TEvent;
    config: SessionConfigJWE<T, MaxAge, TEvent>;
  }) => JWEDecryptJWK | Promise<JWEDecryptJWK>;
}

/** JWE decrypt overrides a session accepts — everything the adapter does not own itself. */
export type SessionDecryptOptions = StrictOmit<
  JWEDecryptOptions,
  "algorithms" | "encryptionAlgorithms" | "typ" | "validateClaims" | "forceUint8Array"
>;

/**
 * Configuration for a JWE-backed (encrypted) session.
 */
export interface SessionConfigJWE<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
> {
  /**
   * Key used for sealing — a symmetric JWK, a `CryptoKey`, or an asymmetric
   * pair: the public key seals, the private key unseals. A `CryptoKey` carries
   * no algorithm, so it additionally requires `jwe.encryptOptions.alg` and
   * `enc`. Passwords are not keys — derive one once with
   * `deriveJWKFromPassword()` and pass the JWK.
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
   * of an incoming token, and drives the cookie expiry. Without it the session
   * writes no `exp` and never expires on its own.
   */
  maxAge?: MaxAge;
  /** Session name — drives the cookie name and the default session header. Default `"h3-jwe"`. */
  name?: string;
  /** Cookie options (`false` to disable). Defaults: `path="/"`, `secure`, `sameSite: "lax"`, `httpOnly: true`. */
  cookie?: false | (CookieSerializeOptions & { chunkMaxLength?: number });
  /** Request header to read the token from (`false` to disable). Default `x-<name>-session`. */
  sessionHeader?: false | string;
  /** Session ID (`jti`) generator. Default `crypto.randomUUID`. */
  generateId?: () => string;
  /** JWE encrypt/decrypt overrides. Set `encryptOptions.alg` and `enc` to pin the session algorithms — unsealing then accepts only them. */
  jwe?: {
    encryptOptions?: Omit<JWEEncryptOptions, "expiresIn">;
    decryptOptions?: SessionDecryptOptions;
  };
  /** Lifecycle hooks — see {@link SessionHooksJWE}. */
  hooks?: SessionHooksJWE<T, MaxAge, TEvent>;
}

const DEFAULT_NAME = "h3-jwe";
const DEFAULT_COOKIE: SessionConfigJWE["cookie"] = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
};

/**
 * Create a session manager for the current request using JWE (encrypted).
 */
export async function useJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionManager<T, MaxAge>> {
  const slot = sessionSlot("jwe", config.name || DEFAULT_NAME);
  await getJWESession(event, config);

  const sessionManager: SessionManager<T, MaxAge> = {
    get id() {
      return (event.context.sessions?.[slot] as SessionJWE<T, MaxAge> | undefined)?.id;
    },
    get createdAt() {
      return (
        (event.context.sessions?.[slot] as SessionJWE<T, MaxAge> | undefined)?.createdAt ??
        Date.now()
      );
    },
    get expiresAt() {
      return (event.context.sessions?.[slot] as SessionJWE<T, MaxAge> | undefined)
        ?.expiresAt as SessionManager<T, MaxAge>["expiresAt"];
    },
    get data() {
      return ((event.context.sessions?.[slot] as SessionJWE<T, MaxAge> | undefined)?.data ||
        {}) as T;
    },
    get token() {
      const session = event.context.sessions?.[slot] as SessionJWE<T, MaxAge> | undefined;
      return session ? session.token : getJWESessionToken(event, config);
    },
    update: async (update?: SessionUpdate<T>, options?: SessionIssueOptions) => {
      await updateJWESession(event, config, update, options);
      return sessionManager as Awaited<ReturnType<SessionManager<T, MaxAge>["update"]>>;
    },
    clear: async () => {
      await clearJWESession(event, config);
      return sessionManager as Awaited<ReturnType<SessionManager<T, MaxAge>["clear"]>>;
    },
  };

  return sessionManager;
}

/**
 * Get (and lazily initialize) the session for the current request.
 */
export async function getJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<SessionJWE<T, MaxAge>> {
  const sessionName = config.name || DEFAULT_NAME;
  const slot = sessionSlot("jwe", sessionName);

  const sessions = getSessionsContext(event);

  const existingSession = sessions[slot] as SessionJWE<T, MaxAge> | undefined;
  if (existingSession) {
    const session = existingSession[kGetSessionPromise]
      ? await existingSession[kGetSessionPromise]
      : existingSession;

    /**
     * We check if a session is expired before returning it. If it is expired we clear it and create a new one,
     * unless we have a read-only event in which case we just return it as it was valid at the time of reading
     * the cookie/header (like in a websocket upgrade)
     */
    if (session.expiresAt !== undefined && session.expiresAt < Date.now()) {
      await config.hooks?.onExpire?.({
        session: {
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          token: session.token!,
        },
        event,
        error: expiredSessionError({ id: session.id, expiresAt: session.expiresAt }),
        config,
      });
      dropSessionCookie(event, sessionName, config);
      const freshSession = emptySession<T, MaxAge>(config);
      sessions[slot] = freshSession;
      return freshSession;
    }

    if (session.id !== undefined && session.token !== undefined) {
      await config.hooks?.onRead?.({
        session: session as SessionJWE<T, MaxAge> & { id: string; token: string },
        event,
        config,
      });
    }
    return session;
  }

  const session = emptySession<T, MaxAge>(config);
  sessions[slot] = session;

  const token = getJWESessionToken(event, config);

  let exclusiveHookFired = false;
  if (token) {
    session.token = token;
    const promise = unsealJWESession(event, config, token)
      .catch(async (error_) => {
        exclusiveHookFired = true;
        if (isJWTError(error_, "ERR_JWT_EXPIRED")) {
          session.token = undefined;
          dropSessionCookie(event, sessionName, config);
          await config.hooks?.onExpire?.({
            session: {
              id: error_.cause.jti,
              createdAt: error_.cause.iat ? error_.cause.iat * 1000 : undefined,
              expiresAt: error_.cause.exp ? error_.cause.exp * 1000 : undefined,
              token,
            },
            event,
            error: error_,
            config,
          });
        } else {
          await config.hooks?.onError?.({
            session,
            event,
            error: error_,
            config,
          });
        }
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

  if (!exclusiveHookFired && session.id !== undefined && session.token !== undefined) {
    await config.hooks?.onRead?.({
      session: session as SessionJWE<T, MaxAge> & { id: string; token: string },
      event,
      config,
    });
  }
  return session;
}

/**
 * Read the raw session token for the request. The cookie is consulted first,
 * and the session header (default `x-<name>-session`, optional case-insensitive
 * `Bearer` prefix) only when the cookie carries none.
 */
export function getJWESessionToken<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): string | undefined {
  return readSessionToken(event, config.name || DEFAULT_NAME, config);
}

/**
 * Update the session data (if provided) and reissue the JWE token.
 * Pass `options.maxAge` to give this one token a lifetime of its own.
 */
export async function updateJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
  update?: SessionUpdate<T>,
  options?: SessionIssueOptions,
): Promise<SessionJWE<T, MaxAge>> {
  const canWriteCookie = hasWritableResponse(event);
  if (config.cookie !== false && !canWriteCookie) {
    throw readOnlyEventError(`${PREFIX} Cannot update session on read-only event.`);
  }

  const sessionName = config.name || DEFAULT_NAME;
  const slot = sessionSlot("jwe", sessionName);

  const session: SessionJWE<T, MaxAge> & { id: string; token: string } =
    (event.context.sessions?.[slot] as SessionJWE<T, MaxAge> & { id: string; token: string }) ||
    (await getJWESession(event, config));

  // Snapshot before the updater runs, with a deep copy of `data`, so
  // `oldSession` is a true "before" state for hook diffing and rollback.
  const oldSession = { ...session, data: sanitizeObjectCopy(session.data) };

  const resolved = typeof update === "function" ? update(session.data) : update;
  if (resolved) {
    Object.assign(session.data, sanitizeSessionUpdate(resolved, { prefix: PREFIX }));
  }

  const maxAge = options?.maxAge ?? config.maxAge;
  const now = config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now();
  const createdAt = now - (now % 1000);
  Object.assign(session, {
    id: config.generateId?.() || crypto.randomUUID(),
    createdAt,
    expiresAt: resolveExpiresAt(createdAt, { maxAge }),
  });

  // Always seal into a token and cache it so `session.token` stays accurate even
  // when cookies are disabled or the response is not writable.
  let sealed: string;
  try {
    sealed = await sealJWESession(event, config);
  } catch (error_) {
    Object.assign(session, {
      id: oldSession.id,
      createdAt: oldSession.createdAt,
      expiresAt: oldSession.expiresAt,
      data: oldSession.data,
    });
    session.token = oldSession.token;
    await config.hooks?.onError?.({ session, event, error: error_, config });
    throw error_;
  }
  session.token = sealed;

  if (config.cookie !== false && canWriteCookie) {
    setChunkedCookie(event as H3Event, sessionName, sealed, {
      ...DEFAULT_COOKIE,
      ...config.cookie,
      expires: session.expiresAt === undefined ? undefined : new Date(session.expiresAt),
    });
  }

  // Fires after sealing so the hook receives the definitive new token, jti, and
  // timestamps. Also fires on pure token refresh (update is undefined).
  await config.hooks?.onUpdate?.({
    session,
    oldSession,
    event,
    config,
  });

  return session;
}

/**
 * Seal the current session as a compact JWE.
 * Payload: `session.data` spread at the top level, plus the reserved claims
 * `jti`, `iat`, and `exp` (when the session has a lifetime).
 */
export async function sealJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<string> {
  const key = getEncryptKey(config);
  const slot = sessionSlot("jwe", config.name || DEFAULT_NAME);

  const session: SessionJWE<T, MaxAge> =
    (event.context.sessions?.[slot] as SessionJWE<T, MaxAge>) ||
    (await getJWESession(event, config));

  const iat = Math.floor(session.createdAt / 1000);
  const exp = session.expiresAt ? Math.floor(session.expiresAt / 1000) : undefined;

  const payload: Record<string, any> = {
    ...session.data,
    jti: session.id,
    iat,
  };
  if (exp) {
    payload.exp = exp;
  }

  return encrypt(payload as Record<string, unknown>, key as JWEEncryptJWK, {
    ...config.jwe?.encryptOptions,
    // `exp` is computed from the session lifetime and carried via the claim above.
    expiresIn: undefined,
    protectedHeader: {
      ...config.jwe?.encryptOptions?.protectedHeader,
      typ: sessionTyp(config.jwe?.encryptOptions?.protectedHeader?.typ),
      cty: "application/json",
    },
  });
}

/**
 * Decrypt and parse a compact JWE into a Session structure.
 * Performs:
 *  - authenticated decryption
 *  - claim validation (always on): `jti` & `iat` required, `exp` honoured
 *  - `typ` and `cty` header checks, and alg/enc pinning when configured
 *  - `maxAge` enforced as `maxTokenAge`, and `exp` required alongside it
 */
export async function unsealJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(
  event: TEvent,
  config: SessionConfigJWE<T, MaxAge, TEvent>,
  sealed: string,
): Promise<Partial<SessionJWE<T, MaxAge>>> {
  const key = config.hooks?.onUnsealKeyLookup
    ? (header: JWEHeaderParameters) =>
        config.hooks!.onUnsealKeyLookup!({
          header,
          event,
          config,
        })
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

/**
 * Clear the session: drop the cookie and leave an empty session behind, so a
 * later read in the same request sees no session rather than the request cookie.
 */
export async function clearJWESession<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TEvent extends CompatEvent | H3Event = CompatEvent | H3Event,
>(event: TEvent, config: SessionConfigJWE<T, MaxAge, TEvent>): Promise<void> {
  const canWriteCookie = hasWritableResponse(event);
  if (config.cookie !== false && !canWriteCookie) {
    throw readOnlyEventError(`${PREFIX} Cannot clear session on read-only event.`);
  }

  const sessionName = config.name || DEFAULT_NAME;
  const slot = sessionSlot("jwe", sessionName);
  const sessions = getSessionsContext(event);

  let session = sessions[slot] as SessionJWE<T, MaxAge> | undefined;
  if (session && session[kGetSessionPromise]) {
    session = await session[kGetSessionPromise];
  }
  const oldSession =
    session && (session.id !== undefined || session.token !== undefined)
      ? { ...session, data: sanitizeObjectCopy(session.data) }
      : undefined;

  sessions[slot] = emptySession<T, MaxAge>(config);

  if (config.cookie !== false && canWriteCookie) {
    deleteChunkedCookie(event as H3Event, sessionName, { ...DEFAULT_COOKIE, ...config.cookie });
  }

  await config.hooks?.onClear?.({
    oldSession,
    event,
    config,
  });
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
    data: Object.create(null),
    token: undefined,
  };
}

function dropSessionCookie(
  event: CompatEvent | H3Event,
  sessionName: string,
  config: SessionConfigJWE<any, any, any>,
): void {
  if (config.cookie === false) return;
  if (!hasWritableResponse(event)) {
    console.warn(`${PREFIX} Session expired but cookie cannot be cleared on a read-only event.`);
    return;
  }
  deleteChunkedCookie(event, sessionName, { ...DEFAULT_COOKIE, ...config.cookie });
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
    // Fall back to the private JWK — `encrypt` accepts a symmetric oct here or
    // extracts the public parts internally when the caller has no public half.
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
