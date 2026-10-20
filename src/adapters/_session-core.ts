/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { ExpiresIn } from "../core/types/index.ts";
import type { SessionDriver } from "./_driver.ts";
import { resolveExpiresAt } from "./_session.ts";
import type { SessionData, SessionRecord } from "./_session-types.ts";
import type { SessionTokenSource, SessionTransport } from "./_transport.ts";

/** In-flight read of a session, awaited by a second reader on the same request. */
export const kSessionPending: unique symbol = Symbol("unjwt_session_pending");

/** In-request session state, mirroring the claims of the underlying token. */
export interface SessionState<T extends SessionRecord, MaxAge extends ExpiresIn | undefined> {
  /** JWT `jti`; `undefined` until the session is persisted. */
  id: string | undefined;
  /** In ms; mirrors the JWT `iat` claim (seconds). */
  createdAt: number;
  /** In ms; mirrors the JWT `exp` claim (seconds). */
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
  data: SessionData<T>;
  token: string | undefined;
  [kSessionPending]?: Promise<SessionState<T, MaxAge>>;
}

export type StoredSession = SessionState<SessionRecord, ExpiresIn | undefined>;

/** What a codec reads back from a token. */
export interface OpenedSession {
  id: string;
  createdAt: number;
  expiresAt: number | undefined;
  data: Record<string, unknown>;
}

/** Session state read back from a token: always carries its `id` and `createdAt`. */
export type OpenedSessionState<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
> = Pick<SessionState<T, MaxAge>, "id" | "createdAt" | "expiresAt" | "data"> & {
  id: string;
  createdAt: number;
};

/** Declared as methods so a family's hook can take a narrower argument type. */
export interface SessionCoreHooks {
  onRead?(args: Record<string, unknown>): void | Promise<void>;
  onUpdate?(args: Record<string, unknown>): void | Promise<void>;
  onClear?(args: Record<string, unknown>): void | Promise<void>;
  onExpire?(args: Record<string, unknown>): void | Promise<void>;
  onError?(args: Record<string, unknown>): void | Promise<void>;
}

export interface SessionCoreConfig extends SessionTokenSource {
  maxAge?: ExpiresIn;
  rolling?: true | ExpiresIn;
  name?: string;
  cookie?: false | { chunkMaxLength?: number };
  generateId?: () => string;
  hooks?: SessionCoreHooks;
}

/** One session's slot in the state of its request. */
export interface SessionStore {
  get: () => unknown;
  set: (state: object) => void;
}

/** How a session is issued and read: signed (JWS) or encrypted (JWE). */
export interface SessionCodec<Config extends SessionCoreConfig> {
  /** Keeps a JWS and a JWE session that share a `name` apart. */
  family: "jws" | "jwe";
  defaultName: string;
  defaultCookie: Record<string, unknown>;
  now: (config: Config) => number;
  /** Resolves the issuing key before any session is read; returns the bound issuer. */
  issuer: (config: Config) => (state: StoredSession) => Promise<string>;
  /** Imports every configured key, once per key object; throws `ERR_SESSION_KEY_INVALID` for an unusable one. */
  assertKeys: (config: Config) => Promise<void>;
  /** Resolves the opening key before the token is read (a missing key is a config error); returns the bound opener. */
  opener: (
    config: Config,
    args: Record<string, unknown>,
  ) => (token: string) => Promise<OpenedSession>;
  open: (config: Config, token: string, args: Record<string, unknown>) => Promise<OpenedSession>;
}

/** The write side as the read path reaches it: the manager hooks receive, and the reissue `rolling` asks for. */
export interface SessionActions<TContext, Config extends SessionCoreConfig> {
  manager: (binding: SessionBinding<TContext, Config>) => object;
  roll: (binding: SessionBinding<TContext, Config>) => Promise<void>;
}

/** One session of one request: its config, its framework, its codec, its write side and its token transport. */
export interface SessionBinding<TContext, Config extends SessionCoreConfig> {
  context: TContext;
  config: Config;
  driver: SessionDriver<TContext>;
  codec: SessionCodec<Config>;
  actions: SessionActions<TContext, Config>;
  /** Session name — drives the cookie name and the default session header. */
  name: string;
  /** The hook argument naming the request. */
  args: Record<string, unknown>;
  store: SessionStore;
  transport: SessionTransport;
}

/** The codec's now, truncated to whole seconds as `iat` carries it. */
export function sessionInstant<Config extends SessionCoreConfig>(source: {
  codec: SessionCodec<Config>;
  config: Config;
}): number {
  const now = source.codec.now(source.config);
  return now - (now % 1000);
}

export function mintSessionId(config: SessionCoreConfig): string {
  return config.generateId?.() || crypto.randomUUID();
}

export function emptySession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TContext,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TContext, Config>): SessionState<T, MaxAge> {
  const createdAt = sessionInstant(binding);
  return typedSession<T, MaxAge>({
    id: undefined,
    createdAt,
    expiresAt: resolveExpiresAt(createdAt, { maxAge: binding.config.maxAge }),
    data: Object.create(null),
    token: undefined,
  });
}

export function storedSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  store: SessionStore,
): SessionState<T, MaxAge> | undefined {
  const state = store.get();
  return state === undefined ? undefined : typedSession<T, MaxAge>(state);
}

export function blankSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(): Pick<
  SessionState<T, MaxAge>,
  "expiresAt" | "data"
> {
  return typedSession<T, MaxAge>({ expiresAt: undefined, data: {} });
}

export function openSessionToken<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  Config extends SessionCoreConfig,
>(
  codec: SessionCodec<Config>,
  config: Config,
  options: { token: string; args: Record<string, unknown> },
): Promise<OpenedSessionState<T, MaxAge>> {
  return codec.open(config, options.token, options.args).then(typedOpened<T, MaxAge>);
}

function typedSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  state: unknown,
): SessionState<T, MaxAge> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- storage and codecs carry session state untyped
  return state as SessionState<T, MaxAge>;
}

function typedOpened<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  opened: OpenedSession,
): OpenedSessionState<T, MaxAge> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- codecs carry session data untyped
  return opened as OpenedSessionState<T, MaxAge>;
}
