import type { ExpiresIn } from "../core/types/index.ts";
import type { kSessionPending } from "./_core.ts";
import type { SessionDriver } from "./_driver.ts";
import type { SessionTokenSource, SessionTransport } from "./_transport.ts";
import type { SessionRecord, SessionState } from "./types.ts";

/** Session state with the in-flight read a second reader on the same request awaits. */
export type PendingSession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
> = SessionState<T, MaxAge> & {
  [kSessionPending]?: Promise<SessionState<T, MaxAge>>;
};

export type StoredSession = PendingSession<SessionRecord, ExpiresIn | undefined>;

/** What a codec reads back from a token. */
export interface OpenedSession {
  id: string;
  createdAt: number;
  expiresAt: number | undefined;
  data: Record<string, unknown>;
}

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
