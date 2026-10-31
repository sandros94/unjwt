import type { ExpiresIn } from "../../core/types/index.ts";
import type { kSessionPending } from "./core.ts";
import type { SessionDriver } from "./driver.ts";
import type { SessionTokenSource, SessionTransport } from "./transport.ts";
import type { SessionRecord, SessionState } from "../types.ts";

/** Session state with the pending read that a second reader on the same request awaits. */
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

/** Declared as methods, so a family's hook can take a narrower argument type. */
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

/** The token one session's transport holds on its request, `undefined` until a read or a write sets it. */
export interface HeldToken {
  get: () => { token: string | undefined } | undefined;
  set: (token: string | undefined) => void;
}

/** How a session is issued and read: signed (JWS) or encrypted (JWE). */
export interface SessionCodec<Config extends SessionCoreConfig> {
  /** Keeps a JWS and a JWE session that share a `name` apart. */
  family: "jws" | "jwe";
  defaultName: string;
  defaultCookie: Record<string, unknown>;
  now: (config: Config) => number;
  /** Resolves the configured keys once. Throws `ERR_SESSION_KEY_INVALID` or `ERR_SESSION_CONFIG_INVALID` for a key the session cannot use. */
  keys: (config: Config) => SessionKeys;
}

/** The resolved keys of one config, which issue and open its tokens. */
export interface SessionKeys {
  /** Imports every configured key, once per key object. Throws `ERR_SESSION_KEY_INVALID` for an unusable one. */
  assertKeys: () => Promise<void>;
  issue: (state: StoredSession) => Promise<string>;
  /** The opener of one request, whose key lookup gets that request's hook arguments. */
  opener: (args: Record<string, unknown>) => (token: string) => Promise<OpenedSession>;
  /** Imports the opening keys, then opens. */
  open: (token: string, args: Record<string, unknown>) => Promise<OpenedSession>;
}

/** The write side the read path calls: the manager hooks receive, and the reissue `rolling` asks for. */
export interface SessionActions<TEvent, Config extends SessionCoreConfig> {
  manager: (binding: SessionBinding<TEvent, Config>) => object;
  roll: (binding: SessionBinding<TEvent, Config>) => Promise<void>;
}

/** One session of one request: its config, driver, codec, write side and token transport. */
export interface SessionBinding<TEvent, Config extends SessionCoreConfig> {
  event: TEvent;
  config: Config;
  driver: SessionDriver<TEvent>;
  codec: SessionCodec<Config>;
  keys: SessionKeys;
  actions: SessionActions<TEvent, Config>;
  /** Session name, used as the cookie name and the base of the default session header. */
  name: string;
  /** The request as every hook receives it. */
  args: { event: TEvent };
  store: SessionStore;
  /** The token the transport read, then the one `update()` issued or none after `clear()`. A failed read leaves it as read. */
  held: HeldToken;
  transport: SessionTransport;
}
