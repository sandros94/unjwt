/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { ExpiresIn } from "../core/types";
import {
  type SessionTokenSource,
  assertRolling,
  assertSessionHeader,
  assertSessionName,
  assertTokenSource,
  invalidConfigError,
  resolveExpiresAt,
} from "./_session";
import type { SessionData, SessionRecord } from "./_session-types";

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

/** RFC 6265 cookie attributes plus the chunk size the token is split at. */
export interface SessionCookie {
  attrs: Record<string, unknown>;
  chunkMaxLength: number | undefined;
}

/** Where a framework keeps the session state of one request. */
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
    carrier: Record<string, unknown>,
  ) => (token: string) => Promise<OpenedSession>;
  open: (config: Config, token: string, carrier: Record<string, unknown>) => Promise<OpenedSession>;
}

/** What a session needs from the framework it serves. */
export interface SessionPort<TCarrier> {
  /** Message prefix for every error and warning the adapter emits. */
  prefix: string;
  /** The hook argument naming the request, e.g. `{ event }` or `{ context }`. */
  carrier: (carrier: TCarrier) => Record<string, unknown>;
  store: (carrier: TCarrier, slot: string) => SessionStore;
  readToken: (
    carrier: TCarrier,
    sessionName: string,
    source: SessionTokenSource,
  ) => string | undefined;
  /** Per-request object the session names bound during that request are registered under. */
  scope: (carrier: TCarrier) => object;
  /** Whether the response can still take a `Set-Cookie`. */
  writable: (carrier: TCarrier) => boolean;
  setCookie: (carrier: TCarrier, sessionName: string, token: string, cookie: SessionCookie) => void;
  deleteCookie: (carrier: TCarrier, sessionName: string, cookie: SessionCookie) => void;
}

/** The write side as the read path reaches it: the manager hooks receive, and the reissue `rolling` asks for. */
export interface SessionActions<TCarrier, Config extends SessionCoreConfig> {
  manager: (binding: SessionBinding<TCarrier, Config>) => object;
  roll: (binding: SessionBinding<TCarrier, Config>) => Promise<void>;
}

/** One session of one request: its config, its framework, its codec and its write side. */
export interface SessionBinding<TCarrier, Config extends SessionCoreConfig> {
  carrier: TCarrier;
  config: Config;
  port: SessionPort<TCarrier>;
  codec: SessionCodec<Config>;
  actions: SessionActions<TCarrier, Config>;
  /** Session name — drives the cookie name and the default session header. */
  name: string;
  args: Record<string, unknown>;
  store: SessionStore;
}

export function bindSession<TCarrier, Config extends SessionCoreConfig>(
  carrier: TCarrier,
  config: Config,
  options: {
    port: SessionPort<TCarrier>;
    codec: SessionCodec<Config>;
    actions: SessionActions<TCarrier, Config>;
  },
): SessionBinding<TCarrier, Config> {
  const { port, codec, actions } = options;
  const name = config.name || codec.defaultName;
  assertSessionName(name, { prefix: port.prefix });
  assertSessionHeader(config.sessionHeader, { prefix: port.prefix });
  assertRolling(config, { prefix: port.prefix });
  claimSessionName(port.scope(carrier), name, codec.family, port.prefix);
  return {
    carrier,
    config,
    port,
    codec,
    actions,
    name,
    args: port.carrier(carrier),
    store: port.store(carrier, `${codec.family}:${name}`),
  };
}

export function sessionToken<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
): string | undefined {
  assertTokenSource(binding.config, { prefix: binding.port.prefix });
  return binding.port.readToken(binding.carrier, binding.name, binding.config);
}

/** Session store over a per-request record, one slot per session. */
export function recordSlotStore(record: () => Record<string, unknown>, slot: string): SessionStore {
  return {
    get: () => record()[slot],
    set: (state) => {
      record()[slot] = state;
    },
  };
}

/** The codec's now, truncated to whole seconds as `iat` carries it. */
export function sessionInstant<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
): number {
  const now = binding.codec.now(binding.config);
  return now - (now % 1000);
}

export function mintSessionId(config: SessionCoreConfig): string {
  return config.generateId?.() || crypto.randomUUID();
}

export function emptySession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TCarrier,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TCarrier, Config>): SessionState<T, MaxAge> {
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
  options: { token: string; carrier: Record<string, unknown> },
): Promise<Partial<SessionState<T, MaxAge>>> {
  return codec.open(config, options.token, options.carrier).then(typedSession<T, MaxAge>);
}

/** An expiring token sets `expires` and drops `maxAge`, which would take precedence (RFC 6265 §5.3). */
export function sessionCookie<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
  options: { expiresAt?: number | undefined } = {},
): SessionCookie {
  const { chunkMaxLength, ...configured } = binding.config.cookie || {};
  const attrs: Record<string, unknown> = { ...binding.codec.defaultCookie, ...configured };
  if (options.expiresAt !== undefined) {
    attrs.expires = new Date(options.expiresAt);
    attrs.maxAge = undefined;
  }
  return { attrs, chunkMaxLength };
}

/** Drops an expired session's cookie; only warns when the response is no longer writable. */
export function dropSessionCookie<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
): void {
  const { config, port, carrier } = binding;
  if (config.cookie === false) return;
  if (!port.writable(carrier)) {
    console.warn(
      `${port.prefix} Session expired but cookie cannot be cleared on a read-only event.`,
    );
    return;
  }
  port.deleteCookie(carrier, binding.name, sessionCookie(binding));
}

const SESSION_NAMES = /* @__PURE__ */ new WeakMap<object, Map<string, "jws" | "jwe">>();

/** One name is one cookie: the first family to bind a name on a request holds it. */
function claimSessionName(
  scope: object,
  name: string,
  family: "jws" | "jwe",
  prefix: string,
): void {
  let registry = SESSION_NAMES.get(scope);
  if (!registry) {
    registry = new Map();
    SESSION_NAMES.set(scope, registry);
  }
  const holder = registry.get(name);
  if (holder === undefined) {
    registry.set(name, family);
    return;
  }
  if (holder === family) return;
  throw invalidConfigError(
    `${prefix} Session name "${name}" is already used by a ${holder.toUpperCase()} session on this request; a name is one cookie, so give this session a "name" of its own.`,
  );
}

function typedSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  state: unknown,
): SessionState<T, MaxAge> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- storage and codecs carry session state untyped
  return state as SessionState<T, MaxAge>;
}
