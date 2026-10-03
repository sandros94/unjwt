/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { ExpiresIn } from "../core/types";
import {
  type SessionTokenSource,
  assertSessionName,
  assertTokenSource,
  invalidConfigError,
  resolveExpiresAt,
} from "./_session";
import type { SessionData } from "./_session-types";

/**
 * Holds the in-flight read of a session, so a second reader on the same
 * request awaits that read instead of starting its own.
 */
export const kSessionPending: unique symbol = Symbol("unjwt_session_pending");

/** In-request session state, mirroring the claims of the underlying token. */
export interface SessionState<T extends Record<string, any>, MaxAge extends ExpiresIn | undefined> {
  /** Session ID — mirrors the JWT `jti` claim. `undefined` until the session is persisted. */
  id: string | undefined;
  /** Session creation time in ms — mirrors the JWT `iat` claim (seconds). */
  createdAt: number;
  /** Session expiry time in ms — mirrors the JWT `exp` claim (seconds). */
  expiresAt: MaxAge extends ExpiresIn ? number : number | undefined;
  /** Session data — carried in the token payload, spread at the top level. */
  data: SessionData<T>;
  /** The current compact token. `undefined` until the session is persisted. */
  token: string | undefined;
  [kSessionPending]?: Promise<SessionState<T, MaxAge>>;
}

type SessionHook = (args: any) => void | Promise<void>;

/** The hooks the core dispatches, whatever argument types a family declares. */
export interface SessionCoreHooks {
  onRead?: SessionHook;
  onUpdate?: SessionHook;
  onClear?: SessionHook;
  onExpire?: SessionHook;
  onError?: SessionHook;
}

/** The parts of a session config the core reads, whatever family declares them. */
export interface SessionCoreConfig extends SessionTokenSource {
  maxAge?: ExpiresIn;
  name?: string;
  generateId?: () => string;
  hooks?: SessionCoreHooks;
}

/** Cookie attributes a write starts from: the family's defaults plus the config's. */
export interface SessionCookieOptions {
  defaults: Record<string, unknown>;
  cookie: object | undefined;
}

/** Where a framework keeps the session state of one request. */
export interface SessionStore {
  get: () => SessionState<any, any> | undefined;
  set: (state: SessionState<any, any>) => void;
}

/** How a session is issued and read: signed (JWS) or encrypted (JWE). */
export interface SessionCodec<Config extends SessionCoreConfig> {
  /** Keeps a JWS and a JWE session that share a `name` apart. */
  family: "jws" | "jwe";
  defaultName: string;
  defaultCookie: Record<string, unknown>;
  /** The instant the session treats as now. */
  now: (config: Config) => number;
  /** The key a new token is issued with, resolved before any session is read. */
  issueKey: (config: Config) => unknown;
  /**
   * Resolve and import every key the config supplies, raising
   * `ERR_SESSION_KEY_INVALID` for one the session cannot use.
   */
  assertKeys: (config: Config) => Promise<void>;
  /**
   * The key an incoming token is opened with — resolved before the token is
   * read, so a key the config cannot supply is a configuration failure rather
   * than an unreadable token.
   */
  openKey: (config: Config, carrier: Record<string, unknown>) => unknown;
  issue: (config: Config, state: SessionState<any, any>, key: unknown) => Promise<string>;
  open: (
    config: Config,
    token: string,
    carrier: Record<string, unknown>,
    key?: unknown,
  ) => Promise<Partial<SessionState<any, any>>>;
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
  /**
   * The object that stands for one request, under which the session names bound
   * during it are registered. Framework-owned and reached from any binding of
   * that request, however many sessions it opens.
   */
  scope: (carrier: TCarrier) => object;
  /** Whether the response can still take a `Set-Cookie`. */
  writable: (carrier: TCarrier) => boolean;
  setCookie: (
    carrier: TCarrier,
    sessionName: string,
    token: string,
    options: SessionCookieOptions & { expiresAt: number | undefined },
  ) => void;
  deleteCookie: (carrier: TCarrier, sessionName: string, options: SessionCookieOptions) => void;
  /** Drop the cookie of a session that expired, warning when it cannot be written. */
  dropCookie: (carrier: TCarrier, sessionName: string, options: SessionCookieOptions) => void;
}

/** One session of one request: its config, its framework, and its codec. */
export interface SessionBinding<TCarrier, Config extends SessionCoreConfig> {
  carrier: TCarrier;
  config: Config;
  port: SessionPort<TCarrier>;
  codec: SessionCodec<Config>;
  /** Session name — drives the cookie name and the default session header. */
  name: string;
  /** The hook argument naming the request. */
  args: Record<string, unknown>;
  store: SessionStore;
}

export function bindSession<TCarrier, Config extends SessionCoreConfig>(
  carrier: TCarrier,
  config: Config,
  options: { port: SessionPort<TCarrier>; codec: SessionCodec<Config> },
): SessionBinding<TCarrier, Config> {
  const { port, codec } = options;
  const name = config.name || codec.defaultName;
  assertSessionName(name, { prefix: port.prefix });
  claimSessionName(port.scope(carrier), name, codec.family, port.prefix);
  return {
    carrier,
    config,
    port,
    codec,
    name,
    args: port.carrier(carrier),
    store: port.store(carrier, `${codec.family}:${name}`),
  };
}

/** The raw session token for the request. */
export function sessionToken<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
): string | undefined {
  assertTokenSource(binding.config, { prefix: binding.port.prefix });
  return binding.port.readToken(binding.carrier, binding.name, binding.config);
}

/** A fresh session ID — the JWT `jti` — from the config's generator, else a random UUID. */
export function mintSessionId(config: SessionCoreConfig): string {
  return config.generateId?.() || crypto.randomUUID();
}

/** A session with no token yet: the state a request that carried none starts from. */
export function emptySession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TCarrier,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TCarrier, Config>): SessionState<T, MaxAge> {
  const { config, codec } = binding;
  const now = codec.now(config);
  const createdAt = now - (now % 1000);
  return {
    id: undefined,
    createdAt,
    expiresAt: resolveExpiresAt(createdAt, { maxAge: config.maxAge }) as SessionState<
      T,
      MaxAge
    >["expiresAt"],
    data: Object.create(null),
    token: undefined,
  };
}

/** Drop the cookie of a session that expired, unless the config writes none. */
export function dropSessionCookie<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
): void {
  const { config, codec, port } = binding;
  if (config.cookie === false) return;
  port.dropCookie(binding.carrier, binding.name, {
    defaults: codec.defaultCookie,
    cookie: config.cookie,
  });
}

/** The families holding each session name, per request. */
const SESSION_NAMES = /* @__PURE__ */ new WeakMap<object, Map<string, "jws" | "jwe">>();

/**
 * A session `name` spells one cookie, and one cookie carries one token: a JWS
 * and a JWE session bound under the same name on one request keep separate
 * state but write over each other's cookie, so the next request reads one of
 * them back as the other's token. The first family to bind a name on a request
 * holds it; a second family under that name is a configuration the application
 * cannot serve.
 */
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
