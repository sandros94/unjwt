import type { ExpiresIn } from "../../core/types/index.ts";
import type { CookieAttributes } from "./cookie-attributes.ts";
import type { SessionDriver } from "./driver.ts";
import { storedSession } from "./core.ts";
import {
  assertCookiePrefix,
  assertRolling,
  assertSessionName,
  invalidConfigError,
} from "./contract.ts";
import type {
  HeldToken,
  SessionActions,
  SessionBinding,
  SessionCodec,
  SessionCoreConfig,
  SessionKeys,
  SessionStore,
} from "./types.ts";
import {
  type SessionTransportOptions,
  assertSessionHeader,
  assertSessionTokenSource,
  resolveSessionTransport,
} from "./transport.ts";

/** The session names bound on one request, in a slot of its state record. */
const kSessionNames: unique symbol = Symbol("unjwt_session_names");

/** The tokens the transports of one request hold, one per session slot. */
const kHeldTokens: unique symbol = Symbol("unjwt_session_held_tokens");

/** The members of a session config that {@link assertSessionConfig} checks. */
export interface SessionConfigChecks {
  /** Request header to read the token from: a name, or `true` for `x-<name>-session`. */
  sessionHeader?: boolean | string;
  /** Cookie attributes over the defaults, or `false` for no cookie. */
  cookie?: false | (CookieAttributes & { chunkMaxLength?: number });
  /** Session lifetime. */
  maxAge?: ExpiresIn;
  /** Reissues a session read from its cookie: on every read with `true`, else once the token is that old. Requires `maxAge`, and is shorter than it. */
  rolling?: true | ExpiresIn;
}

/**
 * Checks what the config alone decides: its name, session header, cookie prefix over `defaultCookie`, and `rolling`.
 * @throws `ERR_SESSION_CONFIG_INVALID` if `name` is not a cookie name or ends in a dot and digits, `sessionHeader` is not a header name,
 * a `__Host-` or `__Secure-` cookie's attributes break its prefix rules, or `rolling` has no `maxAge` or is not shorter than it. The message starts with `prefix`.
 * @throws `ERR_INVALID_OPTION` if `rolling` is neither `true` nor a duration.
 */
export function assertSessionConfig(
  config: SessionConfigChecks,
  options: { name: string; prefix: string; defaultCookie: CookieAttributes },
): void {
  const { name, prefix } = options;
  assertSessionName(name, { prefix });
  assertSessionHeader(config.sessionHeader, { prefix });
  if (config.cookie !== false) {
    assertCookiePrefix(name, { ...options.defaultCookie, ...config.cookie }, { prefix });
  }
  assertRolling(config, { prefix });
}

/** Registers the session's name on the request and resolves its token transport. The config is checked when the session is defined. */
export function bindSession<TEvent, Config extends SessionCoreConfig>(
  event: TEvent,
  options: {
    config: Config;
    name: string;
    driver: SessionDriver<TEvent>;
    codec: SessionCodec<Config>;
    keys: SessionKeys;
    actions: SessionActions<TEvent, Config>;
  },
): SessionBinding<TEvent, Config> {
  const { config, name, driver, codec, keys, actions } = options;
  const record = driver.state(event);
  claimSessionName(record, { name, family: codec.family, prefix: driver.prefix });
  const slot = `${codec.family}:${name}`;
  return {
    event,
    config,
    driver,
    codec,
    keys,
    actions,
    name,
    args: { event },
    store: recordSlotStore(record, slot),
    held: heldTokenSlot(record, slot),
    transport: resolveSessionTransport(driver, event, transportOptions(config, { name, codec })),
  };
}

/** The token behind the session's current state: `undefined` after a failed read or `clear()`. Before any read, the one its transport reads. */
export function sessionToken<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
): string | undefined {
  const { transport } = binding;
  assertSessionTokenSource(transport, { prefix: binding.driver.prefix });
  const session = storedSession(binding.store);
  return session ? session.token : transport.read();
}

/** The token the transport holds, unopened: the one it read whatever the read's outcome, the one `update()` issued, none after `clear()`. Before any read, the one it reads. */
export function transportToken<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
): string | undefined {
  const { transport } = binding;
  assertSessionTokenSource(transport, { prefix: binding.driver.prefix });
  const held = binding.held.get();
  return held ? held.token : transport.read();
}

/** Session store over a per-request record, one slot per session. */
export function recordSlotStore(record: Record<string, unknown>, slot: string): SessionStore {
  return {
    get: () => record[slot],
    set: (state) => {
      record[slot] = state;
    },
  };
}

/** Expires the session cookie. A response already sent leaves it to the next request, which sends the same token. */
export function dropSessionCookie<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
): void {
  const { transport } = binding;
  if (!transport.drop || !transport.writable()) return;
  transport.drop();
}

/** One name is one cookie: the first family to bind a name on a request keeps it. */
function claimSessionName(
  record: Record<string, unknown>,
  options: { name: string; family: "jws" | "jwe"; prefix: string },
): void {
  const { name, family, prefix } = options;
  const holder: { [kSessionNames]?: Map<string, "jws" | "jwe"> } = record;
  const registry = (holder[kSessionNames] ||= new Map());
  const held = registry.get(name);
  if (held === undefined) {
    registry.set(name, family);
    return;
  }
  if (held === family) return;
  throw invalidConfigError(
    `${prefix} Session name "${name}" is already used by a ${held.toUpperCase()} session on this request.`,
  );
}

/** The config's token sources, and its cookie attributes over the codec's defaults. */
function transportOptions<Config extends SessionCoreConfig>(
  config: Config,
  options: { name: string; codec: SessionCodec<Config> },
): SessionTransportOptions {
  const { name, codec } = options;
  const { sessionHeader } = config;
  if (config.cookie === false) return { name, sessionHeader, cookie: false };
  const { chunkMaxLength, ...configured } = config.cookie || {};
  return {
    name,
    sessionHeader,
    cookie: { attrs: { ...codec.defaultCookie, ...configured }, chunkMaxLength },
  };
}

function heldTokenSlot(record: Record<string, unknown>, slot: string): HeldToken {
  const holder: { [kHeldTokens]?: Map<string, string | undefined> } = record;
  const held = (holder[kHeldTokens] ||= new Map());
  return {
    get: () => (held.has(slot) ? { token: held.get(slot) } : undefined),
    set: (token) => {
      held.set(slot, token);
    },
  };
}
