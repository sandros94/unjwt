import type { SessionDriver } from "./driver.ts";
import { storedSession } from "./core.ts";
import {
  assertCookiePrefix,
  assertRolling,
  assertSessionName,
  invalidConfigError,
} from "./contract.ts";
import type {
  SessionActions,
  SessionBinding,
  SessionCodec,
  SessionCoreConfig,
  SessionStore,
} from "./types.ts";
import {
  type SessionCookie,
  assertSessionHeader,
  assertTokenSource,
  resolveTransport,
} from "./transport.ts";

/** The session names bound on one request, in a slot of its state record. */
const kSessionNames: unique symbol = Symbol("unjwt_session_names");

/** Validates the config, claims its name on the request and resolves where its token travels. */
export function bindSession<TEvent, Config extends SessionCoreConfig>(
  event: TEvent,
  config: Config,
  options: {
    driver: SessionDriver<TEvent>;
    codec: SessionCodec<Config>;
    actions: SessionActions<TEvent, Config>;
    /** The hook argument naming the request, as the public entry names it: `{ event }` or `{ context }`. */
    hookArgs: (event: TEvent) => Record<string, unknown>;
  },
): SessionBinding<TEvent, Config> {
  const { driver, codec, actions, hookArgs } = options;
  const { prefix } = driver;
  const name = config.name || codec.defaultName;
  assertSessionName(name, { prefix });
  assertSessionHeader(config.sessionHeader, { prefix });
  if (config.cookie !== false) {
    const attrs: Record<string, unknown> = { ...codec.defaultCookie, ...config.cookie };
    assertCookiePrefix(name, attrs, { prefix });
  }
  assertRolling(config, { prefix });
  const record = driver.state(event);
  claimSessionName(record, { name, family: codec.family, prefix });
  return {
    event,
    config,
    driver,
    codec,
    actions,
    name,
    args: hookArgs(event),
    store: recordSlotStore(record, `${codec.family}:${name}`),
    transport: resolveTransport(driver, event, { config, name }),
  };
}

/** The token of the session this request read or wrote, else the one its transport carries. */
export function sessionToken<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
): string | undefined {
  const { transport } = binding;
  assertTokenSource(transport, { prefix: binding.driver.prefix });
  const session = storedSession(binding.store);
  return session ? session.token : transport.read();
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

/** An expiring token sets `expires` and drops `maxAge`, which would take precedence (RFC 6265 §5.3). */
export function sessionCookie<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
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

/** Drops an expired session's cookie; a sealed response leaves it to the next request, which carries the same token. */
export function dropSessionCookie<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
): void {
  const { transport } = binding;
  if (!transport.drop || !transport.writable()) return;
  transport.drop(sessionCookie(binding));
}

/** One name is one cookie: the first family to bind a name on a request holds it. */
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
