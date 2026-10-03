/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import { sanitizeObjectCopy } from "unsecure/sanitize";
import type { ExpiresIn } from "../core/types";
import {
  type SessionIssueOptions,
  assertTokenSource,
  hasTokenSource,
  readOnlyEventError,
  resolveExpiresAt,
  sanitizeSessionUpdate,
} from "./_session";
import {
  type SessionBinding,
  type SessionCoreConfig,
  type SessionState,
  blankSession,
  emptySession,
  kSessionPending,
  mintSessionId,
  sessionToken,
  storedSession,
} from "./_session-core";
import { loadSession } from "./_session-read";
import type { SessionManager, SessionRecord, SessionUpdate } from "./_session-types";

/**
 * Issue the current session as a compact token, handed back to the caller
 * rather than written anywhere. A session that has no ID yet is issued under a
 * fresh `jti`, and a config with no token source issues from an empty session.
 * Payload: `session.data` spread at the top level, plus the reserved claims
 * `jti`, `iat`, and `exp` (when the session has a lifetime).
 */
export async function encodeSession<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
): Promise<string> {
  const { config, codec, store } = binding;
  await codec.assertKeys(config);
  const issue = codec.issuer(config);
  const session =
    storedSession(store) ||
    (hasTokenSource(config) ? await loadSession(binding) : emptySession(binding));
  return issue(session.id === undefined ? { ...session, id: mintSessionId(config) } : session);
}

/**
 * Update the session data (if provided) and reissue the token.
 * Pass `options.maxAge` to give this one token a lifetime of its own.
 */
export async function issueSession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TCarrier,
  Config extends SessionCoreConfig,
>(
  binding: SessionBinding<TCarrier, Config>,
  update?: SessionUpdate<T>,
  options?: SessionIssueOptions,
): Promise<SessionState<T, MaxAge> & { id: string; token: string }> {
  const { config, codec, port, store, args } = binding;

  if (config.cookie !== false && !port.writable(binding.carrier)) {
    throw readOnlyEventError(`${port.prefix} Cannot update session on read-only event.`);
  }

  const session =
    storedSession<T, MaxAge>(store) || (await loadSession<T, MaxAge, TCarrier, Config>(binding));

  // Snapshot before the updater runs, with a deep copy of `data`, so
  // `oldSession` is a true "before" state for hook diffing and rollback.
  const oldSession = { ...session, data: sanitizeObjectCopy(session.data) };

  const resolved = typeof update === "function" ? update(session.data) : update;
  if (resolved) {
    Object.assign(session.data, sanitizeSessionUpdate(resolved, { prefix: port.prefix }));
  }

  const maxAge = options?.maxAge ?? config.maxAge;
  const now = codec.now(config);
  const createdAt = now - (now % 1000); // round to seconds
  const id = mintSessionId(config);
  Object.assign(session, {
    id,
    createdAt,
    expiresAt: resolveExpiresAt(createdAt, { maxAge }),
  });

  // Always issue a token and cache it so `session.token` stays accurate even
  // when cookies are disabled.
  let issued: SessionState<T, MaxAge> & { id: string; token: string };
  try {
    const token = await encodeSession(binding);
    if (config.cookie !== false) {
      port.setCookie(binding.carrier, binding.name, token, {
        defaults: codec.defaultCookie,
        cookie: config.cookie,
        expiresAt: session.expiresAt,
      });
    }
    issued = Object.assign(session, { id, token });
  } catch (error_) {
    Object.assign(session, {
      id: oldSession.id,
      createdAt: oldSession.createdAt,
      expiresAt: oldSession.expiresAt,
      data: oldSession.data,
    });
    session.token = oldSession.token;
    await config.hooks?.onError?.({ session, ...args, error: error_, config });
    throw error_;
  }

  // Fires after issuing so the hook receives the definitive new token, jti, and
  // timestamps. Also fires on pure token refresh (update is undefined).
  await config.hooks?.onUpdate?.({ session, oldSession, ...args, config });

  return issued;
}

/**
 * Clear the session: drop the cookie and leave an empty session behind, so a
 * later read in the same request sees no session rather than the request cookie.
 */
export async function dropSession<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
): Promise<void> {
  const { config, codec, port, store, args } = binding;

  assertTokenSource(config, { prefix: port.prefix });
  if (config.cookie !== false && !port.writable(binding.carrier)) {
    throw readOnlyEventError(`${port.prefix} Cannot clear session on read-only event.`);
  }

  let session = storedSession(store);
  if (session && session[kSessionPending]) {
    session = await session[kSessionPending];
  }
  const oldSession =
    session && (session.id !== undefined || session.token !== undefined)
      ? { ...session, data: sanitizeObjectCopy(session.data) }
      : undefined;

  store.set(emptySession(binding));

  if (config.cookie !== false) {
    port.deleteCookie(binding.carrier, binding.name, {
      defaults: codec.defaultCookie,
      cookie: config.cookie,
    });
  }

  await config.hooks?.onClear?.({ oldSession, ...args, config });
}

/** The session manager handed to callers: live getters over the stored state. */
export function sessionManager<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TCarrier,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TCarrier, Config>): SessionManager<T, MaxAge> {
  const { store } = binding;
  const state = () => storedSession<T, MaxAge>(store);

  const manager: SessionManager<T, MaxAge> = {
    get id() {
      return state()?.id;
    },
    get createdAt() {
      return state()?.createdAt ?? Date.now();
    },
    get expiresAt() {
      return (state() ?? blankSession<T, MaxAge>()).expiresAt;
    },
    get data() {
      return (state() ?? blankSession<T, MaxAge>()).data;
    },
    get token() {
      const session = state();
      return session ? session.token : sessionToken(binding);
    },
    update: async (update?: SessionUpdate<T>, options?: SessionIssueOptions) => {
      await issueSession<T, MaxAge, TCarrier, Config>(binding, update, options);
      return manager;
    },
    clear: async () => {
      await dropSession(binding);
      return manager;
    },
  };

  return manager;
}
