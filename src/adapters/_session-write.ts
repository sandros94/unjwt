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
  type SessionActions,
  type SessionBinding,
  type SessionCoreConfig,
  type SessionState,
  blankSession,
  emptySession,
  kSessionPending,
  mintSessionId,
  sessionCookie,
  sessionInstant,
  sessionToken,
  storedSession,
} from "./_session-core";
import { loadSession } from "./_session-read";
import type {
  SessionManager,
  SessionRecord,
  SessionUpdate,
  SessionUpdateTrigger,
} from "./_session-types";

/** Issue the session as a compact token without writing it; fresh `jti` if no ID, empty session without a token source. */
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

/** Update the session data (if provided) and reissue the token; `options.maxAge` overrides this token's lifetime. */
export async function issueSession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TCarrier,
  Config extends SessionCoreConfig,
>(
  binding: SessionBinding<TCarrier, Config>,
  update?: SessionUpdate<T>,
  options?: SessionIssueOptions,
  trigger: SessionUpdateTrigger = "update",
): Promise<SessionState<T, MaxAge> & { id: string; token: string }> {
  const { config, port, store, args } = binding;

  assertWritable(binding, "update");

  const session =
    storedSession<T, MaxAge>(store) || (await loadSession<T, MaxAge, TCarrier, Config>(binding));

  const oldSession = snapshotSession(session);

  const resolved = typeof update === "function" ? update(session.data) : update;
  if (resolved) {
    Object.assign(session.data, sanitizeSessionUpdate(resolved, { prefix: port.prefix }));
  }

  const maxAge = options?.maxAge ?? config.maxAge;
  const createdAt = sessionInstant(binding);
  const id = mintSessionId(config);
  Object.assign(session, {
    id,
    createdAt,
    expiresAt: resolveExpiresAt(createdAt, { maxAge }),
  });

  let issued: SessionState<T, MaxAge> & { id: string; token: string };
  try {
    const token = await encodeSession(binding);
    if (config.cookie !== false) {
      port.setCookie(
        binding.carrier,
        binding.name,
        token,
        sessionCookie(binding, { expiresAt: session.expiresAt }),
      );
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
    await config.hooks?.onError?.({
      session: binding.actions.manager(binding),
      ...args,
      error: error_,
      config,
    });
    throw error_;
  }

  await config.hooks?.onUpdate?.({
    session: binding.actions.manager(binding),
    oldSession,
    trigger,
    ...args,
    config,
  });

  return issued;
}

/** Drop the session cookie and leave an empty session for the rest of the request. */
export async function dropSession<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
): Promise<void> {
  const { config, port, store, args } = binding;

  assertTokenSource(config, { prefix: port.prefix });
  assertWritable(binding, "clear");

  let session = storedSession(store);
  if (session && session[kSessionPending]) {
    session = await session[kSessionPending];
  }
  const oldSession =
    session && (session.id !== undefined || session.token !== undefined)
      ? snapshotSession(session)
      : undefined;

  store.set(emptySession(binding));

  if (config.cookie !== false) {
    port.deleteCookie(binding.carrier, binding.name, sessionCookie(binding));
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

/** What a binding needs from this module; passed to `bindSession` by every port. */
export function sessionActions<TCarrier, Config extends SessionCoreConfig>(): SessionActions<
  TCarrier,
  Config
> {
  return {
    manager: (binding) => sessionManager(binding),
    roll: async (binding) => {
      await issueSession(binding, undefined, undefined, "rolling");
    },
  };
}

/** A session that writes a cookie cannot be updated or cleared once the response takes none. */
function assertWritable<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
  operation: "update" | "clear",
): void {
  const { config, port, carrier } = binding;
  if (config.cookie !== false && !port.writable(carrier)) {
    throw readOnlyEventError(`${port.prefix} Cannot ${operation} session on read-only event.`);
  }
}

/** A session with a deep copy of its data, unaffected by later changes to the live one. */
function snapshotSession<S extends { data: Record<string, unknown> }>(session: S): S {
  return { ...session, data: sanitizeObjectCopy(session.data) };
}
