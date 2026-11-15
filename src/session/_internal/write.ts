/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import { safeJsonParse } from "unsecure/sanitize";
import type { ExpiresIn } from "../../core/types/index.ts";
import type {
  SessionIssueOptions,
  SessionManager,
  SessionRecord,
  SessionState,
  SessionUpdate,
  SessionUpdateTrigger,
} from "../types.ts";
import { RESERVED_CLAIMS, resolveExpiresAt, sanitizeSessionUpdate } from "./contract.ts";
import { sessionToken } from "./bind.ts";
import type { SessionActions, SessionBinding, SessionCoreConfig } from "./types.ts";
import {
  blankSession,
  emptySession,
  kSessionPending,
  mintSessionId,
  sessionInstant,
  storedSession,
} from "./core.ts";
import { loadSession } from "./read.ts";
import { assertSessionTokenSource, assertSessionWritable } from "./transport.ts";

/** Merges `update` into the data, issues a token, runs `onUpdate`, then writes the token. `options.maxAge` overrides its lifetime. A failed update leaves the session as it was. */
export async function issueSession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TEvent,
  Config extends SessionCoreConfig,
>(
  binding: SessionBinding<TEvent, Config>,
  update?: SessionUpdate<T>,
  options?: SessionIssueOptions,
  trigger: SessionUpdateTrigger = "update",
): Promise<SessionState<T, MaxAge> & { id: string; token: string }> {
  const { config, keys, driver, store, args, transport } = binding;

  assertSessionWritable(transport, { operation: "update", prefix: driver.prefix });

  const session =
    storedSession<T, MaxAge>(store) || (await loadSession<T, MaxAge, TEvent, Config>(binding));

  const oldSession = snapshotSession(session);

  const { changes, createdAt, id, expiresAt } = restoringOnThrow(session, oldSession, () => {
    const resolved = typeof update === "function" ? update(session.data) : update;
    const instant = sessionInstant(binding);
    return {
      changes: resolved && sanitizeSessionUpdate(resolved, { prefix: driver.prefix }),
      createdAt: instant,
      id: mintSessionId(config),
      expiresAt: resolveExpiresAt(instant, { maxAge: options?.maxAge ?? config.maxAge }),
    };
  });

  if (changes) Object.assign(session.data, changes);
  for (const claim of RESERVED_CLAIMS) delete session.data[claim];
  Object.assign(session, { id, createdAt, expiresAt });

  const reportFailure = async (error: unknown): Promise<never> => {
    restoreSession(session, oldSession);
    await config.hooks?.onError?.({
      session: binding.actions.manager(binding),
      ...args,
      error,
      config,
    });
    throw error;
  };

  const token = await keys
    .assertKeys()
    .then(() => keys.issue(session))
    .catch(reportFailure);
  const issued = Object.assign(session, { id, token, error: undefined });

  try {
    await config.hooks?.onUpdate?.({
      session: snapshotSession(issued),
      oldSession,
      trigger,
      ...args,
      config,
    });
  } catch (error_) {
    restoreSession(session, oldSession);
    throw error_;
  }

  try {
    assertSessionWritable(transport, { operation: "update", prefix: driver.prefix });
    transport.write?.(token, { expiresAt: issued.expiresAt });
    binding.held.set(token);
  } catch (error_) {
    return reportFailure(error_);
  }

  return issued;
}

/** Expires the session cookie where the event has one, and leaves an empty session for the rest of the request. */
export async function dropSession<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
): Promise<void> {
  const { config, driver, store, args, transport } = binding;

  assertSessionTokenSource(transport, { prefix: driver.prefix });
  assertSessionWritable(transport, { operation: "clear", prefix: driver.prefix });

  let session = storedSession(store);
  if (session && session[kSessionPending]) {
    session = await session[kSessionPending];
  }
  const oldSession =
    session &&
    (session.id !== undefined || session.token !== undefined || session.error !== undefined)
      ? snapshotSession(session)
      : undefined;

  store.set(emptySession(binding));
  binding.held.set(undefined);

  transport.drop?.();

  await config.hooks?.onClear?.({ oldSession, ...args, config });
}

/** The session manager returned to callers: live getters over the stored state. */
export function sessionManager<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TEvent,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TEvent, Config>): SessionManager<T, MaxAge> {
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
      return sessionToken(binding);
    },
    get source() {
      return binding.transport.source;
    },
    get error() {
      return state()?.error;
    },
    update: async (update?: SessionUpdate<T>, options?: SessionIssueOptions) => {
      await issueSession<T, MaxAge, TEvent, Config>(binding, update, options);
      return manager;
    },
    clear: async () => {
      await dropSession(binding);
      return manager;
    },
  };

  return manager;
}

/** The write side a binding calls from the read path, passed to `bindSession`. */
export function sessionActions<TEvent, Config extends SessionCoreConfig>(): SessionActions<
  TEvent,
  Config
> {
  return {
    manager: (binding) => sessionManager(binding),
    roll: async (binding) => {
      await issueSession(binding, undefined, undefined, "rolling");
    },
  };
}

/** A copy of the session with its data deep-copied through JSON, unaffected by later changes to the live one. */
function snapshotSession<S extends { data: Record<string, unknown> }>(session: S): S {
  return { ...session, data: safeJsonParse(JSON.stringify(session.data)) };
}

/** Runs `run`, and puts the session back as `oldSession` holds it when `run` throws. */
function restoringOnThrow<S extends RestorableSession, R>(
  session: S,
  oldSession: S,
  run: () => R,
): R {
  try {
    return run();
  } catch (error) {
    restoreSession(session, oldSession);
    throw error;
  }
}

/** Puts the id, times, data, token and error of `oldSession` back on the live session. */
function restoreSession<S extends RestorableSession>(session: S, oldSession: S): void {
  Object.assign(session, {
    id: oldSession.id,
    createdAt: oldSession.createdAt,
    expiresAt: oldSession.expiresAt,
    data: oldSession.data,
    token: oldSession.token,
    error: oldSession.error,
  });
}

type RestorableSession = Pick<
  SessionState<SessionRecord, ExpiresIn | undefined>,
  "id" | "createdAt" | "expiresAt" | "data" | "token" | "error"
>;
