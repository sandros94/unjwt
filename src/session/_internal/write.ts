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
import { sessionCookie, sessionToken } from "./bind.ts";
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
import { assertTokenSource, assertWritable } from "./transport.ts";

/** Issue the session as a compact token without writing it; fresh `jti` if no ID, empty session without a token source. */
export async function encodeSession<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
): Promise<string> {
  const { config, codec, store, transport } = binding;
  await codec.assertKeys(config);
  const issue = codec.issuer(config);
  const session =
    storedSession(store) || (transport.read ? await loadSession(binding) : emptySession(binding));
  return issue(session.id === undefined ? { ...session, id: mintSessionId(config) } : session);
}

/** Update the session data (if provided) and reissue the token; `options.maxAge` overrides this token's lifetime. */
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
  const { config, driver, store, args, transport } = binding;

  assertWritable(transport, { operation: "update", prefix: driver.prefix });

  const session =
    storedSession<T, MaxAge>(store) || (await loadSession<T, MaxAge, TEvent, Config>(binding));

  const oldSession = snapshotSession(session);

  const resolved = typeof update === "function" ? update(session.data) : update;
  if (resolved) {
    Object.assign(session.data, sanitizeSessionUpdate(resolved, { prefix: driver.prefix }));
  }
  for (const claim of RESERVED_CLAIMS) delete session.data[claim];

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
    transport.write?.(token, sessionCookie(binding, { expiresAt: session.expiresAt }));
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

/** Drop the session cookie, where the event takes one, and leave an empty session for the rest of the request. */
export async function dropSession<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
): Promise<void> {
  const { config, driver, store, args, transport } = binding;

  assertTokenSource(transport, { prefix: driver.prefix });
  assertWritable(transport, { operation: "clear", prefix: driver.prefix });

  let session = storedSession(store);
  if (session && session[kSessionPending]) {
    session = await session[kSessionPending];
  }
  const oldSession =
    session && (session.id !== undefined || session.token !== undefined)
      ? snapshotSession(session)
      : undefined;

  store.set(emptySession(binding));

  transport.drop?.(sessionCookie(binding));

  await config.hooks?.onClear?.({ oldSession, ...args, config });
}

/** The session manager handed to callers: live getters over the stored state. */
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

/** What a binding needs from this module; passed to `bindSession` by every adapter. */
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

/** A session with a deep copy of its data as a token carries it, unaffected by later changes to the live one. */
function snapshotSession<S extends { data: Record<string, unknown> }>(session: S): S {
  return { ...session, data: safeJsonParse(JSON.stringify(session.data)) };
}
