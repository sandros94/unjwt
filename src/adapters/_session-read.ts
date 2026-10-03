/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import { isJWTError } from "../core/error";
import type { ExpiresIn } from "../core/types";
import { expiredSessionError } from "./_session";
import {
  type SessionBinding,
  type SessionCoreConfig,
  type SessionState,
  dropSessionCookie,
  emptySession,
  kSessionPending,
  sessionToken,
  storedSession,
} from "./_session-core";
import type { SessionRecord } from "./_session-types";

/** Get (and lazily initialize) the session for the current request. */
export async function loadSession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TCarrier,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TCarrier, Config>): Promise<SessionState<T, MaxAge>> {
  const { config, codec, store, args } = binding;

  // Key material is configuration, not token content: a session whose key
  // cannot issue or open a token is a misconfiguration the caller must see,
  // never an unreadable token reported through `onError` as "no session".
  await codec.assertKeys(config);
  const open = codec.opener(config, args);

  const existing = storedSession<T, MaxAge>(store);
  if (existing) {
    const session = existing[kSessionPending] ? await existing[kSessionPending] : existing;

    /**
     * A session holding a token is checked for expiry before it is handed back.
     * An expired one is dropped and replaced by an empty session, so a later
     * read in the same request — including one made by the hook below — sees
     * no session rather than a stale one. A session without a token has
     * nothing to expire: its `expiresAt` is the lifetime an update would give.
     */
    if (
      session.token !== undefined &&
      session.expiresAt !== undefined &&
      session.expiresAt < codec.now(config)
    ) {
      dropSessionCookie(binding);
      const freshSession = emptySession<T, MaxAge, TCarrier, Config>(binding);
      store.set(freshSession);
      await config.hooks?.onExpire?.({
        session: {
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          token: session.token,
        },
        ...args,
        error: expiredSessionError({ id: session.id, expiresAt: session.expiresAt }),
        config,
      });
      return freshSession;
    }

    if (session.id !== undefined && session.token !== undefined) {
      await config.hooks?.onRead?.({ session, ...args, config });
    }
    return session;
  }

  const session = emptySession<T, MaxAge, TCarrier, Config>(binding);
  store.set(session);

  const token = sessionToken(binding);
  if (!token) return session;

  session.token = token;

  /**
   * What a second reader on this request awaits is the token read alone: the
   * state is settled and `kSessionPending` cleared before any hook runs, so a
   * hook that reads the same session sees that state instead of awaiting a
   * promise that is itself waiting on the hook.
   */
  const pending = open(token)
    .then(
      (opened) => {
        Object.assign(session, opened);
        return { failure: undefined };
      },
      (error: unknown) => {
        // The token did not open, so it is not this session's token.
        session.token = undefined;
        return { failure: { error } };
      },
    )
    .then((outcome) => {
      delete session[kSessionPending];
      return outcome;
    });

  session[kSessionPending] = pending.then(() => session);
  const { failure } = await pending;

  if (failure) {
    if (isJWTError(failure.error, "ERR_JWT_EXPIRED")) {
      dropSessionCookie(binding);
      await config.hooks?.onExpire?.({
        session: {
          id: failure.error.cause.jti,
          createdAt: failure.error.cause.iat ? failure.error.cause.iat * 1000 : undefined,
          expiresAt: failure.error.cause.exp ? failure.error.cause.exp * 1000 : undefined,
          token,
        },
        ...args,
        error: failure.error,
        config,
      });
    } else {
      await config.hooks?.onError?.({ session, ...args, error: failure.error, config });
    }
    return session;
  }

  if (session.id !== undefined && session.token !== undefined) {
    await config.hooks?.onRead?.({ session, ...args, config });
  }
  return session;
}
