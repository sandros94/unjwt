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
} from "./_session-core";

/** Get (and lazily initialize) the session for the current request. */
export async function loadSession<
  T extends Record<string, any>,
  MaxAge extends ExpiresIn | undefined,
  TCarrier,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TCarrier, Config>): Promise<SessionState<T, MaxAge>> {
  const { config, codec, store, args } = binding;

  const existing = store.get() as SessionState<T, MaxAge> | undefined;
  if (existing) {
    const session = existing[kSessionPending] ? await existing[kSessionPending] : existing;

    /**
     * A session is checked for expiry before it is handed back. An expired one
     * is dropped and replaced by an empty session, so a later read in the same
     * request sees no session rather than a stale one.
     */
    if (session.expiresAt !== undefined && session.expiresAt < Date.now()) {
      await config.hooks?.onExpire?.({
        session: {
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          token: session.token!,
        },
        ...args,
        error: expiredSessionError({ id: session.id, expiresAt: session.expiresAt }),
        config,
      });
      dropSessionCookie(binding);
      const freshSession = emptySession<T, MaxAge, TCarrier, Config>(binding);
      store.set(freshSession);
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

  let exclusiveHookFired = false;
  if (token) {
    session.token = token;
    const promise = codec
      .open(config, token, args)
      .catch(async (error_) => {
        exclusiveHookFired = true;
        if (isJWTError(error_, "ERR_JWT_EXPIRED")) {
          session.token = undefined;
          dropSessionCookie(binding);
          await config.hooks?.onExpire?.({
            session: {
              id: error_.cause.jti,
              createdAt: error_.cause.iat ? error_.cause.iat * 1000 : undefined,
              expiresAt: error_.cause.exp ? error_.cause.exp * 1000 : undefined,
              token,
            },
            ...args,
            error: error_,
            config,
          });
        } else {
          await config.hooks?.onError?.({ session, ...args, error: error_, config });
        }
        return undefined;
      })
      .then((opened) => {
        if (opened) {
          Object.assign(session, opened);
        }
        delete session[kSessionPending];
        return session;
      });
    session[kSessionPending] = promise;
    await promise;
  }

  if (!exclusiveHookFired && session.id !== undefined && session.token !== undefined) {
    await config.hooks?.onRead?.({ session, ...args, config });
  }
  return session;
}
