/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import { isJWTError } from "../core/error";
import type { ExpiresIn } from "../core/types";
import { computeDurationInSeconds } from "../core/utils/jwt";
import { expiredSessionError } from "./_session";
import {
  type SessionBinding,
  type SessionCoreConfig,
  type SessionState,
  type StoredSession,
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

  // Key errors are misconfiguration: thrown, never reported through `onError`.
  await codec.assertKeys(config);
  const open = codec.opener(config, args);

  const existing = storedSession<T, MaxAge>(store);
  if (existing) {
    const session = existing[kSessionPending] ? await existing[kSessionPending] : existing;

    // An expired session is replaced by an empty one, so later reads (the hook's too) see none.
    if (
      session.token !== undefined &&
      session.expiresAt !== undefined &&
      session.expiresAt < codec.now(config)
    ) {
      dropSessionCookie(binding);
      const freshSession = emptySession<T, MaxAge, TCarrier, Config>(binding);
      store.set(freshSession);
      await fireExpire(binding, {
        session: {
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          token: session.token,
        },
        error: expiredSessionError({ id: session.id, expiresAt: session.expiresAt }),
      });
      return freshSession;
    }

    return session;
  }

  const session = emptySession<T, MaxAge, TCarrier, Config>(binding);
  store.set(session);

  const token = sessionToken(binding);
  if (!token) return session;

  session.token = token;

  // State settles before any hook runs, so a hook reading this session does not await itself.
  const pending = open(token)
    .then(
      (opened) => {
        Object.assign(session, opened);
        return { failure: undefined };
      },
      (error: unknown) => {
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
      const { jti, iat, exp } = failure.error.cause;
      dropSessionCookie(binding);
      await fireExpire(binding, {
        session: {
          id: jti,
          createdAt: iat ? iat * 1000 : undefined,
          expiresAt: exp ? exp * 1000 : undefined,
          token,
        },
        error: failure.error,
      });
    } else {
      await config.hooks?.onError?.({
        session: binding.actions.manager(binding),
        ...args,
        error: failure.error,
        config,
      });
    }
    return session;
  }

  await fireRead(binding, session);
  await rollSession(binding, session);
  return session;
}

async function fireRead<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
  session: StoredSession,
): Promise<void> {
  if (session.id === undefined || session.token === undefined) return;
  await binding.config.hooks?.onRead?.({
    session: binding.actions.manager(binding),
    ...binding.args,
    config: binding.config,
  });
}

/** Reissues the session just read when `rolling` asks, unless a hook replaced it or the response is sealed. */
async function rollSession<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
  session: StoredSession,
): Promise<void> {
  const { config, codec, port, carrier, store } = binding;
  const { rolling } = config;
  if (rolling === undefined || store.get() !== session) return;
  if (session.token === undefined || session.expiresAt === undefined) return;
  if (rolling !== true) {
    const remaining = session.expiresAt - codec.now(config);
    if (remaining >= computeDurationInSeconds(rolling) * 1000) return;
  }
  if (config.cookie !== false && !port.writable(carrier)) {
    console.warn(
      `${port.prefix} Session not rolled: cookie cannot be written on a read-only event.`,
    );
    return;
  }
  await binding.actions.roll(binding);
}

async function fireExpire<TCarrier, Config extends SessionCoreConfig>(
  binding: SessionBinding<TCarrier, Config>,
  expired: {
    session: {
      id: string | undefined;
      createdAt: number | undefined;
      expiresAt: number | undefined;
      token: string;
    };
    error: Error;
  },
): Promise<void> {
  await binding.config.hooks?.onExpire?.({
    session: expired.session,
    ...binding.args,
    error: expired.error,
    config: binding.config,
  });
}
