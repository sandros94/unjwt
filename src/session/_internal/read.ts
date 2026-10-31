/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import { isJWTError } from "../../error.ts";
import type { ExpiresIn } from "../../core/types/index.ts";
import { computeDurationInSeconds } from "../../utils/jwt.ts";
import { expiredSessionError } from "./contract.ts";
import { dropSessionCookie } from "./bind.ts";
import type { SessionBinding, SessionCoreConfig, StoredSession } from "./types.ts";
import type { SessionRecord, SessionState } from "../types.ts";
import { emptySession, kSessionPending, storedSession } from "./core.ts";
import { assertTokenSource } from "./transport.ts";

/** Returns the session of the current request, reading its token on the first call. */
export async function loadSession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TEvent,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TEvent, Config>): Promise<SessionState<T, MaxAge>> {
  const { config, codec, keys, store, args, transport } = binding;

  // Key errors are misconfiguration: thrown, never reported through `onError`.
  await keys.assertKeys();
  const open = keys.opener(args);
  assertTokenSource(transport, { prefix: binding.driver.prefix });

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
      const freshSession = emptySession<T, MaxAge, TEvent, Config>(binding);
      store.set(freshSession);
      await fireExpire(binding, {
        session: {
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          token: session.token,
        },
        error: expiredSessionError({
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
        }),
      });
      return freshSession;
    }

    return session;
  }

  const session = emptySession<T, MaxAge, TEvent, Config>(binding);
  store.set(session);

  if (transport.malformed) {
    await fireError(binding, transport.malformed);
    return session;
  }
  const token = transport.read();
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
      // A token that fails its checks is dropped like an expired one. A read that failed keeps it.
      if (isJWTError(failure.error, "ERR_SESSION_TOKEN_INVALID")) dropSessionCookie(binding);
      await fireError(binding, failure.error);
    }
    return session;
  }

  try {
    await fireRead(binding, session);
  } catch (error_) {
    store.set(emptySession<T, MaxAge, TEvent, Config>(binding));
    throw error_;
  }
  await rollSession(binding, session);
  return session;
}

async function fireRead<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
  session: StoredSession,
): Promise<void> {
  if (session.id === undefined || session.token === undefined) return;
  await binding.config.hooks?.onRead?.({
    session: binding.actions.manager(binding),
    ...binding.args,
    config: binding.config,
  });
}

/** Reissues a cookie session it read when `rolling` asks, unless a hook replaced it. A cookie session without a response, or with one already sent, leaves it to the next request. A header or token session never rolls. */
async function rollSession<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
  session: StoredSession,
): Promise<void> {
  const { config, codec, transport, store } = binding;
  const { rolling } = config;
  if (rolling === undefined || transport.source !== "cookie" || store.get() !== session) return;
  if (session.token === undefined || session.expiresAt === undefined) return;
  if (rolling !== true) {
    const age = codec.now(config) - session.createdAt;
    if (age < computeDurationInSeconds(rolling) * 1000) return;
  }
  if (transport.readonly || !transport.writable()) return;
  await binding.actions.roll(binding);
}

async function fireError<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
  error: unknown,
): Promise<void> {
  await binding.config.hooks?.onError?.({
    session: binding.actions.manager(binding),
    ...binding.args,
    error,
    config: binding.config,
  });
}

async function fireExpire<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
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
    session: { ...expired.session, source: binding.transport.source },
    ...binding.args,
    error: expired.error,
    config: binding.config,
  });
}
