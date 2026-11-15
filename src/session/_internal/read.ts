/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import { type JWTError, isJWTError } from "../../error.ts";
import type { ExpiresIn } from "../../core/types/index.ts";
import { computeDurationInSeconds } from "../../utils/jwt.ts";
import { expiredSessionError, malformedHeaderError } from "./contract.ts";
import type { SessionBinding, SessionCoreConfig, StoredSession } from "./types.ts";
import type { SessionRecord, SessionRoll, SessionState } from "../types.ts";
import { emptySession, kSessionPending, snapshotSession, storedSession } from "./core.ts";
import { assertSessionTokenSource } from "./transport.ts";

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
  assertSessionTokenSource(transport, { prefix: binding.driver.prefix });

  const existing = storedSession<T, MaxAge>(store);
  if (existing) {
    const session = existing[kSessionPending] ? await existing[kSessionPending] : existing;

    // An expired session is replaced by an empty one, so later reads (the hook's too) see none.
    if (
      session.token !== undefined &&
      session.expiresAt !== undefined &&
      session.expiresAt <= codec.now(config)
    ) {
      transport.drop?.();
      const error = expiredSessionError({
        id: session.id,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
      });
      const freshSession = emptySession<T, MaxAge, TEvent, Config>(binding);
      freshSession.error = error;
      store.set(freshSession);
      await fireExpire(binding, {
        session: {
          id: session.id,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          token: session.token,
        },
        error,
      });
      return freshSession;
    }

    return session;
  }

  const session = emptySession<T, MaxAge, TEvent, Config>(binding);
  store.set(session);

  if (transport.malformed) {
    const error = malformedHeaderError(transport.malformed.header, {
      prefix: binding.driver.prefix,
    });
    session.error = error;
    await fireError(binding, { session, error });
    return session;
  }
  const token = transport.read();
  if (!token) return session;

  binding.held.set(token);
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
    if (isJWTError(failure.error)) session.error = failure.error;
    if (isJWTError(failure.error, "ERR_JWT_EXPIRED")) {
      const { jti, iat, exp } = failure.error.cause;
      transport.drop?.();
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
      if (isJWTError(failure.error, "ERR_SESSION_TOKEN_INVALID")) transport.drop?.();
      await fireError(binding, { session, error: failure.error });
    }
    return session;
  }

  const due = isRollDue(binding, session);
  let skipped = false;
  const roll: SessionRoll = {
    due,
    skip: () => {
      skipped = true;
    },
  };
  try {
    await fireRead(binding, { session, roll });
    if (due && !skipped) await rollSession(binding, { session, token });
  } catch (error_) {
    store.set(emptySession<T, MaxAge, TEvent, Config>(binding));
    throw error_;
  }
  return session;
}

async function fireRead<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
  read: { session: StoredSession; roll: SessionRoll },
): Promise<void> {
  if (read.session.id === undefined || read.session.token === undefined) return;
  await binding.config.hooks?.onRead?.({
    session: binding.actions.manager(binding),
    ...binding.args,
    roll: read.roll,
    config: binding.config,
  });
}

/** Whether `rolling` reissues a cookie session it read: one old enough, on a response that can still change. A header or token session never rolls. */
function isRollDue<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
  session: StoredSession,
): boolean {
  const { config, codec, transport } = binding;
  const { rolling } = config;
  if (rolling === undefined || transport.source !== "cookie") return false;
  if (session.expiresAt === undefined) return false;
  const age = codec.now(config) - session.createdAt;
  if (rolling !== true && age < computeDurationInSeconds(rolling) * 1000) return false;
  return !transport.readonly && transport.writable();
}

/** Reissues a session whose roll is due and that `onRead` did not skip, unless the hook updates or clears it. A response sent during the hook leaves the roll to the next request. */
async function rollSession<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
  read: { session: StoredSession; token: string },
): Promise<void> {
  if (binding.store.get() !== read.session || read.session.token !== read.token) return;
  if (!binding.transport.writable()) return;
  await binding.actions.roll(binding);
}

async function fireError<TEvent, Config extends SessionCoreConfig>(
  binding: SessionBinding<TEvent, Config>,
  failure: { session: StoredSession; error: unknown },
): Promise<void> {
  await binding.config.hooks?.onError?.({
    session: snapshotSession(failure.session),
    oldSession: undefined,
    trigger: "read",
    ...binding.args,
    error: failure.error,
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
    error: JWTError;
  },
): Promise<void> {
  await binding.config.hooks?.onExpire?.({
    session: { ...expired.session, source: binding.transport.source },
    ...binding.args,
    error: expired.error,
    config: binding.config,
  });
}
