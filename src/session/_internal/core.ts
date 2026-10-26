/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { ExpiresIn } from "../../core/types/index.ts";
import { resolveExpiresAt } from "./contract.ts";
import type {
  OpenedSession,
  PendingSession,
  SessionBinding,
  SessionCodec,
  SessionCoreConfig,
  SessionKeys,
  SessionStore,
} from "./types.ts";
import type { OpenedSessionState, SessionRecord, SessionState } from "../types.ts";

/** In-flight read of a session, awaited by a second reader on the same request. */
export const kSessionPending: unique symbol = Symbol("unjwt_session_pending");

/** The codec's current time, truncated to whole seconds as in `iat`. */
export function sessionInstant<Config extends SessionCoreConfig>(source: {
  codec: SessionCodec<Config>;
  config: Config;
}): number {
  const now = source.codec.now(source.config);
  return now - (now % 1000);
}

export function mintSessionId(config: SessionCoreConfig): string {
  return config.generateId?.() || crypto.randomUUID();
}

export function emptySession<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  TEvent,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TEvent, Config>): PendingSession<T, MaxAge> {
  const createdAt = sessionInstant(binding);
  return typedSession<T, MaxAge>({
    id: undefined,
    createdAt,
    expiresAt: resolveExpiresAt(createdAt, { maxAge: binding.config.maxAge }),
    data: Object.create(null),
    token: undefined,
    source: binding.transport.source,
  });
}

export function storedSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  store: SessionStore,
): PendingSession<T, MaxAge> | undefined {
  const state = store.get();
  return state === undefined ? undefined : typedSession<T, MaxAge>(state);
}

export function blankSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(): Pick<
  SessionState<T, MaxAge>,
  "expiresAt" | "data"
> {
  return typedSession<T, MaxAge>({ expiresAt: undefined, data: {} });
}

export function openSessionToken<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  keys: SessionKeys,
  options: { token: string; args: Record<string, unknown> },
): Promise<OpenedSessionState<T, MaxAge>> {
  return keys
    .open(options.token, options.args)
    .then((opened) => typedOpened<T, MaxAge>({ ...opened, source: "token" }));
}

function typedSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  state: unknown,
): PendingSession<T, MaxAge> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- storage and codecs hold session state untyped
  return state as PendingSession<T, MaxAge>;
}

function typedOpened<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  opened: OpenedSession & { source: "token" },
): OpenedSessionState<T, MaxAge> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- codecs return session data untyped
  return opened as OpenedSessionState<T, MaxAge>;
}
