/**
 * This is a fork of h3 library's session utility functions.
 * @source https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/src/utils/session.ts
 * @license MIT https://github.com/h3js/h3/blob/b4dce71c256911335f3402d09f30ffad120ad61a/LICENSE
 */

import type { ExpiresIn } from "../core/types/index.ts";
import { resolveExpiresAt } from "./_contract.ts";
import type {
  OpenedSession,
  PendingSession,
  SessionBinding,
  SessionCodec,
  SessionCoreConfig,
  SessionStore,
} from "./_types.ts";
import type { OpenedSessionState, SessionRecord, SessionState } from "./types.ts";

/** In-flight read of a session, awaited by a second reader on the same request. */
export const kSessionPending: unique symbol = Symbol("unjwt_session_pending");

/** The codec's now, truncated to whole seconds as `iat` carries it. */
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
  TContext,
  Config extends SessionCoreConfig,
>(binding: SessionBinding<TContext, Config>): PendingSession<T, MaxAge> {
  const createdAt = sessionInstant(binding);
  return typedSession<T, MaxAge>({
    id: undefined,
    createdAt,
    expiresAt: resolveExpiresAt(createdAt, { maxAge: binding.config.maxAge }),
    data: Object.create(null),
    token: undefined,
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

export function openSessionToken<
  T extends SessionRecord,
  MaxAge extends ExpiresIn | undefined,
  Config extends SessionCoreConfig,
>(
  codec: SessionCodec<Config>,
  config: Config,
  options: { token: string; args: Record<string, unknown> },
): Promise<OpenedSessionState<T, MaxAge>> {
  return codec.open(config, options.token, options.args).then(typedOpened<T, MaxAge>);
}

function typedSession<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  state: unknown,
): PendingSession<T, MaxAge> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- storage and codecs carry session state untyped
  return state as PendingSession<T, MaxAge>;
}

function typedOpened<T extends SessionRecord, MaxAge extends ExpiresIn | undefined>(
  opened: OpenedSession,
): OpenedSessionState<T, MaxAge> {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- codecs carry session data untyped
  return opened as OpenedSessionState<T, MaxAge>;
}
